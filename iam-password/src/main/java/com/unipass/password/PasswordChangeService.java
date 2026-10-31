package com.unipass.password;

import static com.unipass.password.PasswordFailure.Code.*;

import com.unipass.directory.*;
import com.unipass.identity.Database;
import java.sql.*;
import java.time.*;
import java.util.*;

/** No XA: durable access denial precedes the LDAP write; uncertain writes never reopen access. */
public final class PasswordChangeService {
  private static final Duration RECENT_AUTH = Duration.ofMinutes(5);
  private final Database database;
  private final DirectoryGateway directory;
  private final PasswordPolicy policy;
  private final Clock clock;
  private final boolean directoryHistoryVerified;
  private final boolean resetHistoryVerified;
  private final Hook hook;
  private final CredentialGuard credentials;

  /** Invoked inside the password transaction, after locking the actor's identity. */
  @FunctionalInterface
  public interface CredentialGuard {
    void require(Connection connection, AuthenticatedActor actor) throws SQLException;
  }

  enum Point {
    AFTER_PREPARE,
    AFTER_DIRECTORY_WRITE,
    BEFORE_COMMIT,
    AFTER_COMMIT
  }

  @FunctionalInterface
  interface Hook {
    void at(Point point);
  }

  private record User(
      UUID id,
      String directoryId,
      String type,
      String employee,
      String name,
      String status,
      String gate,
      long epoch) {}

  public PasswordChangeService(
      Database database,
      DirectoryGateway directory,
      PasswordPolicy policy,
      Clock clock,
      boolean directoryHistoryVerified) {
    this(database, directory, policy, clock, directoryHistoryVerified, false, point -> {});
  }

  PasswordChangeService(
      Database database,
      DirectoryGateway directory,
      PasswordPolicy policy,
      Clock clock,
      boolean directoryHistoryVerified,
      Hook hook) {
    this(database, directory, policy, clock, directoryHistoryVerified, false, hook);
  }

  public PasswordChangeService(
      Database database,
      DirectoryGateway directory,
      PasswordPolicy policy,
      Clock clock,
      boolean directoryHistoryVerified,
      boolean resetHistoryVerified) {
    this(
        database,
        directory,
        policy,
        clock,
        directoryHistoryVerified,
        resetHistoryVerified,
        point -> {});
  }

  private PasswordChangeService(
      Database database,
      DirectoryGateway directory,
      PasswordPolicy policy,
      Clock clock,
      boolean directoryHistoryVerified,
      boolean resetHistoryVerified,
      Hook hook) {
    this(
        database,
        directory,
        policy,
        clock,
        directoryHistoryVerified,
        resetHistoryVerified,
        hook,
        (connection, actor) -> {});
  }

  public PasswordChangeService(
      Database database,
      DirectoryGateway directory,
      PasswordPolicy policy,
      Clock clock,
      boolean directoryHistoryVerified,
      boolean resetHistoryVerified,
      CredentialGuard credentials) {
    this(
        database,
        directory,
        policy,
        clock,
        directoryHistoryVerified,
        resetHistoryVerified,
        point -> {},
        credentials);
  }

  private PasswordChangeService(
      Database database,
      DirectoryGateway directory,
      PasswordPolicy policy,
      Clock clock,
      boolean directoryHistoryVerified,
      boolean resetHistoryVerified,
      Hook hook,
      CredentialGuard credentials) {
    this.database = database;
    this.directory = directory;
    this.policy = policy;
    this.clock = clock;
    this.directoryHistoryVerified = directoryHistoryVerified;
    this.resetHistoryVerified = resetHistoryVerified;
    this.hook = hook;
    this.credentials = Objects.requireNonNull(credentials);
  }

  /** Takes ownership of all supplied character arrays and clears them, including on replay. */
  public PasswordOperation change(
      AuthenticatedActor actor,
      String idempotencyKey,
      char[] oldPassword,
      char[] newPassword,
      char[] confirmation) {
    UUID operationId = null;
    try {
      validateKey(idempotencyKey);
      requireRecent(actor);
      PasswordOperation previous = findByKey(actor.userId(), idempotencyKey);
      if (previous != null) return previous;
      if (!directoryHistoryVerified) throw new PasswordFailure(DIRECTORY_POLICY_NOT_VERIFIED);
      User user = claimAttempt(actor);
      if (newPassword == null
          || !Arrays.equals(newPassword, confirmation)
          || oldPassword == null
          || oldPassword.length == 0) throw new PasswordFailure(INVALID_REQUEST);
      if (Arrays.equals(oldPassword, newPassword)
          || !policy.violations(newPassword, user.employee(), user.name()).isEmpty())
        throw new PasswordFailure(POLICY_REJECTED);
      boolean valid;
      String sourceVersion;
      try {
        valid = directory.verifyCredential(user.directoryId(), oldPassword);
        sourceVersion = valid ? directory.passwordVersion(user.directoryId()).orElse(null) : null;
      } catch (DirectoryFailure e) {
        throw new PasswordFailure(DIRECTORY_UNAVAILABLE);
      }
      if (!valid) throw new PasswordFailure(OLD_PASSWORD_INCORRECT);
      PasswordOperation prepared = prepare(actor, idempotencyKey, sourceVersion);
      operationId = prepared.id();
      if (prepared.state() != PasswordOperation.State.PREPARED) return prepared;
      return perform(
          prepared,
          actor.userId(),
          () -> directory.changePassword(user.directoryId(), oldPassword, newPassword));
    } catch (SQLException e) {
      throw new PasswordFailure(STORAGE_UNAVAILABLE, operationId);
    } finally {
      erase(oldPassword);
      erase(newPassword);
      erase(confirmation);
    }
  }

  private PasswordOperation perform(
      PasswordOperation prepared, UUID actorId, Runnable directoryWrite) throws SQLException {
    UUID operationId = prepared.id();
    hook.at(Point.AFTER_PREPARE);
    try {
      directoryWrite.run();
    } catch (DirectoryFailure e) {
      if (e.kind() == DirectoryFailure.Kind.REJECTED)
        return finishRejected(operationId, "DIRECTORY_REJECTED", actorId);
      return uncertain(operationId, "DIRECTORY_RESULT_UNKNOWN", actorId);
    } catch (RuntimeException e) {
      return uncertain(operationId, "DIRECTORY_RESULT_UNKNOWN", actorId);
    }
    hook.at(Point.AFTER_DIRECTORY_WRITE);
    try {
      return finishCommitted(operationId, actorId);
    } catch (SQLException e) {
      return uncertain(operationId, "FINALIZATION_UNAVAILABLE", actorId);
    }
  }

  /** One-time verified recovery grant, never a raw user ID from a reset request. */
  public PasswordOperation reset(
      String resetToken, String key, char[] newPassword, char[] confirmation) {
    UUID operationId = null;
    try {
      validateKey(key);
      if (resetToken == null || !resetToken.matches("[a-zA-Z0-9_-]{43}"))
        throw new PasswordFailure(INVALID_REQUEST);
      if (!resetHistoryVerified || !directory.supportsPasswordReset())
        throw new PasswordFailure(DIRECTORY_POLICY_NOT_VERIFIED);
      String digest = ResetGrantService.digest(resetToken);
      PasswordOperation prepared;
      User target;
      try (Connection c = transaction()) {
        try {
          UUID userId;
          try (PreparedStatement s =
              c.prepareStatement("SELECT user_id FROM password_reset_grant WHERE token_digest=?")) {
            s.setString(1, digest);
            try (ResultSet r = s.executeQuery()) {
              if (!r.next()) throw new PasswordFailure(INVALID_REQUEST);
              userId = r.getObject(1, UUID.class);
            }
          }
          target = user(c, userId);
          try (PreparedStatement s =
              c.prepareStatement(
                  "SELECT * FROM password_reset_grant WHERE token_digest=? FOR UPDATE")) {
            s.setString(1, digest);
            try (ResultSet r = s.executeQuery()) {
              r.next();
              if (r.getTimestamp("consumed_at") != null) {
                PasswordOperation prior = byKey(c, userId, key);
                if (prior == null || !prior.id().equals(r.getObject("operation_id", UUID.class)))
                  throw new PasswordFailure(INVALID_REQUEST);
                c.commit();
                return prior;
              }
              if (!r.getTimestamp("expires_at").toInstant().isAfter(clock.instant()))
                throw new PasswordFailure(INVALID_REQUEST);
              if (!target.status().equals("ACTIVE") || !target.gate().equals("OPEN"))
                throw new PasswordFailure(ACCOUNT_BLOCKED);
              if (r.getLong("auth_epoch") != target.epoch())
                throw new PasswordFailure(STALE_SESSION);
            }
          }
          if (!target.type().equals(directory.type().name()))
            throw new PasswordFailure(INVALID_REQUEST);
          if (newPassword == null || !Arrays.equals(newPassword, confirmation))
            throw new PasswordFailure(INVALID_REQUEST);
          if (!policy.violations(newPassword, target.employee(), target.name()).isEmpty())
            throw new PasswordFailure(POLICY_REJECTED);
          PasswordOperation prior = byKey(c, userId, key);
          if (prior != null) throw new PasswordFailure(INVALID_REQUEST);
          operationId = UUID.randomUUID();
          sql(
              c,
              "UPDATE iam_user SET auth_epoch=auth_epoch+1,password_gate='BLOCKED' WHERE id=?",
              userId);
          sql(
              c,
              "INSERT INTO password_operation(id,user_id,idempotency_key,state,operation_type,fenced_epoch,lease_until,created_at) VALUES (?,?,?,'PREPARED','RESET',?,?,?)",
              operationId,
              userId,
              key,
              target.epoch() + 1,
              Timestamp.from(clock.instant().plusSeconds(30)),
              now());
          sql(
              c,
              "UPDATE password_reset_grant SET consumed_at=?,operation_id=? WHERE token_digest=?",
              now(),
              operationId,
              digest);
          audit(c, operationId, userId, userId, "PASSWORD_RESET_PREPARED", null);
          prepared = operation(c, operationId);
          c.commit();
        } catch (SQLException | RuntimeException e) {
          c.rollback();
          throw e;
        }
      }
      return perform(
          prepared, target.id(), () -> directory.resetPassword(target.directoryId(), newPassword));
    } catch (SQLException e) {
      throw new PasswordFailure(STORAGE_UNAVAILABLE, operationId);
    } finally {
      erase(newPassword);
      erase(confirmation);
    }
  }

  /**
   * Administrative reset is a distinct privileged path, never a user change with elevated LDAP
   * rights.
   */
  public PasswordOperation adminReset(
      AuthenticatedActor admin,
      UUID targetId,
      String key,
      char[] newPassword,
      char[] confirmation) {
    UUID operationId = null;
    try {
      validateKey(key);
      requireAdministrator(admin, "PASSWORD_RESET");
      if (!resetHistoryVerified || !directory.supportsPasswordReset())
        throw new PasswordFailure(DIRECTORY_POLICY_NOT_VERIFIED);
      PasswordOperation prepared;
      User target;
      try (Connection c = transaction()) {
        try {
          // Both user rows are locked in UUID order to avoid cross-admin reset deadlocks.
          if (admin.userId().compareTo(targetId) < 0) {
            user(c, admin.userId());
            target = user(c, targetId);
          } else {
            target = user(c, targetId);
            user(c, admin.userId());
          }
          requireActive(c, user(c, admin.userId()), admin);
          PasswordOperation previous = byKey(c, targetId, key);
          if (previous != null) {
            c.commit();
            return previous;
          }
          if (!target.status().equals("ACTIVE") || !target.gate().equals("OPEN"))
            throw new PasswordFailure(ACCOUNT_BLOCKED);
          if (!target.type().equals(directory.type().name()))
            throw new PasswordFailure(INVALID_REQUEST);
          if (newPassword == null || !Arrays.equals(newPassword, confirmation))
            throw new PasswordFailure(INVALID_REQUEST);
          if (!policy.violations(newPassword, target.employee(), target.name()).isEmpty())
            throw new PasswordFailure(POLICY_REJECTED);
          operationId = UUID.randomUUID();
          sql(
              c,
              "UPDATE iam_user SET auth_epoch=auth_epoch+1,password_gate='BLOCKED' WHERE id=?",
              targetId);
          sql(
              c,
              "INSERT INTO password_operation(id,user_id,idempotency_key,state,operation_type,force_change,fenced_epoch,lease_until,created_at) VALUES (?,?,?,'PREPARED','RESET',true,?,?,?)",
              operationId,
              targetId,
              key,
              target.epoch() + 1,
              Timestamp.from(clock.instant().plusSeconds(30)),
              now());
          audit(c, operationId, targetId, admin.userId(), "ADMIN_PASSWORD_RESET_PREPARED", null);
          prepared = operation(c, operationId);
          c.commit();
        } catch (SQLException | RuntimeException e) {
          c.rollback();
          throw e;
        }
      }
      return perform(
          prepared,
          admin.userId(),
          () -> directory.resetPassword(target.directoryId(), newPassword));
    } catch (SQLException e) {
      throw new PasswordFailure(STORAGE_UNAVAILABLE, operationId);
    } finally {
      erase(newPassword);
      erase(confirmation);
    }
  }

  private User claimAttempt(AuthenticatedActor actor) throws SQLException {
    try (Connection c = transaction()) {
      try {
        User user = user(c, actor.userId());
        requireActive(c, user, actor);
        try (PreparedStatement s =
            c.prepareStatement(
                "SELECT requested_at FROM password_request_guard WHERE user_id=? FOR UPDATE")) {
          s.setObject(1, actor.userId());
          try (ResultSet r = s.executeQuery()) {
            if (r.next() && r.getTimestamp(1).toInstant().plusSeconds(60).isAfter(clock.instant()))
              throw new PasswordFailure(RATE_LIMITED);
          }
        }
        sql(
            c,
            "INSERT INTO password_request_guard(user_id,requested_at) VALUES (?,?) ON CONFLICT(user_id) DO UPDATE SET requested_at=excluded.requested_at",
            actor.userId(),
            now());
        c.commit();
        return user;
      } catch (SQLException | RuntimeException e) {
        c.rollback();
        throw e;
      }
    }
  }

  private PasswordOperation prepare(AuthenticatedActor actor, String key, String sourceVersion)
      throws SQLException {
    try (Connection c = transaction()) {
      try {
        User user = user(c, actor.userId());
        PasswordOperation previous = byKey(c, actor.userId(), key);
        if (previous != null) {
          c.commit();
          return previous;
        }
        requireActive(c, user, actor);
        try (PreparedStatement s =
            c.prepareStatement(
                "SELECT 1 FROM password_operation WHERE user_id=? AND state IN ('PREPARED','UNKNOWN')")) {
          s.setObject(1, user.id());
          try (ResultSet r = s.executeQuery()) {
            if (r.next()) throw new PasswordFailure(CONCURRENT_OPERATION);
          }
        }
        UUID id = UUID.randomUUID();
        sql(
            c,
            "UPDATE iam_user SET auth_epoch=auth_epoch+1,password_gate='BLOCKED' WHERE id=?",
            user.id());
        sql(
            c,
            "INSERT INTO password_operation(id,user_id,idempotency_key,state,operation_type,fenced_epoch,source_version,lease_until,created_at) VALUES (?,?,?,'PREPARED','CHANGE',?,?,?,?)",
            id,
            user.id(),
            key,
            user.epoch() + 1,
            sourceVersion,
            Timestamp.from(clock.instant().plusSeconds(30)),
            now());
        audit(c, id, user.id(), actor.userId(), "PASSWORD_PREPARED", null);
        PasswordOperation operation = operation(c, id);
        c.commit();
        return operation;
      } catch (SQLException | RuntimeException e) {
        c.rollback();
        throw e;
      }
    }
  }

  private PasswordOperation finishCommitted(UUID id, UUID actorId) throws SQLException {
    try (Connection c = transaction()) {
      try {
        PasswordOperation operation = lockedOperation(c, id);
        if (operation.state() == PasswordOperation.State.COMMITTED) {
          c.commit();
          return operation;
        }
        if (operation.state() == PasswordOperation.State.REJECTED)
          throw new PasswordFailure(RECOVERY_NOT_PERMITTED, id);
        // A concurrent disable has its own higher epoch and must never be undone.
        sql(
            c,
            "UPDATE iam_user SET password_changed_at=?,must_change_password=(SELECT force_change FROM password_operation WHERE id=?),password_gate=CASE WHEN status='ACTIVE' AND auth_epoch=? THEN 'OPEN' ELSE password_gate END WHERE id=?",
            now(),
            id,
            operation.fencedEpoch(),
            operation.userId());
        sql(
            c,
            "UPDATE password_operation SET state='COMMITTED',finished_at=?,error_code=NULL WHERE id=?",
            now(),
            id);
        addEventAndTasks(c, operation);
        audit(c, id, operation.userId(), actorId, "PASSWORD_CHANGED", null);
        hook.at(Point.BEFORE_COMMIT);
        c.commit();
        hook.at(Point.AFTER_COMMIT);
        return get(id, operation.userId());
      } catch (SQLException | RuntimeException e) {
        c.rollback();
        throw e;
      }
    }
  }

  private PasswordOperation finishRejected(UUID id, String reason, UUID actorId)
      throws SQLException {
    try (Connection c = transaction()) {
      try {
        PasswordOperation operation = lockedOperation(c, id);
        if (operation.state() == PasswordOperation.State.COMMITTED
            || operation.state() == PasswordOperation.State.REJECTED) {
          c.commit();
          return operation;
        }
        sql(
            c,
            "UPDATE password_operation SET state='REJECTED',error_code=?,finished_at=? WHERE id=?",
            reason,
            now(),
            id);
        sql(
            c,
            "UPDATE iam_user SET password_gate='OPEN' WHERE id=? AND auth_epoch=? AND status='ACTIVE'",
            operation.userId(),
            operation.fencedEpoch());
        audit(c, id, operation.userId(), actorId, "PASSWORD_REJECTED", reason);
        c.commit();
        return get(id, operation.userId());
      } catch (SQLException | RuntimeException e) {
        c.rollback();
        throw e;
      }
    }
  }

  private PasswordOperation uncertain(UUID id, String reason, UUID actorId) {
    try (Connection c = transaction()) {
      try {
        PasswordOperation operation = lockedOperation(c, id);
        if (operation.state() == PasswordOperation.State.PREPARED) {
          sql(
              c,
              "UPDATE password_operation SET state='UNKNOWN',error_code=? WHERE id=?",
              reason,
              id);
          audit(c, id, operation.userId(), actorId, "PASSWORD_UNKNOWN", reason);
        }
        c.commit();
        return get(id, operation.userId());
      } catch (SQLException | RuntimeException e) {
        c.rollback();
        throw e;
      }
    } catch (SQLException e) {
      throw new PasswordFailure(STORAGE_UNAVAILABLE, id);
    }
  }

  /**
   * Safe periodic recovery: mark expired intents UNKNOWN, never replay a password or infer success.
   */
  public int markAbandonedUnknown() {
    try {
      List<UUID> candidates = new ArrayList<>();
      try (Connection c = database.open();
          PreparedStatement s =
              c.prepareStatement(
                  "SELECT id FROM password_operation WHERE state='PREPARED' AND lease_until<? ORDER BY lease_until LIMIT 100")) {
        s.setTimestamp(1, now());
        try (ResultSet r = s.executeQuery()) {
          while (r.next()) candidates.add(r.getObject(1, UUID.class));
        }
      }
      int count = 0;
      for (UUID id : candidates) {
        try (Connection c = transaction()) {
          try {
            PasswordOperation operation = lockedOperation(c, id);
            if (operation.state() == PasswordOperation.State.PREPARED) {
              sql(
                  c,
                  "UPDATE password_operation SET state='UNKNOWN',error_code='WORKER_INTERRUPTED' WHERE id=?",
                  id);
              audit(
                  c,
                  id,
                  operation.userId(),
                  operation.userId(),
                  "PASSWORD_UNKNOWN_TIMEOUT",
                  "WORKER_INTERRUPTED");
              count++;
            }
            c.commit();
          } catch (SQLException | RuntimeException e) {
            c.rollback();
            throw e;
          }
        }
      }
      return count;
    } catch (SQLException e) {
      throw new PasswordFailure(STORAGE_UNAVAILABLE);
    }
  }

  /**
   * Only an authenticated administrator with recent MFA and external evidence may resolve
   * ambiguity.
   */
  public PasswordOperation recover(
      AuthenticatedActor admin, UUID id, boolean confirmedCommitted, String evidenceRef) {
    requireAdministrator(admin, "PASSWORD_RECOVERY");
    if (evidenceRef == null || !evidenceRef.matches("[a-zA-Z0-9:/_.-]{8,500}"))
      throw new PasswordFailure(RECOVERY_EVIDENCE_REQUIRED);
    try (Connection c = transaction()) {
      try {
        PasswordOperation candidate = operation(c, id);
        if (admin.userId().compareTo(candidate.userId()) < 0) {
          user(c, admin.userId());
          user(c, candidate.userId());
        } else {
          user(c, candidate.userId());
          user(c, admin.userId());
        }
        requireActive(c, user(c, admin.userId()), admin);
        PasswordOperation operation = lockedOperation(c, id);
        if (operation.state() != PasswordOperation.State.UNKNOWN) {
          boolean expected =
              operation.state()
                  == (confirmedCommitted
                      ? PasswordOperation.State.COMMITTED
                      : PasswordOperation.State.REJECTED);
          try (PreparedStatement s =
              c.prepareStatement(
                  "SELECT recovered_by,recovery_evidence_ref FROM password_operation WHERE id=?")) {
            s.setObject(1, id);
            try (ResultSet r = s.executeQuery()) {
              r.next();
              if (expected
                  && admin.userId().equals(r.getObject(1, UUID.class))
                  && evidenceRef.equals(r.getString(2))) {
                c.commit();
                return operation;
              }
            }
          }
          throw new PasswordFailure(RECOVERY_NOT_PERMITTED, id);
        }
        try (PreparedStatement s =
            c.prepareStatement("SELECT lease_until FROM password_operation WHERE id=?")) {
          s.setObject(1, id);
          try (ResultSet r = s.executeQuery()) {
            r.next();
            if (r.getTimestamp(1).toInstant().isAfter(clock.instant()))
              throw new PasswordFailure(RECOVERY_NOT_PERMITTED, id);
          }
        }
        sql(
            c,
            "UPDATE password_operation SET state=?,error_code=?,finished_at=?,recovery_evidence_ref=?,recovered_by=? WHERE id=?",
            confirmedCommitted ? "COMMITTED" : "REJECTED",
            confirmedCommitted ? null : "VERIFIED_NOT_CHANGED",
            now(),
            evidenceRef,
            admin.userId(),
            id);
        sql(
            c,
            "UPDATE iam_user SET password_gate=CASE WHEN status='ACTIVE' AND auth_epoch=? THEN 'OPEN' ELSE password_gate END,password_changed_at=CASE WHEN ? THEN ? ELSE password_changed_at END,must_change_password=CASE WHEN ? THEN (SELECT force_change FROM password_operation WHERE id=?) ELSE must_change_password END WHERE id=?",
            operation.fencedEpoch(),
            confirmedCommitted,
            now(),
            confirmedCommitted,
            id,
            operation.userId());
        if (confirmedCommitted) addEventAndTasks(c, operation);
        audit(
            c,
            id,
            operation.userId(),
            admin.userId(),
            confirmedCommitted ? "PASSWORD_RECOVERED_COMMITTED" : "PASSWORD_RECOVERED_REJECTED",
            null);
        PasswordOperation result = operation(c, id);
        c.commit();
        return result;
      } catch (SQLException | RuntimeException e) {
        c.rollback();
        throw e;
      }
    } catch (SQLException e) {
      throw new PasswordFailure(STORAGE_UNAVAILABLE, id);
    }
  }

  private PasswordOperation lockedOperation(Connection c, UUID id) throws SQLException {
    PasswordOperation candidate = operation(c, id);
    user(c, candidate.userId());
    try (PreparedStatement s =
        c.prepareStatement("SELECT id FROM password_operation WHERE id=? FOR UPDATE")) {
      s.setObject(1, id);
      s.executeQuery().close();
    }
    return operation(c, id);
  }

  private void addEventAndTasks(Connection c, PasswordOperation operation) throws SQLException {
    UUID id = operation.id();
    String payload =
        "{\"user_id\":\""
            + operation.userId()
            + "\",\"operation_id\":\""
            + id
            + "\",\"auth_epoch\":"
            + operation.fencedEpoch()
            + "}";
    sql(
        c,
        "INSERT INTO outbox_event(event_id,aggregate_id,event_type,auth_epoch,payload,created_at) VALUES (?,?,'unipass.password.changed',?,?::jsonb,?) ON CONFLICT DO NOTHING",
        id,
        operation.userId(),
        operation.fencedEpoch(),
        payload,
        now());
    for (String target : List.of("FEISHU_APP_REAUTH", "APP_PUSH"))
      sql(
          c,
          "INSERT INTO sync_task(id,event_id,target,state,next_retry_at) VALUES (?,?,?,'PENDING',?) ON CONFLICT(event_id,target) DO NOTHING",
          UUID.randomUUID(),
          id,
          target,
          now());
  }

  public PasswordOperation get(UUID id, UUID requestingUser) {
    try (Connection c = database.open()) {
      PasswordOperation operation = operation(c, id);
      if (!operation.userId().equals(requestingUser)) throw new PasswordFailure(NOT_FOUND);
      return operation;
    } catch (SQLException e) {
      throw new PasswordFailure(STORAGE_UNAVAILABLE, id);
    }
  }

  private PasswordOperation findByKey(UUID userId, String key) throws SQLException {
    try (Connection c = database.open()) {
      return byKey(c, userId, key);
    }
  }

  /** Read-only recovery after a lost write response; never resubmits a directory password. */
  public PasswordOperation getByRequest(UUID requestingUser, String key) {
    validateKey(key);
    try {
      PasswordOperation operation = findByKey(requestingUser, key);
      if (operation == null) throw new PasswordFailure(NOT_FOUND);
      return operation;
    } catch (SQLException failure) {
      throw new PasswordFailure(STORAGE_UNAVAILABLE);
    }
  }

  private static PasswordOperation byKey(Connection c, UUID userId, String key)
      throws SQLException {
    try (PreparedStatement s =
        c.prepareStatement(
            "SELECT id FROM password_operation WHERE user_id=? AND idempotency_key=?")) {
      s.setObject(1, userId);
      s.setString(2, key);
      try (ResultSet r = s.executeQuery()) {
        return r.next() ? operation(c, r.getObject(1, UUID.class)) : null;
      }
    }
  }

  private static PasswordOperation operation(Connection c, UUID id) throws SQLException {
    try (PreparedStatement s = c.prepareStatement("SELECT * FROM password_operation WHERE id=?")) {
      s.setObject(1, id);
      try (ResultSet r = s.executeQuery()) {
        if (!r.next()) throw new PasswordFailure(NOT_FOUND);
        Timestamp finished = r.getTimestamp("finished_at");
        return new PasswordOperation(
            id,
            r.getObject("user_id", UUID.class),
            PasswordOperation.State.valueOf(r.getString("state")),
            r.getLong("fenced_epoch"),
            r.getTimestamp("created_at").toInstant(),
            finished == null ? null : finished.toInstant(),
            r.getString("error_code"));
      }
    }
  }

  private User user(Connection c, UUID id) throws SQLException {
    try (PreparedStatement s = c.prepareStatement("SELECT * FROM iam_user WHERE id=? FOR UPDATE")) {
      s.setObject(1, id);
      try (ResultSet r = s.executeQuery()) {
        if (!r.next()) throw new PasswordFailure(NOT_FOUND);
        return new User(
            id,
            r.getString("directory_id"),
            r.getString("directory_type"),
            r.getString("employee_no"),
            r.getString("display_name"),
            r.getString("status"),
            r.getString("password_gate"),
            r.getLong("auth_epoch"));
      }
    }
  }

  private void requireActive(Connection connection, User user, AuthenticatedActor actor)
      throws SQLException {
    if (!user.status().equals("ACTIVE") || !user.gate().equals("OPEN"))
      throw new PasswordFailure(ACCOUNT_BLOCKED);
    if (user.epoch() != actor.authEpoch()) throw new PasswordFailure(STALE_SESSION);
    if (!user.type().equals(directory.type().name())) throw new PasswordFailure(INVALID_REQUEST);
    credentials.require(connection, actor);
  }

  private void requireRecent(AuthenticatedActor actor) {
    if (actor == null
        || actor.authenticatedAt().isAfter(clock.instant())
        || actor.authenticatedAt().plus(RECENT_AUTH).isBefore(clock.instant()))
      throw new PasswordFailure(RECENT_AUTH_REQUIRED);
  }

  private void requireAdministrator(AuthenticatedActor actor, String authority) {
    requireRecent(actor);
    if (!actor.authorities().contains(authority)
        || actor.mfaAt() == null
        || actor.mfaAt().isAfter(clock.instant())
        || actor.mfaAt().plus(RECENT_AUTH).isBefore(clock.instant()))
      throw new PasswordFailure(RECOVERY_NOT_PERMITTED);
  }

  private static void validateKey(String key) {
    if (key == null || !key.matches("[a-zA-Z0-9_-]{16,128}"))
      throw new PasswordFailure(INVALID_REQUEST);
  }

  private Connection transaction() throws SQLException {
    Connection c = database.open();
    c.setAutoCommit(false);
    try {
      sql(c, "SET LOCAL lock_timeout='3s'");
      sql(c, "SET LOCAL statement_timeout='10s'");
      return c;
    } catch (SQLException e) {
      c.close();
      throw e;
    }
  }

  private void audit(
      Connection c, UUID operationId, UUID userId, UUID actorId, String action, String error)
      throws SQLException {
    sql(
        c,
        "INSERT INTO password_audit(id,operation_id,user_id,actor_id,action,error_code,trace_id,created_at) VALUES (?,?,?,?,?,?,?,?)",
        UUID.randomUUID(),
        operationId,
        userId,
        actorId,
        action,
        error,
        operationId,
        now());
  }

  private Timestamp now() {
    return Timestamp.from(clock.instant());
  }

  private static void sql(Connection c, String query, Object... values) throws SQLException {
    try (PreparedStatement s = c.prepareStatement(query)) {
      for (int i = 0; i < values.length; i++) s.setObject(i + 1, values[i]);
      s.executeUpdate();
    }
  }

  private static void erase(char[] value) {
    if (value != null) Arrays.fill(value, '\0');
  }
}
