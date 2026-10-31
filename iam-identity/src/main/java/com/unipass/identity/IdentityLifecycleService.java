package com.unipass.identity;

import static com.unipass.identity.IdentityImportService.*;

import com.unipass.directory.*;
import java.sql.*;
import java.util.UUID;

public final class IdentityLifecycleService {
  private final Database db;
  private final DirectoryGateway directory;

  public IdentityLifecycleService(Database db, DirectoryGateway directory) {
    this.db = db;
    this.directory = directory;
  }

  /** Commit local access denial before making any call to the external directory. */
  public void disable(UUID userId, UUID traceId) throws SQLException {
    try (Connection c = db.open()) {
      c.setAutoCommit(false);
      try {
        lock(c);
        int changed;
        try (PreparedStatement s =
            c.prepareStatement(
                "UPDATE iam_user SET auth_epoch=auth_epoch+CASE WHEN status='DISABLED' THEN 0 ELSE 1 END,status='DISABLED',password_gate='BLOCKED' WHERE id=?")) {
          s.setObject(1, userId);
          changed = s.executeUpdate();
        }
        if (changed != 1) throw new IllegalArgumentException("Unknown user");
        enqueueDisable(c, userId);
        execute(
            c,
            "INSERT INTO identity_audit(id,user_id,action,trace_id) VALUES (?,?,'USER_DISABLED',?)",
            UUID.randomUUID(),
            userId,
            traceId);
        c.commit();
      } catch (SQLException | RuntimeException e) {
        c.rollback();
        throw e;
      }
    }
  }

  /**
   * Single bounded attempt; durable retry survives crashes. Only idempotent disables are retried.
   */
  public boolean reconcileOne() throws SQLException {
    UUID userId;
    String directoryId;
    String directoryType;
    UUID leaseToken = UUID.randomUUID();
    // Reserve a 60 second retry window in a short transaction, no DB lock over network calls.
    try (Connection c = db.open()) {
      c.setAutoCommit(false);
      try (PreparedStatement s =
          c.prepareStatement(
              "SELECT t.user_id,u.directory_id,u.directory_type FROM directory_disable_task t JOIN iam_user u ON u.id=t.user_id WHERE t.state='PENDING' AND t.next_attempt_at<=now() ORDER BY t.next_attempt_at LIMIT 1 FOR UPDATE OF t SKIP LOCKED")) {
        try (ResultSet r = s.executeQuery()) {
          if (!r.next()) {
            c.commit();
            return false;
          }
          userId = r.getObject(1, UUID.class);
          directoryId = r.getString(2);
          directoryType = r.getString(3);
        }
        execute(
            c,
            "UPDATE directory_disable_task SET attempts=attempts+1,lease_token=?,next_attempt_at=now()+interval '60 seconds',updated_at=now() WHERE user_id=?",
            leaseToken,
            userId);
        c.commit();
      } catch (SQLException | RuntimeException e) {
        c.rollback();
        throw e;
      }
    }
    String error = null;
    try {
      if (!directory.type().name().equals(directoryType))
        throw new IllegalStateException("Directory type mismatch");
      directory.disableUser(directoryId);
    } catch (DirectoryFailure e) {
      error = e.kind().name();
    } catch (IllegalStateException e) {
      error = "WRITER_NOT_CONFIGURED";
    }
    try (Connection c = db.open()) {
      execute(
          c,
          "UPDATE directory_disable_task SET state=?,last_error=?,updated_at=now() WHERE user_id=? AND lease_token=?",
          error == null ? "DONE" : "PENDING",
          error,
          userId,
          leaseToken);
    }
    return true;
  }

  /** Fresh DB read: outage cannot silently authenticate an otherwise valid LDAP credential. */
  public boolean canAuthenticate(UUID userId, long epoch) throws SQLException {
    try (Connection c = db.open();
        PreparedStatement s =
            c.prepareStatement(
                "SELECT 1 FROM iam_user WHERE id=? AND status='ACTIVE' AND password_gate='OPEN' AND auth_epoch=?")) {
      s.setObject(1, userId);
      s.setLong(2, epoch);
      try (ResultSet r = s.executeQuery()) {
        return r.next();
      }
    }
  }
}
