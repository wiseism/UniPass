package com.unipass.server;

import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.*;
import java.util.*;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

/** Replacing a factor never creates a password-only token issuance window. */
@Service
public final class MfaLifecycleService {
  private static final String AUTHORITY = "ROLE_ADMIN_MFA_RECOVERY";
  private final JdbcTemplate jdbc;
  private final TransactionTemplate tx;
  private final AccountState accounts;
  private final MfaService mfa;
  private final Clock clock;

  public MfaLifecycleService(
      JdbcTemplate jdbc,
      TransactionTemplate tx,
      AccountState accounts,
      MfaService mfa,
      Clock clock) {
    this.jdbc = jdbc;
    this.tx = tx;
    this.accounts = accounts;
    this.mfa = mfa;
    this.clock = clock;
  }

  public record Replacement(UUID id, String secret, String otpauthUri, Instant expiresAt) {
    @Override
    public String toString() {
      return "Replacement[REDACTED]";
    }
  }

  public record RecoveryGrant(UUID id, String token, Instant expiresAt) {
    @Override
    public String toString() {
      return "RecoveryGrant[REDACTED]";
    }
  }

  private record Grant(
      UUID id,
      UUID user,
      UUID actor,
      long actorEpoch,
      long epoch,
      String reason,
      String evidence,
      Instant expires,
      boolean consumed,
      boolean revoked) {}

  private record Change(
      UUID user,
      long epoch,
      String session,
      byte[] encrypted,
      String mode,
      UUID grant,
      String state,
      Instant expires) {}

  private static ResponseStatusException denied() {
    return new ResponseStatusException(
        HttpStatus.BAD_REQUEST, "Invalid or expired factor operation");
  }

  private void recentPassword(IdentityPrincipal principal) {
    Instant now = clock.instant();
    if (!principal.hasRecentPassword(now))
      throw new ResponseStatusException(
          HttpStatus.FORBIDDEN, "Recent password authentication required");
  }

  private void lockUsers(UUID target, UUID actor) {
    int expected = target.equals(actor) ? 1 : 2;
    if (jdbc.queryForList(
                "SELECT id FROM iam_user WHERE id IN (?,?) ORDER BY id FOR UPDATE",
                UUID.class,
                target,
                actor)
            .size()
        != expected)
      throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Identity unavailable");
  }

  private boolean liveIssuer(Grant grant) {
    return accounts.allowed(grant.actor, grant.actorEpoch)
        && accounts.roles(grant.actor).contains(AUTHORITY);
  }

  public RecoveryGrant authorizeRecovery(
      IdentityPrincipal principal, UUID target, String key, String reason, String evidence) {
    if (target.equals(principal.getUserId()))
      throw new ResponseStatusException(
          HttpStatus.FORBIDDEN, "Independent recovery operator required");
    if (key == null
        || !key.matches("[A-Za-z0-9_-]{16,128}")
        || reason == null
        || reason.isBlank()
        || reason.length() > 500
        || reason.codePoints().anyMatch(Character::isISOControl)
        || evidence == null
        || !evidence.matches("[A-Za-z0-9:/_.-]{8,500}"))
      throw new ResponseStatusException(
          HttpStatus.BAD_REQUEST, "Reason, evidence and idempotency key required");
    return tx.execute(
        status -> {
          lockUsers(target, principal.getUserId());
          accounts.lockAndRequire(principal);
          recentPassword(principal);
          if (!mfa.recent(principal) || !accounts.roles(principal.getUserId()).contains(AUTHORITY))
            throw new ResponseStatusException(
                HttpStatus.FORBIDDEN, "Recovery authority and recent MFA required");
          var previous =
              jdbc.query(
                  "SELECT * FROM mfa_recovery_grant WHERE actor_id=? AND user_id=? AND idempotency_key=?",
                  (r, n) -> grant(r),
                  principal.getUserId(),
                  target,
                  key);
          if (!previous.isEmpty()) {
            Grant prior = previous.get(0);
            if (!reason.equals(prior.reason) || !evidence.equals(prior.evidence))
              throw new ResponseStatusException(HttpStatus.CONFLICT, "Idempotency context changed");
            return new RecoveryGrant(
                prior.id,
                null,
                prior.expires); // A retry cannot recover a raw capability from its digest.
          }
          var epochs =
              jdbc.queryForList(
                  "SELECT auth_epoch FROM iam_user WHERE id=? AND status='ACTIVE' AND password_gate='OPEN'",
                  Long.class,
                  target);
          if (epochs.isEmpty() || !mfa.enrolled(target) && !mfa.recoveryRequired(target))
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Enabled factor required");
          long epoch = epochs.get(0);
          Instant now = clock.instant(), expires = now.plusSeconds(900);
          UUID id = UUID.randomUUID();
          byte[] random = new byte[32];
          new SecureRandom().nextBytes(random);
          String token;
          try {
            token = Base64.getUrlEncoder().withoutPadding().encodeToString(random);
          } finally {
            Arrays.fill(random, (byte) 0);
          }
          jdbc.update(
              "UPDATE mfa_recovery_grant SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL",
              Timestamp.from(now),
              target);
          supersede(target, now);
          jdbc.update("DELETE FROM mfa_totp WHERE user_id=?", target);
          fence(target, true, now);
          jdbc.update(
              "INSERT INTO mfa_recovery_grant(id,user_id,actor_id,actor_epoch,auth_epoch,token_digest,idempotency_key,reason,evidence_ref,expires_at,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
              id,
              target,
              principal.getUserId(),
              principal.getEpoch(),
              epoch + 1,
              DigestAuthorizationService.digest(token),
              key,
              reason,
              evidence,
              Timestamp.from(expires),
              Timestamp.from(now));
          accounts.audit(target, "MFA_RECOVERY_AUTHORIZED");
          return new RecoveryGrant(id, token, expires);
        });
  }

  public Replacement rotate(IdentityPrincipal principal, String session) {
    return tx.execute(
        status -> {
          accounts.lockAndRequire(principal);
          recentPassword(principal);
          if (!mfa.recent(principal)
              || !mfa.enrolled(principal.getUserId())
              || mfa.recoveryRequired(principal.getUserId()))
            throw new ResponseStatusException(
                HttpStatus.FORBIDDEN, "Current factor verification required");
          return begin(principal, session, "ROTATE", null, clock.instant().plusSeconds(300));
        });
  }

  public Replacement recover(IdentityPrincipal principal, String session, String token) {
    recentPassword(principal);
    if (token == null || !token.matches("[A-Za-z0-9_-]{43}")) throw denied();
    var rows =
        jdbc.query(
            "SELECT * FROM mfa_recovery_grant WHERE token_digest=? AND user_id=?",
            (r, n) -> grant(r),
            DigestAuthorizationService.digest(token),
            principal.getUserId());
    if (rows.isEmpty()) throw denied();
    Grant observed = rows.get(0);
    return tx.execute(
        status -> {
          lockUsers(principal.getUserId(), observed.actor);
          accounts.lockAndRequire(principal);
          recentPassword(principal);
          Grant current =
              jdbc.queryForObject(
                  "SELECT * FROM mfa_recovery_grant WHERE id=? FOR UPDATE",
                  (r, n) -> grant(r),
                  observed.id);
          if (current == null
              || current.consumed
              || current.revoked
              || !current.expires.isAfter(clock.instant())
              || current.epoch != principal.getEpoch()
              || !mfa.recoveryRequired(principal.getUserId())
              || !liveIssuer(current)) throw denied();
          Instant expires = clock.instant().plusSeconds(300);
          if (current.expires.isBefore(expires)) expires = current.expires;
          Replacement replacement = begin(principal, session, "RECOVER", current.id, expires);
          jdbc.update(
              "UPDATE mfa_recovery_grant SET consumed_at=? WHERE id=?",
              Timestamp.from(clock.instant()),
              current.id);
          return replacement;
        });
  }

  private Replacement begin(
      IdentityPrincipal principal, String session, String mode, UUID grant, Instant expires) {
    UUID user = principal.getUserId();
    unlocked(user);
    Instant now = clock.instant();
    supersede(user, now);
    byte[] secret = new byte[20];
    new SecureRandom().nextBytes(secret);
    try {
      UUID id = UUID.randomUUID();
      var enrollment = mfa.enrollment(user, secret, expires);
      jdbc.update(
          "INSERT INTO mfa_factor_change(id,user_id,auth_epoch,session_digest,secret_cipher,mode,recovery_grant_id,state,expires_at,created_at) VALUES (?,?,?,?,?,?,?,'PENDING',?,?)",
          id,
          user,
          principal.getEpoch(),
          DigestAuthorizationService.digest(session),
          mfa.encrypt(user, secret),
          mode,
          grant,
          Timestamp.from(expires),
          Timestamp.from(now));
      accounts.audit(user, "MFA_" + mode + "_STARTED");
      return new Replacement(id, enrollment.secret(), enrollment.otpauthUri(), expires);
    } finally {
      Arrays.fill(secret, (byte) 0);
    }
  }

  private Change change(UUID id, boolean lock) {
    var rows =
        jdbc.query(
            "SELECT * FROM mfa_factor_change WHERE id=?" + (lock ? " FOR UPDATE" : ""),
            (r, n) ->
                new Change(
                    r.getObject("user_id", UUID.class),
                    r.getLong("auth_epoch"),
                    r.getString("session_digest"),
                    r.getBytes("secret_cipher"),
                    r.getString("mode"),
                    r.getObject("recovery_grant_id", UUID.class),
                    r.getString("state"),
                    r.getTimestamp("expires_at").toInstant()),
            id);
    if (rows.isEmpty()) throw denied();
    return rows.get(0);
  }

  public void confirm(IdentityPrincipal principal, String session, UUID id, String code) {
    Change observed = change(id, false);
    if (!observed.user.equals(principal.getUserId())) throw denied();
    Grant issuer =
        observed.grant == null
            ? null
            : jdbc.queryForObject(
                "SELECT * FROM mfa_recovery_grant WHERE id=?", (r, n) -> grant(r), observed.grant);
    boolean valid =
        Boolean.TRUE.equals(
            tx.execute(
                status -> {
                  lockUsers(
                      principal.getUserId(), issuer == null ? principal.getUserId() : issuer.actor);
                  accounts.lockAndRequire(principal);
                  recentPassword(principal);
                  Change current = change(id, true);
                  Instant now = clock.instant();
                  if (!"PENDING".equals(current.state)
                      || current.epoch != principal.getEpoch()
                      || !current.session.equals(DigestAuthorizationService.digest(session))
                      || !current.expires.isAfter(now)) throw denied();
                  if ("ROTATE".equals(current.mode)) {
                    if (!mfa.recent(principal)
                        || !mfa.enrolled(current.user)
                        || mfa.recoveryRequired(current.user))
                      throw new ResponseStatusException(
                          HttpStatus.FORBIDDEN, "Current factor verification required");
                  } else {
                    Grant grant =
                        jdbc.queryForObject(
                            "SELECT * FROM mfa_recovery_grant WHERE id=? FOR UPDATE",
                            (r, n) -> grant(r),
                            current.grant);
                    if (grant == null
                        || !grant.consumed
                        || grant.revoked
                        || !grant.expires.isAfter(now)
                        || grant.epoch != principal.getEpoch()
                        || !mfa.recoveryRequired(current.user)
                        || !liveIssuer(grant)) throw denied();
                  }
                  unlocked(current.user);
                  long step = mfa.matchingStep(current.user, current.encrypted, -1, code);
                  if (step < 0) {
                    failed(current.user, now);
                    return false;
                  }
                  jdbc.update(
                      "INSERT INTO mfa_totp(user_id,secret_cipher,enabled,last_used_step) VALUES (?,?,true,?) ON CONFLICT(user_id) DO UPDATE SET secret_cipher=excluded.secret_cipher,enabled=true,pending_expires_at=NULL,last_used_step=excluded.last_used_step,failed_attempts=0,locked_until=NULL",
                      current.user,
                      mfa.reencrypt(current.user, current.encrypted),
                      step);
                  jdbc.update(
                      "UPDATE mfa_factor_change SET state='COMMITTED',secret_cipher=NULL,finished_at=? WHERE id=?",
                      Timestamp.from(now),
                      id);
                  jdbc.update(
                      "UPDATE mfa_lifecycle_guard SET failed_attempts=0,locked_until=NULL WHERE user_id=?",
                      current.user);
                  fence(current.user, false, now);
                  accounts.audit(current.user, "MFA_" + current.mode + "_COMMITTED");
                  return true;
                }));
    if (!valid) throw denied(); // Persist a failed attempt even when the HTTP request is rejected.
  }

  public void cancel(IdentityPrincipal principal, String session, UUID id) {
    tx.executeWithoutResult(
        status -> {
          accounts.lockAndRequire(principal);
          Change current = change(id, true);
          if (!current.user.equals(principal.getUserId())
              || current.epoch != principal.getEpoch()
              || !current.session.equals(DigestAuthorizationService.digest(session))
              || !"PENDING".equals(current.state)) throw denied();
          jdbc.update(
              "UPDATE mfa_factor_change SET state='CANCELLED',secret_cipher=NULL,finished_at=? WHERE id=?",
              Timestamp.from(clock.instant()),
              id);
          accounts.audit(current.user, "MFA_FACTOR_CHANGE_CANCELLED");
        });
  }

  private void fence(UUID user, boolean recovery, Instant now) {
    jdbc.update(
        "UPDATE iam_user SET auth_epoch=auth_epoch+1,mfa_recovery_required=? WHERE id=?",
        recovery,
        user);
    jdbc.update(
        "UPDATE oauth2_authorization SET revoked=true WHERE principal_name=? AND revoked=false",
        user.toString());
    jdbc.update(
        "UPDATE mfa_challenge SET consumed_at=? WHERE user_id=? AND consumed_at IS NULL",
        Timestamp.from(now),
        user);
  }

  private void supersede(UUID user, Instant now) {
    jdbc.update(
        "UPDATE mfa_factor_change SET state='SUPERSEDED',secret_cipher=NULL,finished_at=? WHERE user_id=? AND state='PENDING'",
        Timestamp.from(now),
        user);
  }

  private void unlocked(UUID user) {
    jdbc.update("INSERT INTO mfa_lifecycle_guard(user_id) VALUES (?) ON CONFLICT DO NOTHING", user);
    var until =
        jdbc.queryForObject(
            "SELECT locked_until FROM mfa_lifecycle_guard WHERE user_id=? FOR UPDATE",
            Timestamp.class,
            user);
    if (until != null && until.toInstant().isAfter(clock.instant()))
      throw new ResponseStatusException(
          HttpStatus.TOO_MANY_REQUESTS, "Factor change temporarily locked");
  }

  private void failed(UUID user, Instant now) {
    int count =
        jdbc.queryForObject(
            "SELECT CASE WHEN locked_until<=? THEN 1 ELSE failed_attempts+1 END FROM mfa_lifecycle_guard WHERE user_id=?",
            Integer.class,
            Timestamp.from(now),
            user);
    jdbc.update(
        "UPDATE mfa_lifecycle_guard SET failed_attempts=?,locked_until=? WHERE user_id=?",
        count,
        count >= 5 ? Timestamp.from(now.plusSeconds(1800)) : null,
        user);
    accounts.audit(user, "MFA_FACTOR_CHANGE_FAILED");
  }

  public int expire() {
    return jdbc.update(
        "UPDATE mfa_factor_change SET state='EXPIRED',secret_cipher=NULL,finished_at=? WHERE state='PENDING' AND expires_at<=?",
        Timestamp.from(clock.instant()),
        Timestamp.from(clock.instant()));
  }

  private static Grant grant(java.sql.ResultSet r) throws java.sql.SQLException {
    return new Grant(
        r.getObject("id", UUID.class),
        r.getObject("user_id", UUID.class),
        r.getObject("actor_id", UUID.class),
        r.getLong("actor_epoch"),
        r.getLong("auth_epoch"),
        r.getString("reason"),
        r.getString("evidence_ref"),
        r.getTimestamp("expires_at").toInstant(),
        r.getTimestamp("consumed_at") != null,
        r.getTimestamp("revoked_at") != null);
  }
}
