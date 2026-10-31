package com.unipass.server;

import com.unipass.identity.Database;
import com.unipass.password.*;
import java.sql.Timestamp;
import java.time.Clock;
import java.util.*;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

@Service
public final class EmailRecoveryService {
  private final JdbcTemplate jdbc;
  private final TransactionTemplate tx;
  private final Clock clock;
  private final RecoveryEmailSender sender;
  private final RecoveryRateLimiter limiter;
  private final ResetGrantService grants;
  private final PasswordChangeService passwords;

  public EmailRecoveryService(
      JdbcTemplate jdbc,
      TransactionTemplate tx,
      Clock clock,
      RecoveryEmailSender sender,
      RecoveryRateLimiter limiter,
      Database db,
      PasswordChangeService passwords) {
    this.jdbc = jdbc;
    this.tx = tx;
    this.clock = clock;
    this.sender = sender;
    this.limiter = limiter;
    this.passwords = passwords;
    this.grants = new ResetGrantService(db, clock);
  }

  public void request(String employee, String ip) {
    if (!sender.available())
      throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Email recovery disabled");
    if (!limiter.allow(employee, ip)) return;
    tx.executeWithoutResult(
        status -> {
          var users =
              jdbc.queryForList(
                  "SELECT id FROM iam_user WHERE employee_no=? AND status='ACTIVE' AND password_gate='OPEN' FOR UPDATE",
                  UUID.class,
                  employee);
          if (users.isEmpty()) return;
          UUID user = users.get(0);
          var contacts =
              jdbc.queryForList(
                  "SELECT contact_version FROM recovery_contact WHERE user_id=? AND enabled AND verified_at<=?",
                  UUID.class,
                  user,
                  now());
          if (contacts.isEmpty()) return;
          jdbc.update(
              "INSERT INTO reset_mail_request(id,user_id,contact_version,state,next_attempt_at,created_at) VALUES (?,?,?,'PENDING',?,?)",
              UUID.randomUUID(),
              user,
              contacts.get(0),
              now(),
              now());
        });
  }

  public record Verified(
      @com.fasterxml.jackson.annotation.JsonProperty("reset_token") String resetToken,
      @com.fasterxml.jackson.annotation.JsonProperty("expires_at") java.time.Instant expiresAt) {
    @Override
    public String toString() {
      return "Verified[REDACTED]";
    }
  }

  public Verified verify(String emailToken, String sessionId) {
    requireToken(emailToken);
    String digest = RecoveryMailWorker.digest(emailToken);
    UUID verification =
        tx.execute(
            status -> {
              var users =
                  jdbc.queryForList(
                      "SELECT user_id FROM reset_email_challenge WHERE token_digest=?",
                      UUID.class,
                      digest);
              if (users.isEmpty()) throw invalid();
              UUID user = users.get(0);
              var epochs =
                  jdbc.queryForList(
                      "SELECT auth_epoch FROM iam_user WHERE id=? AND status='ACTIVE' AND password_gate='OPEN' FOR UPDATE",
                      Long.class,
                      user);
              if (epochs.isEmpty()) throw invalid();
              var valid =
                  jdbc.queryForList(
                      "SELECT c.user_id FROM reset_email_challenge c JOIN recovery_contact r ON r.user_id=c.user_id AND r.contact_version=c.contact_version WHERE c.token_digest=? AND c.consumed_at IS NULL AND c.expires_at>? AND c.auth_epoch=? AND r.enabled AND r.verified_at<=? FOR UPDATE OF c",
                      UUID.class,
                      digest,
                      now(),
                      epochs.get(0),
                      now());
              if (valid.isEmpty()) throw invalid();
              UUID id = UUID.randomUUID();
              jdbc.update(
                  "INSERT INTO identity_verification(id,user_id,auth_epoch,factor,verified_at,expires_at) VALUES (?,?,?,'EMAIL_LINK',?,?)",
                  id,
                  user,
                  epochs.get(0),
                  now(),
                  Timestamp.from(clock.instant().plusSeconds(300)));
              jdbc.update(
                  "UPDATE reset_email_challenge SET consumed_at=? WHERE token_digest=?",
                  now(),
                  digest);
              return id;
            });
    // Each boundary commits before returning a bearer credential. A crash can lose delivery of a
    // grant,
    // but cannot replay the email proof; the user requests a fresh link rather than guessing
    // completion.
    ResetGrantService.Grant grant = grants.issueFromVerification(verification);
    jdbc.update(
        "INSERT INTO reset_browser_grant(token_digest,session_digest,expires_at) VALUES (?,?,?)",
        RecoveryMailWorker.digest(grant.token()),
        DigestAuthorizationService.digest(sessionId),
        Timestamp.from(clock.instant().plusSeconds(3600)));
    return new Verified(grant.token(), grant.expiresAt());
  }

  public PasswordOperation confirm(
      String token, String sessionId, String key, char[] password, char[] confirmation) {
    try {
      requireToken(token);
      requireBinding(token, sessionId);
      return passwords.reset(token, key, password, confirmation);
    } finally {
      if (password != null) Arrays.fill(password, '\0');
      if (confirmation != null) Arrays.fill(confirmation, '\0');
    }
  }

  public PasswordOperation status(UUID operation, String sessionId) {
    var users =
        jdbc.queryForList(
            "SELECT g.user_id FROM reset_browser_grant b JOIN password_reset_grant g ON g.token_digest=b.token_digest WHERE b.session_digest=? AND b.expires_at>? AND g.operation_id=?",
            UUID.class,
            DigestAuthorizationService.digest(sessionId),
            now(),
            operation);
    if (users.isEmpty())
      throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Operation unavailable");
    return passwords.get(operation, users.get(0));
  }

  private void requireBinding(String token, String sessionId) {
    if (!Boolean.TRUE.equals(
        jdbc.queryForObject(
            "SELECT EXISTS(SELECT 1 FROM reset_browser_grant WHERE token_digest=? AND session_digest=? AND expires_at>?)",
            Boolean.class,
            RecoveryMailWorker.digest(token),
            DigestAuthorizationService.digest(sessionId),
            now()))) throw invalid();
  }

  public PasswordOperation requestStatus(UUID key, String sessionId) {
    var operations =
        jdbc.queryForList(
            """
                SELECT g.operation_id FROM reset_browser_grant b JOIN password_reset_grant g ON g.token_digest=b.token_digest
                JOIN password_operation p ON p.id=g.operation_id
                WHERE b.session_digest=? AND b.expires_at>? AND p.idempotency_key=? AND p.operation_type='RESET'
                """,
            UUID.class,
            DigestAuthorizationService.digest(sessionId),
            now(),
            key.toString());
    if (operations.isEmpty())
      throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Operation unavailable");
    return status(operations.get(0), sessionId);
  }

  private static void requireToken(String token) {
    if (token == null || !token.matches("[A-Za-z0-9_-]{43}")) throw invalid();
  }

  private static ResponseStatusException invalid() {
    return new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired recovery proof");
  }

  private Timestamp now() {
    return Timestamp.from(clock.instant());
  }
}
