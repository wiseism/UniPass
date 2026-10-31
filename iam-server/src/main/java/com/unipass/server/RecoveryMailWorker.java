package com.unipass.server;

import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.*;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Durable non-secret mail work. Each attempt creates a new digest and holds no DB lock during SMTP.
 */
@Service
public final class RecoveryMailWorker {
  private final JdbcTemplate jdbc;
  private final TransactionTemplate tx;
  private final Clock clock;
  private final RecoveryEmailSender sender;
  private final String issuer;

  public RecoveryMailWorker(
      JdbcTemplate jdbc,
      TransactionTemplate tx,
      Clock clock,
      RecoveryEmailSender sender,
      AuthorizationServerSettings settings) {
    this.jdbc = jdbc;
    this.tx = tx;
    this.clock = clock;
    this.sender = sender;
    this.issuer = settings.getIssuer();
  }

  private record Claim(UUID id, UUID user, UUID contactVersion, UUID lease, int attempts) {}

  private record Delivery(String email, String link) {
    @Override
    public String toString() {
      return "Delivery[REDACTED]";
    }
  }

  public boolean runOnce() {
    if (!sender.available()) return false;
    Claim claim =
        tx.execute(
            status -> {
              var rows =
                  jdbc.query(
                      "SELECT * FROM reset_mail_request WHERE (state='PENDING' AND next_attempt_at<=?) OR (state='RUNNING' AND lease_until<?) ORDER BY next_attempt_at LIMIT 1 FOR UPDATE SKIP LOCKED",
                      (r, n) ->
                          new Claim(
                              r.getObject("id", UUID.class),
                              r.getObject("user_id", UUID.class),
                              r.getObject("contact_version", UUID.class),
                              UUID.randomUUID(),
                              r.getInt("attempts") + 1),
                      now(),
                      now());
              if (rows.isEmpty()) return null;
              Claim picked = rows.get(0);
              if (picked.attempts > 5) {
                jdbc.update(
                    "UPDATE reset_mail_request SET state='DEAD',last_error='ATTEMPTS_EXHAUSTED' WHERE id=?",
                    picked.id);
                return null;
              }
              jdbc.update(
                  "UPDATE reset_mail_request SET state='RUNNING',lease_token=?,lease_until=?,attempts=? WHERE id=?",
                  picked.lease,
                  Timestamp.from(clock.instant().plusSeconds(30)),
                  picked.attempts,
                  picked.id);
              return picked;
            });
    if (claim == null) return false;
    Delivery delivery =
        tx.execute(
            status -> {
              var users =
                  jdbc.query(
                      "SELECT auth_epoch,status,password_gate FROM iam_user WHERE id=? FOR UPDATE",
                      (r, n) ->
                          new User(
                              r.getLong(1),
                              r.getString(2).equals("ACTIVE") && r.getString(3).equals("OPEN")),
                      claim.user);
              var contacts =
                  jdbc.queryForList(
                      "SELECT email FROM recovery_contact WHERE user_id=? AND contact_version=? AND enabled AND verified_at<=?",
                      String.class,
                      claim.user,
                      claim.contactVersion,
                      now());
              if (jdbc.update(
                      "UPDATE reset_mail_request SET lease_until=? WHERE id=? AND state='RUNNING' AND lease_token=? AND lease_until>?",
                      Timestamp.from(clock.instant().plusSeconds(30)),
                      claim.id,
                      claim.lease,
                      now())
                  != 1) return null;
              if (users.isEmpty() || !users.get(0).active || contacts.isEmpty()) {
                jdbc.update(
                    "UPDATE reset_mail_request SET state='BLOCKED',last_error='CONTACT_OR_ACCOUNT_UNAVAILABLE' WHERE id=? AND lease_token=?",
                    claim.id,
                    claim.lease);
                return null;
              }
              jdbc.update(
                  "UPDATE reset_email_challenge SET consumed_at=? WHERE request_id=? AND consumed_at IS NULL",
                  now(),
                  claim.id);
              byte[] bytes = new byte[32];
              new SecureRandom().nextBytes(bytes);
              String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
              Arrays.fill(bytes, (byte) 0);
              jdbc.update(
                  "INSERT INTO reset_email_challenge(token_digest,user_id,request_id,auth_epoch,contact_version,expires_at) VALUES (?,?,?,?,?,?)",
                  digest(token),
                  claim.user,
                  claim.id,
                  users.get(0).epoch,
                  claim.contactVersion,
                  Timestamp.from(clock.instant().plusSeconds(600)));
              return new Delivery(contacts.get(0), issuer + "/reset#token=" + token);
            });
    if (delivery == null) return true;
    try {
      sender.send(delivery.email, delivery.link);
      jdbc.update(
          "UPDATE reset_mail_request SET state='SENT',last_error=NULL,lease_until=NULL WHERE id=? AND lease_token=? AND state='RUNNING' AND lease_until>?",
          claim.id,
          claim.lease,
          now());
    } catch (RuntimeException e) {
      long delay = Math.min(3600, 60L << Math.min(claim.attempts - 1, 6));
      delay += new SecureRandom().nextInt((int) (delay / 10) + 1);
      jdbc.update(
          "UPDATE reset_mail_request SET state=?,last_error='SMTP_DELIVERY_UNCERTAIN',next_attempt_at=?,lease_until=NULL WHERE id=? AND lease_token=? AND state='RUNNING' AND lease_until>?",
          claim.attempts >= 5 ? "DEAD" : "PENDING",
          Timestamp.from(clock.instant().plusSeconds(delay)),
          claim.id,
          claim.lease,
          now());
    }
    return true;
  }

  private record User(long epoch, boolean active) {}

  private Timestamp now() {
    return Timestamp.from(clock.instant());
  }

  static String digest(String raw) {
    return DigestAuthorizationService.digest(raw).substring("sha256:".length());
  }
}
