package com.unipass.server;

import java.sql.Timestamp;
import java.time.Clock;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionTemplate;

/** Offline trusted-roster import, never called with an address asserted by an anonymous user. */
public final class RecoveryContactProvisioner {
  private final JdbcTemplate jdbc;
  private final TransactionTemplate tx;
  private final Clock clock;

  public RecoveryContactProvisioner(JdbcTemplate jdbc, TransactionTemplate tx, Clock clock) {
    this.jdbc = jdbc;
    this.tx = tx;
    this.clock = clock;
  }

  public void provision(UUID user, String email, String evidence) {
    RecoveryMailConfiguration.validatedAddress(email);
    if (evidence == null || !evidence.matches("[a-zA-Z0-9:/_.-]{8,500}"))
      throw new IllegalArgumentException("Verified contact evidence required");
    tx.executeWithoutResult(
        status -> {
          if (jdbc.update(
                  "UPDATE iam_user SET auth_epoch=auth_epoch+1 WHERE id=? AND status='ACTIVE' AND password_gate='OPEN'",
                  user)
              != 1) throw new IllegalArgumentException("Identity unavailable");
          jdbc.update(
              "INSERT INTO recovery_contact(user_id,email,contact_version,verified_at,evidence_ref) VALUES (?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET email=excluded.email,contact_version=excluded.contact_version,verified_at=excluded.verified_at,evidence_ref=excluded.evidence_ref,enabled=true",
              user,
              email,
              UUID.randomUUID(),
              Timestamp.from(clock.instant()),
              evidence);
          jdbc.update(
              "UPDATE reset_email_challenge SET consumed_at=? WHERE user_id=? AND consumed_at IS NULL",
              Timestamp.from(clock.instant()),
              user);
          jdbc.update(
              "INSERT INTO auth_audit(id,user_id,action,trace_id) VALUES (?,?,'RECOVERY_CONTACT_PROVISIONED',?)",
              UUID.randomUUID(),
              user,
              UUID.randomUUID());
        });
  }
}
