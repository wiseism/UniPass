package com.unipass.server;

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
public final class AdminPasswordService {
  private final JdbcTemplate jdbc;
  private final TransactionTemplate tx;
  private final AccountState accounts;
  private final MfaService mfa;
  private final PasswordChangeService passwords;
  private final Clock clock;

  public AdminPasswordService(
      JdbcTemplate jdbc,
      TransactionTemplate tx,
      AccountState accounts,
      MfaService mfa,
      PasswordChangeService passwords,
      Clock clock) {
    this.jdbc = jdbc;
    this.tx = tx;
    this.accounts = accounts;
    this.mfa = mfa;
    this.passwords = passwords;
    this.clock = clock;
  }

  private AuthenticatedActor actor(IdentityPrincipal principal, String authority) {
    if (!principal.hasRecentPassword(clock.instant())
        || !accounts.roles(principal.getUserId()).contains("ROLE_ADMIN_" + authority)
        || !mfa.recent(principal))
      throw new ResponseStatusException(
          HttpStatus.FORBIDDEN, "Administrative authority and recent password/MFA required");
    return new AuthenticatedActor(
        principal.getUserId(),
        principal.getEpoch(),
        principal.getPasswordAuthenticatedAt(),
        Set.of(authority),
        principal.getMfaAt(),
        principal.getLoginId());
  }

  public PasswordOperation reset(
      IdentityPrincipal principal,
      UUID target,
      String key,
      String reason,
      char[] password,
      char[] confirmation) {
    try {
      var admin = actor(principal, "PASSWORD_RESET");
      UUID intent = intent(principal, target, "RESET", key, reason, null, null);
      PasswordOperation result = passwords.adminReset(admin, target, key, password, confirmation);
      complete(intent, result.id());
      return result;
    } finally {
      if (password != null) Arrays.fill(password, '\0');
      if (confirmation != null) Arrays.fill(confirmation, '\0');
    }
  }

  public PasswordOperation recover(
      IdentityPrincipal principal,
      UUID operation,
      String key,
      boolean committed,
      String reason,
      String evidence) {
    var admin = actor(principal, "PASSWORD_RECOVERY");
    UUID target = target(operation);
    if (evidence == null || !evidence.matches("[a-zA-Z0-9:/_.-]{8,500}"))
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Evidence required");
    UUID intent =
        intent(
            principal,
            target,
            committed ? "RECOVER_COMMITTED" : "RECOVER_REJECTED",
            key,
            reason,
            evidence,
            operation);
    PasswordOperation result = passwords.recover(admin, operation, committed, evidence);
    complete(intent, result.id());
    return result;
  }

  public PasswordOperation status(IdentityPrincipal principal, UUID operation) {
    if (!principal.hasRecentPassword(clock.instant())
        || !mfa.recent(principal)
        || accounts.roles(principal.getUserId()).stream()
            .noneMatch(
                role ->
                    Set.of("ROLE_ADMIN_PASSWORD_RESET", "ROLE_ADMIN_PASSWORD_RECOVERY")
                        .contains(role)))
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Administrative authority required");
    return passwords.get(operation, target(operation));
  }

  private UUID target(UUID operation) {
    var rows =
        jdbc.queryForList(
            "SELECT user_id FROM password_operation WHERE id=?", UUID.class, operation);
    if (rows.isEmpty())
      throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Operation unavailable");
    return rows.get(0);
  }

  private UUID intent(
      IdentityPrincipal principal,
      UUID target,
      String action,
      String key,
      String reason,
      String evidence,
      UUID requestedOperation) {
    if (key == null
        || !key.matches("[a-zA-Z0-9_-]{16,128}")
        || reason == null
        || reason.isBlank()
        || reason.length() > 500
        || reason.codePoints().anyMatch(Character::isISOControl))
      throw new ResponseStatusException(
          HttpStatus.BAD_REQUEST, "Reason and idempotency key required");
    return tx.execute(
        status -> {
          accounts.lockAndRequire(principal);
          if (!Boolean.TRUE.equals(
              jdbc.queryForObject(
                  "SELECT EXISTS(SELECT 1 FROM iam_user WHERE id=?)", Boolean.class, target)))
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Identity unavailable");
          UUID id = UUID.randomUUID();
          jdbc.update(
              "INSERT INTO admin_password_action(id,actor_id,target_id,action,idempotency_key,reason,evidence_ref,requested_operation_id,created_at) VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING",
              id,
              principal.getUserId(),
              target,
              action,
              key,
              reason,
              evidence,
              requestedOperation,
              Timestamp.from(clock.instant()));
          return jdbc.query(
              "SELECT id,reason,evidence_ref,requested_operation_id FROM admin_password_action WHERE actor_id=? AND target_id=? AND action=? AND idempotency_key=?",
              r -> {
                if (!r.next()
                    || !reason.equals(r.getString(2))
                    || !Objects.equals(evidence, r.getString(3))
                    || !Objects.equals(requestedOperation, r.getObject(4, UUID.class)))
                  throw new ResponseStatusException(
                      HttpStatus.CONFLICT, "Idempotency context changed");
                return r.getObject(1, UUID.class);
              },
              principal.getUserId(),
              target,
              action,
              key);
        });
  }

  private void complete(UUID intent, UUID operation) {
    jdbc.update("UPDATE admin_password_action SET operation_id=? WHERE id=?", operation, intent);
  }
}
