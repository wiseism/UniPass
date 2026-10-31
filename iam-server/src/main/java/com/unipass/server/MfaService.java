package com.unipass.server;

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.*;
import java.util.*;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base32;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

/**
 * Persistent attempt limits and step consumption apply across challenges, sessions and instances.
 */
@Service
public final class MfaService {
  private final JdbcTemplate jdbc;
  private final TransactionTemplate tx;
  private final AccountState accounts;
  private final Clock clock;
  private final MfaKeyService cipher;
  private final TimeBasedOneTimePasswordGenerator totp = new TimeBasedOneTimePasswordGenerator();

  public MfaService(
      JdbcTemplate jdbc,
      TransactionTemplate tx,
      AccountState accounts,
      Clock clock,
      MfaKeyService cipher) {
    this.jdbc = jdbc;
    this.tx = tx;
    this.accounts = accounts;
    this.clock = clock;
    this.cipher = cipher;
  }

  public record Enrollment(String secret, String otpauthUri, Instant expiresAt) {
    @Override
    public String toString() {
      return "Enrollment[REDACTED]";
    }
  }

  public boolean enrolled(UUID user) {
    return Boolean.TRUE.equals(
        jdbc.queryForObject(
            "SELECT EXISTS(SELECT 1 FROM mfa_totp WHERE user_id=? AND enabled)",
            Boolean.class,
            user));
  }

  public boolean required(IdentityPrincipal principal) {
    return recoveryRequired(principal.getUserId())
        || enrolled(principal.getUserId())
        || principal.getRoles().stream().anyMatch(role -> role.startsWith("ROLE_ADMIN"));
  }

  public boolean recoveryRequired(UUID user) {
    return Boolean.TRUE.equals(
        jdbc.queryForObject(
            "SELECT mfa_recovery_required FROM iam_user WHERE id=?", Boolean.class, user));
  }

  public boolean recent(IdentityPrincipal principal) {
    return principal.getMfaAt() != null
        && !principal.getMfaAt().isAfter(clock.instant())
        && principal.getMfaAt().plusSeconds(300).isAfter(clock.instant());
  }

  public void requireStrong(IdentityPrincipal principal) {
    if (required(principal) && !recent(principal))
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, "MFA required");
  }

  public Enrollment enroll(IdentityPrincipal principal) {
    if (!principal.hasRecentPassword(clock.instant()))
      throw new ResponseStatusException(
          HttpStatus.FORBIDDEN, "Recent password authentication required");
    return tx.execute(
        status -> {
          accounts.lockAndRequire(principal);
          if (recoveryRequired(principal.getUserId()))
            throw new ResponseStatusException(
                HttpStatus.FORBIDDEN, "Controlled factor recovery required");
          if (enrolled(principal.getUserId()))
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Factor already enrolled");
          byte[] secret = new byte[20];
          new SecureRandom().nextBytes(secret);
          try {
            Instant expires = clock.instant().plusSeconds(300);
            jdbc.update(
                "INSERT INTO mfa_totp(user_id,secret_cipher,pending_expires_at) VALUES (?,?,?) ON CONFLICT(user_id) DO UPDATE SET secret_cipher=excluded.secret_cipher,pending_expires_at=excluded.pending_expires_at,last_used_step=-1",
                principal.getUserId(),
                cipher.encrypt(principal.getUserId(), secret),
                Timestamp.from(expires));
            accounts.audit(principal.getUserId(), "MFA_ENROLL_STARTED");
            return enrollment(principal.getUserId(), secret, expires);
          } finally {
            Arrays.fill(secret, (byte) 0);
          }
        });
  }

  public void confirmEnrollment(IdentityPrincipal principal, String code) {
    boolean valid =
        Boolean.TRUE.equals(
            tx.execute(
                status -> {
                  accounts.lockAndRequire(principal);
                  var factor = factor(principal.getUserId());
                  Instant now = clock.instant();
                  if (recoveryRequired(principal.getUserId())
                      || factor == null
                      || factor.enabled
                      || factor.pendingExpires == null
                      || !factor.pendingExpires.isAfter(now)
                      || !principal.hasRecentPassword(now)) return false;
                  long step = verify(principal.getUserId(), factor, code);
                  if (step < 0) return false;
                  jdbc.update(
                      "UPDATE mfa_totp SET enabled=true,pending_expires_at=NULL,last_used_step=?,failed_attempts=0,locked_until=NULL WHERE user_id=?",
                      step,
                      principal.getUserId());
                  jdbc.update(
                      "UPDATE iam_user SET auth_epoch=auth_epoch+1 WHERE id=?",
                      principal.getUserId());
                  accounts.audit(principal.getUserId(), "MFA_ENROLLED");
                  return true;
                }));
    if (!valid)
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired verification");
  }

  public UUID challenge(IdentityPrincipal principal, String sessionId, UUID context) {
    return tx.execute(
        status -> {
          accounts.lockAndRequire(principal);
          if (!enrolled(principal.getUserId()))
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Factor enrollment required");
          // A new challenge supersedes outstanding challenges for this session and user.
          String session = DigestAuthorizationService.digest(sessionId);
          jdbc.update(
              "UPDATE mfa_challenge SET consumed_at=? WHERE user_id=? AND session_digest=? AND consumed_at IS NULL",
              Timestamp.from(clock.instant()),
              principal.getUserId(),
              session);
          UUID id = UUID.randomUUID();
          jdbc.update(
              "INSERT INTO mfa_challenge(id,user_id,auth_epoch,session_digest,context_id,expires_at) VALUES (?,?,?,?,?,?)",
              id,
              principal.getUserId(),
              principal.getEpoch(),
              session,
              context,
              Timestamp.from(clock.instant().plusSeconds(300)));
          return id;
        });
  }

  public Instant verifyChallenge(
      IdentityPrincipal principal, String sessionId, UUID context, UUID challenge, String code) {
    boolean valid =
        Boolean.TRUE.equals(
            tx.execute(
                status -> {
                  accounts.lockAndRequire(principal);
                  Factor factor = factor(principal.getUserId());
                  if (factor == null || !factor.enabled) return false;
                  var rows =
                      jdbc.query(
                          "SELECT expires_at,consumed_at FROM mfa_challenge WHERE id=? AND user_id=? AND auth_epoch=? AND session_digest=? AND context_id=? FOR UPDATE",
                          (r, n) ->
                              r.getTimestamp("consumed_at") == null
                                  && r.getTimestamp("expires_at")
                                      .toInstant()
                                      .isAfter(clock.instant()),
                          challenge,
                          principal.getUserId(),
                          principal.getEpoch(),
                          DigestAuthorizationService.digest(sessionId),
                          context);
                  if (rows.isEmpty() || !rows.get(0)) return false;
                  long step = verify(principal.getUserId(), factor, code);
                  if (step < 0) return false;
                  jdbc.update(
                      "UPDATE mfa_totp SET last_used_step=?,failed_attempts=0,locked_until=NULL WHERE user_id=?",
                      step,
                      principal.getUserId());
                  jdbc.update(
                      "UPDATE mfa_challenge SET consumed_at=? WHERE id=?",
                      Timestamp.from(clock.instant()),
                      challenge);
                  accounts.audit(principal.getUserId(), "MFA_VERIFIED");
                  return true;
                }));
    if (!valid)
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired verification");
    return clock.instant();
  }

  private record Factor(
      byte[] encrypted,
      boolean enabled,
      Instant pendingExpires,
      long lastStep,
      int failures,
      Instant lockedUntil) {}

  private Factor factor(UUID user) {
    var rows =
        jdbc.query(
            "SELECT * FROM mfa_totp WHERE user_id=? FOR UPDATE",
            (r, n) ->
                new Factor(
                    r.getBytes("secret_cipher"),
                    r.getBoolean("enabled"),
                    r.getTimestamp("pending_expires_at") == null
                        ? null
                        : r.getTimestamp("pending_expires_at").toInstant(),
                    r.getLong("last_used_step"),
                    r.getInt("failed_attempts"),
                    r.getTimestamp("locked_until") == null
                        ? null
                        : r.getTimestamp("locked_until").toInstant()),
            user);
    return rows.isEmpty() ? null : rows.get(0);
  }

  private long verify(UUID user, Factor factor, String code) {
    Instant now = clock.instant();
    if (factor.lockedUntil != null && factor.lockedUntil.isAfter(now)) return -1;
    long matched = matchingStep(user, factor.encrypted, factor.lastStep, code);
    if (matched < 0) {
      int failures =
          factor.lockedUntil != null && !factor.lockedUntil.isAfter(now) ? 1 : factor.failures + 1;
      jdbc.update(
          "UPDATE mfa_totp SET failed_attempts=?,locked_until=? WHERE user_id=?",
          failures,
          failures >= 5 ? Timestamp.from(now.plusSeconds(1800)) : null,
          user);
      accounts.audit(user, "MFA_FAILED");
    }
    return matched;
  }

  byte[] encrypt(UUID user, byte[] secret) {
    return cipher.encrypt(user, secret);
  }

  byte[] reencrypt(UUID user, byte[] encrypted) {
    return cipher.reencrypt(user, encrypted);
  }

  Enrollment enrollment(UUID user, byte[] secret, Instant expires) {
    String encoded = new Base32().encodeAsString(secret).replace("=", "");
    String label = URLEncoder.encode("UniPass:" + user, StandardCharsets.UTF_8);
    return new Enrollment(
        encoded,
        "otpauth://totp/"
            + label
            + "?secret="
            + encoded
            + "&issuer=UniPass&algorithm=SHA1&digits=6&period=30",
        expires);
  }

  long matchingStep(UUID user, byte[] encrypted, long lastStep, String code) {
    Instant now = clock.instant();
    byte[] raw = cipher.decrypt(user, encrypted);
    long matched = -1;
    try {
      if (code != null && code.matches("[0-9]{6}")) {
        long current = now.getEpochSecond() / 30;
        for (long step = current - 1; step <= current + 1; step++)
          if (totp.validateOneTimePassword(
                  new SecretKeySpec(raw, totp.getAlgorithm()),
                  Instant.ofEpochSecond(step * 30),
                  code)
              && step > lastStep) matched = step;
      }
    } catch (java.security.InvalidKeyException e) {
      throw new IllegalStateException("Factor key unavailable");
    } finally {
      Arrays.fill(raw, (byte) 0);
    }
    return matched;
  }
}
