package com.unipass.server;

import java.time.*;
import java.util.*;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

/** A login survives servlet SID rotation. PostgreSQL is the revocation authority. */
@Service
public final class LoginSessions {
  private final JdbcTemplate jdbc;
  private final AccountState accounts;
  private final TransactionTemplate tx;
  private final MfaService mfa;
  private final Clock clock;

  public LoginSessions(
      JdbcTemplate jdbc,
      AccountState accounts,
      TransactionTemplate tx,
      MfaService mfa,
      Clock clock) {
    this.jdbc = jdbc;
    this.accounts = accounts;
    this.tx = tx;
    this.mfa = mfa;
    this.clock = clock;
  }

  public record Entry(
      UUID id,
      Instant authenticatedAt,
      Instant lastAccessAt,
      String method,
      String device,
      boolean current) {}

  public record Page(List<Entry> entries, UUID nextCursor) {}

  public Page list(IdentityPrincipal principal, UUID before) {
    return tx.execute(
        ignored -> {
          accounts.lockAndRequire(principal);
          if (before != null
              && !Boolean.TRUE.equals(
                  jdbc.queryForObject(
                      "SELECT EXISTS(SELECT 1 FROM iam_login WHERE id=? AND user_id=?)",
                      Boolean.class,
                      before,
                      principal.getUserId()))) throw missing();
          var rows =
              jdbc.query(
                  """
                    SELECT * FROM iam_login WHERE user_id=? AND auth_epoch=? AND revoked_at IS NULL
                    AND (?::uuid IS NULL OR (authenticated_at,id)<(SELECT authenticated_at,id FROM iam_login WHERE id=?))
                    ORDER BY authenticated_at DESC,id DESC LIMIT 51
                    """,
                  (r, n) ->
                      new Entry(
                          r.getObject("id", UUID.class),
                          r.getTimestamp("authenticated_at").toInstant(),
                          r.getTimestamp("last_access_at").toInstant(),
                          r.getString("authentication_method"),
                          Objects.requireNonNullElse(r.getString("device"), "Unknown"),
                          principal.getLoginId().equals(r.getObject("id", UUID.class))),
                  principal.getUserId(),
                  principal.getEpoch(),
                  before,
                  before);
          boolean more = rows.size() > 50;
          var page = List.copyOf(rows.subList(0, Math.min(50, rows.size())));
          return new Page(page, more ? page.get(page.size() - 1).id() : null);
        });
  }

  public void revoke(IdentityPrincipal principal, UUID login) {
    tx.executeWithoutResult(
        ignored -> {
          accounts.lockAndRequire(principal);
          mfa.requireStrong(principal);
          if (!principal.hasRecentPassword(clock.instant()))
            throw new ResponseStatusException(
                HttpStatus.FORBIDDEN, "Recent password authentication required");
          // Same owner lock as grant issuance: either the grant commits first and is
          // revoked here, or its later save observes this revoked login and fails.
          if (!Boolean.TRUE.equals(
              jdbc.queryForObject(
                  "SELECT EXISTS(SELECT 1 FROM iam_login WHERE id=? AND user_id=? AND auth_epoch=?)",
                  Boolean.class,
                  login,
                  principal.getUserId(),
                  principal.getEpoch()))) throw missing();
          int changed =
              jdbc.update(
                  "UPDATE iam_login SET revoked_at=clock_timestamp() WHERE id=? AND revoked_at IS NULL",
                  login);
          jdbc.update(
              "UPDATE oauth2_authorization SET revoked=true WHERE revoked=false AND id IN (SELECT authorization_id FROM iam_login_grant WHERE login_id=?)",
              login);
          if (changed > 0) accounts.audit(principal.getUserId(), "LOGIN_REVOKED", login);
        });
  }

  void seen(IdentityPrincipal principal, String userAgent) {
    jdbc.update(
        """
                UPDATE iam_login SET last_access_at=clock_timestamp(),device=COALESCE(device,?)
                WHERE id=? AND user_id=? AND revoked_at IS NULL AND (device IS NULL OR last_access_at<clock_timestamp()-interval '1 minute')
                """,
        device(userAgent),
        principal.getLoginId(),
        principal.getUserId());
  }

  static String device(String userAgent) {
    if (userAgent == null || userAgent.length() > 1024) return "Unknown";
    String browser =
        userAgent.contains("Edg/")
            ? "Edge"
            : userAgent.contains("Firefox/")
                ? "Firefox"
                : userAgent.contains("Chrome/")
                    ? "Chrome"
                    : userAgent.contains("Safari/") ? "Safari" : "Other browser";
    String os =
        userAgent.contains("Android")
            ? "Android"
            : userAgent.contains("iPhone") || userAgent.contains("iPad")
                ? "iOS"
                : userAgent.contains("Windows")
                    ? "Windows"
                    : userAgent.contains("Macintosh")
                        ? "macOS"
                        : userAgent.contains("Linux") ? "Linux" : "Unknown OS";
    return browser + " / " + os;
  }

  private static ResponseStatusException missing() {
    return new ResponseStatusException(HttpStatus.NOT_FOUND, "Login unavailable");
  }
}
