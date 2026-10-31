package com.unipass.server;

import com.unipass.directory.*;
import java.time.Clock;
import java.util.*;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

/**
 * Password proof upgrades the current identity, never switches accounts or renews login lifetime.
 */
@Service
public final class PasswordReauthentication {
  private final JdbcTemplate jdbc;
  private final DirectoryGateway directory;
  private final AccountState accounts;
  private final TransactionTemplate tx;
  private final Clock clock;
  private final LoginAttemptLimiter limiter;

  public PasswordReauthentication(
      JdbcTemplate jdbc,
      DirectoryGateway directory,
      AccountState accounts,
      TransactionTemplate tx,
      Clock clock,
      LoginAttemptLimiter limiter) {
    this.jdbc = jdbc;
    this.directory = directory;
    this.accounts = accounts;
    this.tx = tx;
    this.clock = clock;
    this.limiter = limiter;
  }

  public IdentityPrincipal verify(IdentityPrincipal principal, char[] password, String ip) {
    try {
      if (password == null || password.length == 0 || password.length > 1024)
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password required");
      if (!accounts.allowed(principal))
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Session unavailable");
      var rows =
          jdbc.queryForList(
              "SELECT employee_no,directory_id,directory_type FROM iam_user WHERE id=?",
              principal.getUserId());
      if (rows.size() != 1 || !directory.type().name().equals(rows.get(0).get("directory_type")))
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Identity unavailable");
      var row = rows.get(0);
      String employee = (String) row.get("employee_no");
      limiter.check(employee, ip);
      if (!directory.verifyCredential(row.get("directory_id").toString(), password)) {
        limiter.failed(employee, ip);
        accounts.audit(principal.getUserId(), "PASSWORD_REAUTH_FAILED");
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credential");
      }
      limiter.succeeded(employee, ip);
      return tx.execute(
          ignored -> {
            accounts.lockAndRequire(principal);
            accounts.audit(principal.getUserId(), "PASSWORD_REAUTH_SUCCESS");
            return new IdentityPrincipal(
                principal.getUserId(),
                principal.getEpoch(),
                principal.getAuthenticatedAt(),
                accounts.roles(principal.getUserId()),
                principal.getMfaAt(),
                principal.getAuthenticationMethod(),
                clock.instant(),
                principal.getLoginId());
          });
    } catch (LockedException limited) {
      throw new ResponseStatusException(
          HttpStatus.TOO_MANY_REQUESTS, "Authentication rate limited");
    } catch (BadCredentialsException stale) {
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Session changed");
    } catch (DirectoryFailure
        | AuthenticationServiceException
        | org.springframework.dao.DataAccessException unavailable) {
      throw new ResponseStatusException(
          HttpStatus.SERVICE_UNAVAILABLE, "Authentication unavailable");
    } finally {
      if (password != null) Arrays.fill(password, '\0');
    }
  }
}
