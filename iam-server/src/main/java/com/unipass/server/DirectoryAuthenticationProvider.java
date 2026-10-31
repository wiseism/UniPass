package com.unipass.server;

import com.unipass.directory.*;
import java.time.Clock;
import java.util.Arrays;
import org.springframework.security.authentication.*;
import org.springframework.security.core.*;
import org.springframework.transaction.support.TransactionTemplate;

public final class DirectoryAuthenticationProvider implements AuthenticationProvider {
  private final DirectoryGateway directory;
  private final AccountState accounts;
  private final TransactionTemplate transactions;
  private final Clock clock;
  private final LoginAttemptLimiter limiter;

  public DirectoryAuthenticationProvider(
      DirectoryGateway directory,
      AccountState accounts,
      TransactionTemplate transactions,
      Clock clock,
      LoginAttemptLimiter limiter) {
    this.directory = directory;
    this.accounts = accounts;
    this.transactions = transactions;
    this.clock = clock;
    this.limiter = limiter;
  }

  @Override
  public Authentication authenticate(Authentication authentication) {
    char[] password =
        authentication.getCredentials() == null
            ? new char[0]
            : authentication.getCredentials().toString().toCharArray();
    String ip =
        authentication.getDetails()
                instanceof
                org.springframework.security.web.authentication.WebAuthenticationDetails details
            ? details.getRemoteAddress()
            : "unknown";
    try {
      limiter.check(authentication.getName(), ip);
      var user = accounts.byEmployee(authentication.getName());
      if (user == null
          || !user.active()
          || !user.type().equals(directory.type().name())
          || password.length == 0
          || !directory.verifyCredential(user.directoryId(), password)) {
        limiter.failed(authentication.getName(), ip);
        accounts.audit(user == null ? null : user.id(), "LOGIN_FAILED");
        throw new BadCredentialsException("Invalid credentials");
      }
      limiter.succeeded(authentication.getName(), ip);
      return transactions.execute(
          status -> {
            accounts.lockAndRequire(user.id(), user.epoch());
            IdentityPrincipal principal =
                new IdentityPrincipal(
                    user.id(), user.epoch(), clock.instant(), accounts.roles(user.id()));
            accounts.registerLogin(principal);
            accounts.audit(user.id(), "LOGIN_SUCCESS");
            return UsernamePasswordAuthenticationToken.authenticated(
                principal, null, principal.getAuthorities());
          });
    } catch (DirectoryFailure e) {
      throw new AuthenticationServiceException("Directory unavailable");
    } finally {
      Arrays.fill(password, '\0');
    }
  }

  @Override
  public boolean supports(Class<?> type) {
    return UsernamePasswordAuthenticationToken.class.isAssignableFrom(type);
  }
}
