package com.unipass.server;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcLogoutAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/** Authenticated logout is global: fences every session and token for this identity. */
@Service
public final class LogoutService {
  private final JdbcTemplate jdbc;
  private final TransactionTemplate tx;
  private final AccountState accounts;

  public LogoutService(JdbcTemplate jdbc, TransactionTemplate tx, AccountState accounts) {
    this.jdbc = jdbc;
    this.tx = tx;
    this.accounts = accounts;
  }

  public void browser(Authentication authentication) {
    if (authentication == null
        || !(authentication.getPrincipal() instanceof IdentityPrincipal principal)) return;
    tx.executeWithoutResult(
        status -> {
          accounts.lockAndRequire(principal);
          jdbc.update(
              "UPDATE iam_user SET auth_epoch=auth_epoch+1 WHERE id=?", principal.getUserId());
          jdbc.update(
              "UPDATE oauth2_authorization SET revoked=true WHERE principal_name=?",
              principal.getUserId().toString());
          accounts.audit(principal.getUserId(), "GLOBAL_LOGOUT");
        });
  }

  public void oidc(Authentication authentication) {
    var logout = (OidcLogoutAuthenticationToken) authentication;
    if (logout.isPrincipalAuthenticated()) browser((Authentication) logout.getPrincipal());
    else {
      // The framework already validated this ID-token hint and registered callback.
      String family = logout.getIdToken().getClaim("unipass_family");
      tx.executeWithoutResult(
          status ->
              jdbc.update(
                  "UPDATE oauth2_authorization SET revoked=true WHERE id=? AND principal_name=?",
                  family,
                  logout.getIdToken().getSubject()));
    }
  }
}
