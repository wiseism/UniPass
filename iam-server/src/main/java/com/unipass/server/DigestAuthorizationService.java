package com.unipass.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Principal;
import java.sql.Timestamp;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.transaction.support.*;

/**
 * Framework token storage with digest-only bearer values and durable refresh-family replay
 * detection.
 */
public final class DigestAuthorizationService implements OAuth2AuthorizationService {
  private final JdbcOAuth2AuthorizationService delegate;
  private final JdbcTemplate jdbc;
  private final AccountState accounts;
  private final TransactionTemplate tx;
  private final RegisteredClientRepository clients;

  public DigestAuthorizationService(
      JdbcTemplate jdbc,
      RegisteredClientRepository clients,
      AccountState accounts,
      TransactionTemplate tx) {
    this.jdbc = jdbc;
    this.accounts = accounts;
    this.tx = tx;
    this.clients = clients;
    delegate = new JdbcOAuth2AuthorizationService(jdbc, clients);
    ObjectMapper mapper = new ObjectMapper();
    mapper.registerModules(SecurityJackson2Modules.getModules(getClass().getClassLoader()));
    mapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
    mapper.registerModule(new JavaTimeModule());
    mapper.addMixIn(List.of().getClass(), TrustedCollection.class);
    mapper.addMixIn(List.of("one").getClass(), TrustedCollection.class);
    mapper.addMixIn(Long.class, TrustedCollection.class);
    var rowMapper = new JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper(clients);
    rowMapper.setObjectMapper(mapper);
    delegate.setAuthorizationRowMapper(rowMapper);
    var parameters = new JdbcOAuth2AuthorizationService.OAuth2AuthorizationParametersMapper();
    parameters.setObjectMapper(mapper);
    delegate.setAuthorizationParametersMapper(parameters);
  }

  @com.fasterxml.jackson.annotation.JsonTypeInfo(
      use = com.fasterxml.jackson.annotation.JsonTypeInfo.Id.CLASS)
  private abstract static class TrustedCollection {}

  @Override
  public void save(OAuth2Authorization authorization) {
    tx.executeWithoutResult(
        status -> {
          IdentityPrincipal principal = principal(authorization);
          try {
            accounts.lockAndRequire(principal);
          } catch (org.springframework.security.authentication.BadCredentialsException e) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
          }
          boolean revoked =
              Boolean.TRUE.equals(
                  jdbc.query(
                      "SELECT revoked FROM oauth2_authorization WHERE id=? FOR UPDATE",
                      r -> r.next() && r.getBoolean(1),
                      authorization.getId()));
          if (revoked) throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
          var login =
              jdbc.queryForList(
                  "SELECT login_id FROM iam_login_grant WHERE authorization_id=?",
                  UUID.class,
                  authorization.getId());
          if (!login.isEmpty() && !login.get(0).equals(principal.getLoginId()))
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
          OAuth2Authorization.Builder hashed = OAuth2Authorization.from(authorization);
          for (Class<? extends OAuth2Token> type : tokenClasses()) {
            var token = authorization.getToken(type);
            if (token != null)
              hashed.token(
                  copy(token.getToken(), storedDigest(token.getToken().getTokenValue())),
                  meta -> meta.putAll(token.getMetadata()));
          }
          delegate.save(hashed.build());
          jdbc.update(
              "INSERT INTO iam_login_grant(authorization_id,login_id) VALUES (?,?) ON CONFLICT(authorization_id) DO NOTHING",
              authorization.getId(),
              principal.getLoginId());
          if (authorization.getToken(OidcIdToken.class) != null) {
            var client = clients.findById(authorization.getRegisteredClientId());
            String target =
                client == null
                    ? null
                    : client.getClientSettings().getSetting("unipass.backchannel_logout_uri");
            String sid =
                authorization.getToken(OidcIdToken.class).getToken().getClaimAsString("sid");
            if (target != null && !target.isBlank() && sid != null && !sid.isBlank())
              jdbc.update(
                  "INSERT INTO oidc_rp_session(authorization_id,user_id,client_id,target_uri,sid,login_authenticated_at) VALUES (?,?,?,?,?,?) ON CONFLICT(authorization_id) DO NOTHING",
                  authorization.getId(),
                  principal.getUserId(),
                  client.getClientId(),
                  target,
                  sid,
                  Timestamp.from(principal.getAuthenticatedAt()));
          }
          for (Class<? extends OAuth2Token> type : tokenClasses()) {
            var token = authorization.getToken(type);
            if (token == null) continue;
            String digest = storedDigest(token.getToken().getTokenValue());
            String name = type.getSimpleName();
            jdbc.update(
                "UPDATE oauth_token_index SET replaced_at=COALESCE(replaced_at,now()) WHERE authorization_id=? AND token_type=? AND digest<>?",
                authorization.getId(),
                name,
                digest);
            jdbc.update(
                "INSERT INTO oauth_token_index(digest,authorization_id,token_type,expires_at) VALUES (?,?,?,?) ON CONFLICT DO NOTHING",
                digest,
                authorization.getId(),
                name,
                token.getToken().getExpiresAt() == null
                    ? null
                    : Timestamp.from(token.getToken().getExpiresAt()));
          }
          if (authorization.getRefreshToken() != null
                  && authorization.getRefreshToken().isInvalidated()
              || authorization.getAccessToken() != null
                  && authorization.getAccessToken().isInvalidated())
            jdbc.update(
                "UPDATE oauth2_authorization SET revoked=true WHERE id=?", authorization.getId());
        });
  }

  @Override
  public void remove(OAuth2Authorization authorization) {
    jdbc.update("UPDATE oauth2_authorization SET revoked=true WHERE id=?", authorization.getId());
  }

  @Override
  public OAuth2Authorization findById(String id) {
    return delegate.findById(id);
  }

  @Override
  public OAuth2Authorization findByToken(String raw, OAuth2TokenType type) {
    if (raw == null || raw.isBlank()) return null;
    // OAuth state is not a bearer credential and uses the framework's state query.
    if (type != null && "state".equals(type.getValue())) return delegate.findByToken(raw, type);
    String digest = digest(raw);
    List<String> ids =
        jdbc.queryForList(
            "SELECT authorization_id FROM oauth_token_index WHERE digest=?", String.class, digest);
    if (ids.isEmpty()) return null;
    String indexedType =
        jdbc.queryForObject(
            "SELECT token_type FROM oauth_token_index WHERE digest=?", String.class, digest);
    if (type != null && !matchesType(type.getValue(), indexedType)) return null;
    String id = ids.get(0);
    OAuth2Authorization authorization = delegate.findById(id);
    if (authorization == null) return null;
    IdentityPrincipal principal = principal(authorization);
    if (TransactionSynchronizationManager.isActualTransactionActive()) {
      try {
        accounts.lockAndRequire(principal);
      } catch (org.springframework.security.authentication.BadCredentialsException e) {
        return null;
      }
      jdbc.queryForList(
          "SELECT id FROM oauth2_authorization WHERE id=? FOR UPDATE", String.class, id);
      authorization = delegate.findById(id);
    } else if (!accounts.allowed(principal)) return null;
    if (Boolean.TRUE.equals(
        jdbc.queryForObject(
            "SELECT revoked FROM oauth2_authorization WHERE id=?", Boolean.class, id))) return null;
    var clientAuth =
        org.springframework.security.core.context.SecurityContextHolder.getContext()
            .getAuthentication();
    if (clientAuth
            instanceof
            org.springframework.security.oauth2.server.authorization.authentication
                        .OAuth2ClientAuthenticationToken
                    client
        && client.getRegisteredClient() != null
        && !client.getRegisteredClient().getId().equals(authorization.getRegisteredClientId()))
      return null;
    var refresh = authorization.getRefreshToken();
    if (OAuth2TokenType.REFRESH_TOKEN.equals(type)
        && refresh != null
        && !refresh.getToken().getTokenValue().equals(digest)) {
      jdbc.update("UPDATE oauth2_authorization SET revoked=true WHERE id=?", id);
      accounts.audit(principal.getUserId(), "TOKEN_REUSE_DETECTED");
      return null;
    }
    OAuth2Authorization.Builder restored = OAuth2Authorization.from(authorization);
    boolean matched = false;
    for (Class<? extends OAuth2Token> tokenClass : tokenClasses()) {
      var token = authorization.getToken(tokenClass);
      if (token != null && token.getToken().getTokenValue().equals(digest)) {
        restored.token(copy(token.getToken(), raw), meta -> meta.putAll(token.getMetadata()));
        matched = true;
      }
    }
    return matched ? restored.build() : null;
  }

  private static boolean matchesType(String value, String indexedType) {
    return switch (value) {
      case "code" -> indexedType.equals("OAuth2AuthorizationCode");
      case "access_token" -> indexedType.equals("OAuth2AccessToken");
      case "refresh_token" -> indexedType.equals("OAuth2RefreshToken");
      case "id_token" -> indexedType.equals("OidcIdToken");
      default -> false;
    };
  }

  static IdentityPrincipal principal(OAuth2Authorization auth) {
    Object value = auth.getAttribute(Principal.class.getName());
    if (value instanceof org.springframework.security.core.Authentication authentication
        && authentication.getPrincipal() instanceof IdentityPrincipal principal) return principal;
    throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
  }

  private static List<Class<? extends OAuth2Token>> tokenClasses() {
    return List.of(
        OAuth2AuthorizationCode.class,
        OAuth2AccessToken.class,
        OAuth2RefreshToken.class,
        OidcIdToken.class);
  }

  private static OAuth2Token copy(OAuth2Token token, String value) {
    if (token instanceof OAuth2AuthorizationCode)
      return new OAuth2AuthorizationCode(value, token.getIssuedAt(), token.getExpiresAt());
    if (token instanceof OAuth2AccessToken access)
      return new OAuth2AccessToken(
          access.getTokenType(),
          value,
          token.getIssuedAt(),
          token.getExpiresAt(),
          access.getScopes());
    if (token instanceof OAuth2RefreshToken)
      return new OAuth2RefreshToken(value, token.getIssuedAt(), token.getExpiresAt());
    if (token instanceof OidcIdToken id)
      return new OidcIdToken(value, token.getIssuedAt(), token.getExpiresAt(), id.getClaims());
    throw new IllegalArgumentException("Unsupported token");
  }

  static String digest(String token) {
    try {
      return "sha256:"
          + HexFormat.of()
              .formatHex(
                  MessageDigest.getInstance("SHA-256")
                      .digest(token.getBytes(StandardCharsets.UTF_8)));
    } catch (Exception e) {
      throw new IllegalStateException("SHA-256 unavailable");
    }
  }

  private static String storedDigest(String value) {
    return value.matches("sha256:[a-f0-9]{64}") ? value : digest(value);
  }
}
