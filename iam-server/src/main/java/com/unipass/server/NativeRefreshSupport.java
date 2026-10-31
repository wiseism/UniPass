package com.unipass.server;

import jakarta.servlet.http.HttpServletRequest;
import java.security.SecureRandom;
import java.time.*;
import java.util.*;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.*;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.web.authentication.AuthenticationConverter;

/** Public native applications can rotate refresh tokens; browser SPAs remain ineligible. */
final class NativeRefreshSupport
    implements AuthenticationProvider,
        AuthenticationConverter,
        OAuth2TokenGenerator<OAuth2RefreshToken> {
  private final RegisteredClientRepository clients;
  private final Clock clock;

  NativeRefreshSupport(RegisteredClientRepository clients, Clock clock) {
    this.clients = clients;
    this.clock = clock;
  }

  @Override
  public Authentication convert(HttpServletRequest request) {
    if (!"refresh_token".equals(request.getParameter("grant_type"))
        || request.getHeader("Authorization") != null
        || request.getParameter("client_secret") != null
        || request.getParameter("client_assertion") != null) return null;
    String[] clientId = request.getParameterValues("client_id");
    if (clientId == null || clientId.length != 1 || clientId[0].isBlank())
      throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
    return new OAuth2ClientAuthenticationToken(
        clientId[0], ClientAuthenticationMethod.NONE, null, Map.of("grant_type", "refresh_token"));
  }

  @Override
  public Authentication authenticate(Authentication authentication) {
    OAuth2ClientAuthenticationToken token = (OAuth2ClientAuthenticationToken) authentication;
    if (!ClientAuthenticationMethod.NONE.equals(token.getClientAuthenticationMethod())
        || !"refresh_token".equals(token.getAdditionalParameters().get("grant_type"))) return null;
    RegisteredClient client = clients.findByClientId(token.getPrincipal().toString());
    if (client == null
        || !client.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.NONE)
        || !Boolean.TRUE.equals(client.getClientSettings().getSetting("unipass.native"))
        || !client.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN))
      throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
    return new OAuth2ClientAuthenticationToken(client, ClientAuthenticationMethod.NONE, null);
  }

  @Override
  public boolean supports(Class<?> type) {
    return OAuth2ClientAuthenticationToken.class.isAssignableFrom(type);
  }

  @Override
  public OAuth2RefreshToken generate(OAuth2TokenContext context) {
    if (!OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) return null;
    RegisteredClient client = context.getRegisteredClient();
    if (client.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.NONE)
        && !Boolean.TRUE.equals(client.getClientSettings().getSetting("unipass.native")))
      return null;
    Instant now = clock.instant();
    Instant expires = now.plus(client.getTokenSettings().getRefreshTokenTimeToLive());
    if (context.getPrincipal().getPrincipal() instanceof IdentityPrincipal principal) {
      Instant absolute = principal.getAuthenticatedAt().plus(Duration.ofDays(30));
      if (expires.isAfter(absolute)) expires = absolute;
    }
    if (!expires.isAfter(now))
      throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
    byte[] bytes = new byte[32];
    new SecureRandom().nextBytes(bytes);
    return new OAuth2RefreshToken(
        Base64.getUrlEncoder().withoutPadding().encodeToString(bytes), now, expires);
  }
}
