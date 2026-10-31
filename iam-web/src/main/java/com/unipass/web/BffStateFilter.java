package com.unipass.web;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.time.Instant;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.filter.OncePerRequestFilter;

final class BffStateFilter extends OncePerRequestFilter {
  static final String CLIENT = BffStateFilter.class.getName() + ".client";
  private static final String STARTED = BffStateFilter.class.getName() + ".started";
  private final OAuth2AuthorizedClientManager manager;
  private final LiveAccessDecoder decoder;
  private final BackchannelSessions sessions;

  BffStateFilter(
      OAuth2AuthorizedClientManager manager,
      LiveAccessDecoder decoder,
      BackchannelSessions sessions) {
    this.manager = manager;
    this.decoder = decoder;
    this.sessions = sessions;
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    return !request.getServletPath().startsWith("/bff/");
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    var authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication instanceof OAuth2AuthenticationToken login
        && login.getPrincipal() instanceof OidcUser user) {
      try {
        if (!sessions.active(user)) {
          reject(request, response);
          return;
        }
      } catch (RuntimeException unavailable) {
        response.setStatus(503);
        return;
      }
      var session = request.getSession();
      Instant start = (Instant) session.getAttribute(STARTED);
      if (start == null) {
        start = user.getIdToken().getIssuedAt();
        session.setAttribute(STARTED, start);
      }
      if (start == null || !start.plusSeconds(86400).isAfter(Instant.now())) {
        reject(request, response);
        return;
      }
      OAuth2AuthorizedClient client;
      try {
        client =
            manager.authorize(
                OAuth2AuthorizeRequest.withClientRegistrationId("unipass")
                    .principal(authentication)
                    .attribute(HttpServletRequest.class.getName(), request)
                    .attribute(HttpServletResponse.class.getName(), response)
                    .build());
      } catch (RuntimeException failure) {
        reject(request, response);
        return;
      } // Refresh outcome unknown: discard, never retry the old refresh token.
      if (client == null) {
        reject(request, response);
        return;
      }
      try {
        Jwt jwt = decoder.decode(client.getAccessToken().getTokenValue());
        if (!user.getSubject().equals(jwt.getSubject()))
          throw new BadJwtException("Subject mismatch");
      } catch (AuthenticationServiceException unavailable) {
        response.setStatus(503);
        return;
      } catch (BadJwtException invalid) {
        reject(request, response);
        return;
      } catch (JwtException unavailable) {
        response.setStatus(503);
        return;
      }
      request.setAttribute(CLIENT, client);
    }
    chain.doFilter(request, response);
  }

  private static void reject(HttpServletRequest request, HttpServletResponse response) {
    if (request.getSession(false) != null) request.getSession(false).invalidate();
    SecurityContextHolder.clearContext();
    response.setStatus(401);
  }
}
