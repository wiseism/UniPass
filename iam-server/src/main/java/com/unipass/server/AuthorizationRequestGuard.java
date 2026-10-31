package com.unipass.server;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.util.List;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Strict contract before any authentication redirect, including loopback port and duplicate checks.
 */
final class AuthorizationRequestGuard extends OncePerRequestFilter {
  private final RegisteredClientRepository clients;
  private final AccountState accounts;
  private final MfaService mfa;
  private final PortalContinuations continuations;

  AuthorizationRequestGuard(
      RegisteredClientRepository clients,
      AccountState accounts,
      MfaService mfa,
      PortalContinuations continuations) {
    this.clients = clients;
    this.accounts = accounts;
    this.mfa = mfa;
    this.continuations = continuations;
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    return !request.getServletPath().equals("/oauth/authorize");
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    boolean invalid = false;
    for (String key :
        List.of(
            "response_type",
            "client_id",
            "redirect_uri",
            "scope",
            "state",
            "code_challenge",
            "code_challenge_method",
            "nonce",
            "prompt",
            "max_age",
            "login_hint")) {
      String[] values = request.getParameterValues(key);
      if (values != null && values.length != 1) invalid = true;
    }
    String clientId = request.getParameter("client_id");
    var client = clientId == null ? null : clients.findByClientId(clientId);
    String challenge = request.getParameter("code_challenge"),
        state = request.getParameter("state");
    invalid |=
        client == null
            || !"code".equals(request.getParameter("response_type"))
            || !"S256".equals(request.getParameter("code_challenge_method"))
            || challenge == null
            || !challenge.matches("[A-Za-z0-9_-]{43}")
            || state == null
            || state.isBlank()
            || state.length() > 500
            || client != null
                && !client.getRedirectUris().contains(request.getParameter("redirect_uri"));
    if (invalid) {
      response.setStatus(400);
      response.setContentType("application/json");
      response.getWriter().write("{\"error\":\"invalid_request\"}");
      return;
    }
    if (request.getQueryString() != null && request.getQueryString().length() > 8192) {
      response.setStatus(400);
      return;
    }
    var authentication =
        org.springframework.security.core.context.SecurityContextHolder.getContext()
            .getAuthentication();
    if (authentication != null
        && authentication.getPrincipal() instanceof IdentityPrincipal principal) {
      try {
        // A family-only logout does not fence the user's other clients. Reusing
        // this IAM login for the same RP would resurrect its already retired sid.
        if (accounts.backchannelRequiresReauthentication(principal, clientId)) {
          continuations.retainAcrossInvalidation(request, principal);
          org.springframework.security.core.context.SecurityContextHolder.clearContext();
          authentication = null;
        }
      } catch (RuntimeException unavailable) {
        response.setStatus(503);
        return;
      }
    }
    IdentityPrincipal principal =
        authentication != null
                && authentication.getPrincipal() instanceof IdentityPrincipal identity
            ? identity
            : null;
    if (principal == null) continuations.capture(request, null);
    if (principal != null
        && PortalContinuations.html(request)
        && (accounts.mustChange(principal.getUserId())
            || mfa.required(principal) && !mfa.recent(principal))) {
      continuations.capture(request, principal);
      response.sendRedirect(continuations.afterLogin(request, principal));
      return;
    }
    if (principal != null && accounts.mustChange(principal.getUserId())) {
      response.setStatus(403);
      response.setContentType("application/json");
      response.getWriter().write("{\"error\":\"password_change_required\"}");
      return;
    }
    if (principal != null && mfa.required(principal) && !mfa.recent(principal)) {
      java.util.UUID context = java.util.UUID.randomUUID();
      request.getSession().setAttribute(MfaController.CONTEXT, context);
      response.setStatus(401);
      response.setContentType("application/json");
      response.getWriter().write("{\"error\":\"mfa_required\",\"context\":\"" + context + "\"}");
      return;
    }
    if (principal != null) continuations.authorized(request);
    chain.doFilter(request, response);
  }
}
