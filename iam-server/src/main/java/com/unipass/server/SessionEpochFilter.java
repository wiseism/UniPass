package com.unipass.server;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.time.*;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Redis session existence alone is insufficient after password change or directory lifecycle
 * updates.
 */
final class SessionEpochFilter extends OncePerRequestFilter {
  private final AccountState accounts;
  private final Clock clock;
  private final LoginSessions sessions;
  private final PortalContinuations continuations;

  SessionEpochFilter(
      AccountState accounts,
      Clock clock,
      LoginSessions sessions,
      PortalContinuations continuations) {
    this.accounts = accounts;
    this.clock = clock;
    this.sessions = sessions;
    this.continuations = continuations;
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    // Recovery routes use their own browser-bound capability; never trust a stale principal here.
    String path = request.getServletPath();
    return path.startsWith("/api/password/reset/")
        || path.equals("/api/public/csrf")
        || path.startsWith("/portal/assets/")
        || java.util.Set.of(
                "/reset",
                "/portal/",
                "/portal/mfa",
                "/portal/password",
                "/portal/factors",
                "/portal/sessions",
                "/portal/binding")
            .contains(path);
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    var authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication != null
        && authentication.getPrincipal() instanceof IdentityPrincipal principal) {
      boolean allowed;
      try {
        allowed =
            principal.getAuthenticatedAt().plus(Duration.ofDays(1)).isAfter(clock.instant())
                && accounts.allowed(principal);
      } catch (RuntimeException e) {
        response.setStatus(503);
        return;
      }
      // Only the operation-status route keeps a recent, bounded recovery session during its own
      // fence.
      boolean recoveryStatus;
      try {
        String path = request.getServletPath();
        boolean operation = path.matches("/api/password/operations/[a-fA-F0-9-]{36}");
        boolean byRequest = path.matches("/api/password/requests/[a-fA-F0-9-]{36}/operation");
        recoveryStatus =
            !allowed
                && request.getMethod().equals("GET")
                && principal.hasRecentPassword(clock.instant())
                && (operation
                        && accounts.recoveryStatusAllowed(
                            principal, path.substring(path.lastIndexOf('/') + 1))
                    || byRequest
                        && accounts.recoveryRequestStatusAllowed(principal, path.split("/")[4]));
      } catch (RuntimeException e) {
        response.setStatus(503);
        return;
      }
      if (!allowed && !recoveryStatus) {
        continuations.retainAcrossInvalidation(request, principal);
        SecurityContextHolder.clearContext();
        if (request.getServletPath().equals("/login")) {
          chain.doFilter(request, response);
          return;
        }
        response.setStatus(401);
        return;
      }
      if (allowed) {
        try {
          sessions.seen(principal, request.getHeader("User-Agent"));
        } catch (RuntimeException e) {
          response.setStatus(503);
          return;
        }
      }
    }
    chain.doFilter(request, response);
  }
}
