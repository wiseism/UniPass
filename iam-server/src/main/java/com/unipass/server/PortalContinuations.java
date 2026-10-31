package com.unipass.server;

import jakarta.servlet.http.*;
import java.io.Serializable;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

/** Only validated authorization requests enter this server-written session value. */
@Service
public final class PortalContinuations {
  private static final String ATTRIBUTE = "unipass.portal.continuation";
  private final AccountState accounts;
  private final MfaService mfa;
  private final Clock clock;

  public PortalContinuations(AccountState accounts, MfaService mfa, Clock clock) {
    this.accounts = accounts;
    this.mfa = mfa;
    this.clock = clock;
  }

  private record Pending(UUID id, String target, UUID owner, Instant expiresAt)
      implements Serializable {}

  static boolean html(HttpServletRequest request) {
    String accept = request.getHeader("Accept");
    return accept != null && accept.contains("text/html");
  }

  private static String target(HttpServletRequest request) {
    var parameters = new ArrayList<String>();
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
      String value = request.getParameter(key);
      if (value != null)
        parameters.add(key + "=" + URLEncoder.encode(value, StandardCharsets.UTF_8));
    }
    String target = "/oauth/authorize?" + String.join("&", parameters);
    if (target.length() > 8192)
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Authorization request too large");
    return target;
  }

  UUID capture(HttpServletRequest request, IdentityPrincipal principal) {
    String target = target(request);
    UUID owner = principal == null ? null : principal.getUserId();
    var session = request.getSession();
    Pending prior = current(session);
    if (prior != null && prior.target.equals(target) && Objects.equals(prior.owner, owner))
      return prior.id;
    Pending next = new Pending(UUID.randomUUID(), target, owner, clock.instant().plusSeconds(600));
    session.setAttribute(ATTRIBUTE, next);
    return next.id;
  }

  void authorized(HttpServletRequest request) {
    HttpSession session = request.getSession(false);
    Pending pending = current(session);
    if (pending != null && pending.target.equals(target(request)))
      session.removeAttribute(ATTRIBUTE);
  }

  private Pending current(HttpSession session) {
    if (session == null) return null;
    Object value = session.getAttribute(ATTRIBUTE);
    return value instanceof Pending pending && pending.expiresAt.isAfter(clock.instant())
        ? pending
        : null;
  }

  private String step(IdentityPrincipal principal) {
    if (mfa.recoveryRequired(principal.getUserId())) return "/portal/factors";
    if (mfa.required(principal) && !mfa.recent(principal)) return "/portal/mfa";
    if (accounts.mustChange(principal.getUserId())) return "/portal/password";
    return null;
  }

  String afterLogin(HttpServletRequest request, IdentityPrincipal principal) {
    HttpSession session = request.getSession();
    Pending pending = current(session);
    if (pending != null && pending.owner != null && !pending.owner.equals(principal.getUserId())) {
      session.removeAttribute(ATTRIBUTE);
      pending = null;
    }
    if (pending != null) {
      pending = new Pending(pending.id, pending.target, principal.getUserId(), pending.expiresAt);
      session.setAttribute(ATTRIBUTE, pending);
    }
    String step = step(principal);
    if (step != null) return step + (pending == null ? "" : "?continue=" + pending.id);
    if (pending == null) return "/portal/";
    session.removeAttribute(ATTRIBUTE);
    return pending.target;
  }

  String resume(HttpServletRequest request, IdentityPrincipal principal, UUID id) {
    if (!accounts.allowed(principal))
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Login unavailable");
    HttpSession session = request.getSession(false);
    Pending pending = current(session);
    if (pending == null || !pending.id.equals(id) || !principal.getUserId().equals(pending.owner))
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Continuation unavailable");
    String step = step(principal);
    if (step != null) return step + "?continue=" + pending.id;
    session.removeAttribute(ATTRIBUTE);
    return pending.target;
  }

  // Password changes fence the principal. Carry only the original validated
  // request into a fresh anonymous session, never any authentication/MFA proof.
  void retainAcrossInvalidation(HttpServletRequest request, IdentityPrincipal principal) {
    HttpSession previous = request.getSession(false);
    Pending pending = current(previous);
    if (previous != null) previous.invalidate();
    if (pending != null && principal.getUserId().equals(pending.owner))
      request.getSession(true).setAttribute(ATTRIBUTE, pending);
  }
}
