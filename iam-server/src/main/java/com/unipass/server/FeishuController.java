package com.unipass.server;

import jakarta.servlet.http.*;
import java.util.*;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.csrf.CsrfAuthenticationStrategy;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/connector/feishu")
public final class FeishuController {
  private final FeishuService service;
  private final PortalContinuations continuations;

  public FeishuController(FeishuService service, PortalContinuations continuations) {
    this.service = service;
    this.continuations = continuations;
  }

  @PostMapping("/login/start")
  FeishuService.Start login(
      @AuthenticationPrincipal IdentityPrincipal principal, HttpServletRequest request) {
    return service.start(false, principal, request.getSession().getId(), request.getRemoteAddr());
  }

  @PostMapping("/binding/start")
  FeishuService.Start bind(
      @AuthenticationPrincipal IdentityPrincipal principal, HttpServletRequest request) {
    return service.start(true, principal, request.getSession().getId(), request.getRemoteAddr());
  }

  @PostMapping("/binding/remove")
  Map<String, Boolean> unlink(@AuthenticationPrincipal IdentityPrincipal principal) {
    service.unlink(principal);
    return Map.of("reauthentication_required", true);
  }

  @GetMapping("/callback")
  Map<String, Boolean> callback(
      @AuthenticationPrincipal IdentityPrincipal principal,
      HttpServletRequest request,
      HttpServletResponse response)
      throws java.io.IOException {
    response.setHeader("Cache-Control", "no-store");
    var session = request.getSession(false);
    IdentityPrincipal authenticated;
    try {
      if (session == null
          || request.getParameterMap().entrySet().stream()
              .anyMatch(
                  entry ->
                      entry.getValue().length != 1
                          || !Set.of("state", "code", "error").contains(entry.getKey())))
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Flow unavailable");
      authenticated =
          service.callback(
              request.getParameter("state"),
              request.getParameter("code"),
              request.getParameter("error"),
              principal,
              session.getId());
    } catch (ResponseStatusException failure) {
      if (!PortalContinuations.html(request)) throw failure;
      response.sendRedirect("/login?external_error");
      return null;
    }
    if (authenticated == null) {
      if (PortalContinuations.html(request)) {
        response.sendRedirect("/portal/binding?bound");
        return null;
      }
      return Map.of("bound", true);
    }
    var context = SecurityContextHolder.createEmptyContext();
    context.setAuthentication(
        UsernamePasswordAuthenticationToken.authenticated(
            authenticated, null, authenticated.getAuthorities()));
    request.changeSessionId();
    session.removeAttribute(MfaController.CONTEXT);
    new CsrfAuthenticationStrategy(new HttpSessionCsrfTokenRepository())
        .onAuthentication(context.getAuthentication(), request, response);
    SecurityContextHolder.setContext(context);
    new HttpSessionSecurityContextRepository().saveContext(context, request, response);
    if (PortalContinuations.html(request)) {
      response.sendRedirect(continuations.afterLogin(request, authenticated));
      return null;
    }
    return Map.of("authenticated", true);
  }
}
