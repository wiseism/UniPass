package com.unipass.server;

import jakarta.servlet.http.*;
import java.util.*;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/mfa")
public class MfaController {
  static final String CONTEXT = "unipass.mfa.context";
  private final MfaService mfa;

  public MfaController(MfaService mfa) {
    this.mfa = mfa;
  }

  public record Code(String code) {
    @Override
    public String toString() {
      return "Code[REDACTED]";
    }
  }

  public record ChallengeRequest(UUID context) {}

  public record VerifyRequest(UUID context, UUID challenge, String code) {
    @Override
    public String toString() {
      return "VerifyRequest[REDACTED]";
    }
  }

  @GetMapping
  Map<String, Object> status(@AuthenticationPrincipal IdentityPrincipal principal) {
    return Map.of(
        "enrolled",
        mfa.enrolled(principal.getUserId()),
        "required",
        mfa.required(principal),
        "recent",
        mfa.recent(principal),
        "recovery_required",
        mfa.recoveryRequired(principal.getUserId()));
  }

  @PostMapping("/enrollment")
  MfaService.Enrollment enroll(@AuthenticationPrincipal IdentityPrincipal principal) {
    return mfa.enroll(principal);
  }

  @PostMapping("/enrollment/confirm")
  Map<String, Boolean> confirm(
      @AuthenticationPrincipal IdentityPrincipal principal, @RequestBody Code request) {
    mfa.confirmEnrollment(principal, request.code());
    return Map.of("reauthentication_required", true);
  }

  @PostMapping("/context")
  Map<String, UUID> context(HttpSession session) {
    UUID context = UUID.randomUUID();
    session.setAttribute(CONTEXT, context);
    return Map.of("context", context);
  }

  @PostMapping("/challenges")
  Map<String, UUID> challenge(
      @AuthenticationPrincipal IdentityPrincipal principal,
      HttpSession session,
      @RequestBody ChallengeRequest request) {
    checkContext(session, request.context());
    return Map.of("challenge", mfa.challenge(principal, session.getId(), request.context()));
  }

  @PostMapping("/verify")
  Map<String, Boolean> verify(
      @AuthenticationPrincipal IdentityPrincipal principal,
      HttpServletRequest servletRequest,
      HttpServletResponse response,
      @RequestBody VerifyRequest request) {
    HttpSession session = servletRequest.getSession();
    checkContext(session, request.context());
    if (request.challenge() == null)
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid challenge");
    var at =
        mfa.verifyChallenge(
            principal, session.getId(), request.context(), request.challenge(), request.code());
    IdentityPrincipal upgraded = principal.withMfa(at);
    var context = SecurityContextHolder.createEmptyContext();
    context.setAuthentication(
        UsernamePasswordAuthenticationToken.authenticated(
            upgraded, null, upgraded.getAuthorities()));
    servletRequest.changeSessionId();
    session.removeAttribute(CONTEXT);
    SecurityContextHolder.setContext(context);
    new HttpSessionSecurityContextRepository().saveContext(context, servletRequest, response);
    return Map.of("verified", true);
  }

  private static void checkContext(HttpSession session, UUID context) {
    if (context == null || !context.equals(session.getAttribute(CONTEXT)))
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid challenge context");
  }
}
