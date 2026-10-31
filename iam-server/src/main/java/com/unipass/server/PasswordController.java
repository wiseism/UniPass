package com.unipass.server;

import com.unipass.password.*;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Size;
import java.util.*;
import org.springframework.http.*;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;

@RestController
public class PasswordController {
  private final PasswordChangeService passwords;
  private final MfaService mfa;
  private final java.time.Clock clock;
  private final AccountState accounts;

  public PasswordController(
      PasswordChangeService passwords,
      MfaService mfa,
      java.time.Clock clock,
      AccountState accounts) {
    this.passwords = passwords;
    this.mfa = mfa;
    this.clock = clock;
    this.accounts = accounts;
  }

  public static final class PasswordRequest {
    @com.fasterxml.jackson.annotation.JsonProperty("old_password")
    @Size(min = 1, max = 1024)
    public char[] oldPassword;

    @com.fasterxml.jackson.annotation.JsonProperty("new_password")
    @Size(min = 1, max = 1024)
    public char[] newPassword;

    @com.fasterxml.jackson.annotation.JsonProperty("confirm_password")
    @Size(min = 1, max = 1024)
    public char[] confirmation;

    @Override
    public String toString() {
      return "PasswordRequest[REDACTED]";
    }
  }

  @GetMapping("/api/session/csrf")
  Map<String, String> csrf(CsrfToken csrf) {
    return Map.of(
        "header_name",
        csrf.getHeaderName(),
        "parameter_name",
        csrf.getParameterName(),
        "token",
        csrf.getToken());
  }

  @GetMapping("/api/session/me")
  Map<String, Object> me(@AuthenticationPrincipal IdentityPrincipal principal) {
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("sub", principal.getUserId());
    result.put("auth_epoch", principal.getEpoch());
    result.put("login_id", principal.getLoginId());
    result.put("authenticated_at", principal.getAuthenticatedAt());
    result.put("method", principal.getAuthenticationMethod().name());
    result.put("password_recent", principal.hasRecentPassword(clock.instant()));
    result.put("must_change_password", accounts.mustChange(principal.getUserId()));
    result.put("roles", accounts.roles(principal.getUserId()));
    result.put(
        "mfa",
        Map.of(
            "enrolled",
            mfa.enrolled(principal.getUserId()),
            "required",
            mfa.required(principal),
            "recent",
            mfa.recent(principal),
            "recovery_required",
            mfa.recoveryRequired(principal.getUserId())));
    return result;
  }

  @PostMapping("/api/password/change")
  ResponseEntity<PasswordOperation> change(
      @AuthenticationPrincipal IdentityPrincipal principal,
      @RequestHeader("Idempotency-Key") String key,
      @Valid @RequestBody PasswordRequest request) {
    try {
      mfa.requireStrong(principal);
      if (!principal.hasRecentPassword(clock.instant()))
        throw new PasswordFailure(PasswordFailure.Code.RECENT_AUTH_REQUIRED);
      AuthenticatedActor actor =
          AuthenticatedActor.user(
              principal.getUserId(),
              principal.getEpoch(),
              principal.getPasswordAuthenticatedAt(),
              principal.getLoginId());
      PasswordOperation operation =
          passwords.change(
              actor, key, request.oldPassword, request.newPassword, request.confirmation);
      return ResponseEntity.status(
              operation.state() == PasswordOperation.State.UNKNOWN
                      || operation.state() == PasswordOperation.State.PREPARED
                  ? 202
                  : 200)
          .body(operation);
    } finally {
      if (request.oldPassword != null) Arrays.fill(request.oldPassword, '\0');
      if (request.newPassword != null) Arrays.fill(request.newPassword, '\0');
      if (request.confirmation != null) Arrays.fill(request.confirmation, '\0');
    }
  }

  @GetMapping("/api/password/operations/{id}")
  PasswordOperation status(
      @AuthenticationPrincipal IdentityPrincipal principal, @PathVariable("id") UUID id) {
    return passwords.get(id, principal.getUserId());
  }

  @GetMapping("/api/password/requests/{key}/operation")
  PasswordOperation requestStatus(
      @AuthenticationPrincipal IdentityPrincipal principal, @PathVariable UUID key) {
    return passwords.getByRequest(principal.getUserId(), key.toString());
  }
}
