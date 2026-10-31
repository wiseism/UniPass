package com.unipass.server;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import java.util.*;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
public final class MfaLifecycleController {
  private final MfaLifecycleService lifecycle;

  public MfaLifecycleController(MfaLifecycleService lifecycle) {
    this.lifecycle = lifecycle;
  }

  public record Recover(
      @JsonProperty("recovery_token") @NotBlank @Pattern(regexp = "[A-Za-z0-9_-]{43}")
          String token) {
    @Override
    public String toString() {
      return "Recover[REDACTED]";
    }
  }

  public record Authorization(
      @NotBlank @Size(max = 500) String reason,
      @JsonProperty("evidence_ref") @NotBlank @Size(max = 500) String evidence) {}

  @PostMapping("/api/mfa/rotation")
  MfaLifecycleService.Replacement rotate(
      @AuthenticationPrincipal IdentityPrincipal principal, HttpSession session) {
    return lifecycle.rotate(principal, session.getId());
  }

  @PostMapping("/api/mfa/recovery")
  MfaLifecycleService.Replacement recover(
      @AuthenticationPrincipal IdentityPrincipal principal,
      HttpSession session,
      @Valid @RequestBody Recover input) {
    return lifecycle.recover(principal, session.getId(), input.token());
  }

  @PostMapping("/api/mfa/changes/{id}/confirm")
  Map<String, Boolean> confirm(
      @AuthenticationPrincipal IdentityPrincipal principal,
      HttpSession session,
      @PathVariable("id") UUID id,
      @Valid @RequestBody MfaController.Code input) {
    lifecycle.confirm(principal, session.getId(), id, input.code());
    return Map.of("reauthentication_required", true);
  }

  @PostMapping("/api/mfa/changes/{id}/cancel")
  Map<String, Boolean> cancel(
      @AuthenticationPrincipal IdentityPrincipal principal,
      HttpSession session,
      @PathVariable("id") UUID id) {
    lifecycle.cancel(principal, session.getId(), id);
    return Map.of("cancelled", true);
  }

  @PostMapping("/api/admin/mfa/users/{id}/recovery")
  MfaLifecycleService.RecoveryGrant authorize(
      @AuthenticationPrincipal IdentityPrincipal principal,
      @PathVariable("id") UUID target,
      @RequestHeader("Idempotency-Key") String key,
      @Valid @RequestBody Authorization input) {
    return lifecycle.authorizeRecovery(principal, target, key, input.reason(), input.evidence());
  }
}
