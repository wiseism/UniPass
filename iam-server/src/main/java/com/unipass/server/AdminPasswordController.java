package com.unipass.server;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.unipass.password.PasswordOperation;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin/password")
public class AdminPasswordController {
  private final AdminPasswordService service;

  public AdminPasswordController(AdminPasswordService service) {
    this.service = service;
  }

  public static final class Reset {
    @NotBlank
    @Size(max = 500)
    public String reason;

    @JsonProperty("new_password")
    @NotNull
    @Size(min = 1, max = 1024)
    public char[] password;

    @JsonProperty("confirm_password")
    @NotNull
    @Size(min = 1, max = 1024)
    public char[] confirmation;

    @Override
    public String toString() {
      return "Reset[REDACTED]";
    }
  }

  public record Recovery(
      @JsonProperty("confirmed_committed") @NotNull Boolean committed,
      @NotBlank @Size(max = 500) String reason,
      @JsonProperty("evidence_ref") @NotBlank @Size(max = 500) String evidence) {}

  @PostMapping("/users/{id}/reset")
  ResponseEntity<PasswordOperation> reset(
      @AuthenticationPrincipal IdentityPrincipal principal,
      @PathVariable("id") UUID target,
      @RequestHeader("Idempotency-Key") String key,
      @Valid @RequestBody Reset input) {
    return result(
        service.reset(principal, target, key, input.reason, input.password, input.confirmation));
  }

  @PostMapping("/operations/{id}/recover")
  ResponseEntity<PasswordOperation> recover(
      @AuthenticationPrincipal IdentityPrincipal principal,
      @PathVariable("id") UUID operation,
      @RequestHeader("Idempotency-Key") String key,
      @Valid @RequestBody Recovery input) {
    return result(
        service.recover(
            principal, operation, key, input.committed(), input.reason(), input.evidence()));
  }

  @GetMapping("/operations/{id}")
  PasswordOperation status(
      @AuthenticationPrincipal IdentityPrincipal principal, @PathVariable("id") UUID operation) {
    return service.status(principal, operation);
  }

  private ResponseEntity<PasswordOperation> result(PasswordOperation operation) {
    return ResponseEntity.status(
            operation.state() == PasswordOperation.State.PREPARED
                    || operation.state() == PasswordOperation.State.UNKNOWN
                ? 202
                : 200)
        .body(operation);
  }
}
