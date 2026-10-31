package com.unipass.server;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.unipass.password.PasswordOperation;
import jakarta.servlet.http.*;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import java.util.*;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;

@RestController
public class EmailRecoveryController {
  private final EmailRecoveryService recovery;

  public EmailRecoveryController(EmailRecoveryService recovery) {
    this.recovery = recovery;
  }

  public record Request(@JsonProperty("employee_no") @NotBlank @Size(max = 100) String employee) {}

  public record Proof(@NotBlank @Size(max = 100) String token) {
    @Override
    public String toString() {
      return "Proof[REDACTED]";
    }
  }

  public static final class Confirmation {
    @JsonProperty("reset_token")
    @NotBlank
    @Size(max = 100)
    public String token;

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
      return "Confirmation[REDACTED]";
    }
  }

  @GetMapping("/api/public/csrf")
  Map<String, String> csrf(CsrfToken token) {
    return Map.of(
        "header_name",
        token.getHeaderName(),
        "parameter_name",
        token.getParameterName(),
        "token",
        token.getToken());
  }

  @PostMapping("/api/password/reset/request")
  ResponseEntity<Map<String, String>> request(
      @Valid @RequestBody Request input, HttpServletRequest request) {
    recovery.request(input.employee(), request.getRemoteAddr());
    return ResponseEntity.accepted().body(Map.of("status", "accepted"));
  }

  @PostMapping("/api/password/reset/verify")
  EmailRecoveryService.Verified verify(@Valid @RequestBody Proof proof, HttpSession session) {
    return recovery.verify(proof.token(), session.getId());
  }

  @PostMapping("/api/password/reset/confirm")
  ResponseEntity<PasswordOperation> confirm(
      @Valid @RequestBody Confirmation input,
      HttpSession session,
      @RequestHeader("Idempotency-Key") String key) {
    PasswordOperation result =
        recovery.confirm(input.token, session.getId(), key, input.password, input.confirmation);
    return ResponseEntity.status(
            result.state() == PasswordOperation.State.UNKNOWN
                    || result.state() == PasswordOperation.State.PREPARED
                ? 202
                : 200)
        .body(result);
  }

  @GetMapping("/api/password/reset/operations/{id}")
  PasswordOperation status(@PathVariable("id") UUID id, HttpSession session) {
    return recovery.status(id, session.getId());
  }

  @GetMapping("/api/password/reset/requests/{key}/operation")
  PasswordOperation requestStatus(@PathVariable UUID key, HttpSession session) {
    return recovery.requestStatus(key, session.getId());
  }
}
