package com.unipass.server;

import com.unipass.password.PasswordFailure;
import java.util.*;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;

@RestControllerAdvice
public class ApiErrors {
  @ExceptionHandler(org.springframework.security.authentication.BadCredentialsException.class)
  ResponseEntity<Map<String, String>> inactive() {
    return ResponseEntity.status(401)
        .body(Map.of("error", "SESSION_UNAVAILABLE", "trace_id", UUID.randomUUID().toString()));
  }

  @ExceptionHandler({
    org.springframework.dao.DataAccessException.class,
    org.springframework.transaction.TransactionException.class
  })
  ResponseEntity<Map<String, String>> storage() {
    return ResponseEntity.status(503)
        .body(Map.of("error", "STATE_UNAVAILABLE", "trace_id", UUID.randomUUID().toString()));
  }

  @ExceptionHandler(org.springframework.web.server.ResponseStatusException.class)
  ResponseEntity<Map<String, String>> rejected(
      org.springframework.web.server.ResponseStatusException error) {
    return ResponseEntity.status(error.getStatusCode())
        .body(Map.of("error", "REQUEST_REJECTED", "trace_id", UUID.randomUUID().toString()));
  }

  @ExceptionHandler(PasswordFailure.class)
  ResponseEntity<Map<String, Object>> password(PasswordFailure failure) {
    int status =
        switch (failure.code()) {
          case RECENT_AUTH_REQUIRED, STALE_SESSION -> 401;
          case ACCOUNT_BLOCKED, RECOVERY_NOT_PERMITTED -> 403;
          case RATE_LIMITED -> 429;
          case NOT_FOUND -> 404;
          case CONCURRENT_OPERATION -> 409;
          case STORAGE_UNAVAILABLE, DIRECTORY_UNAVAILABLE, DIRECTORY_POLICY_NOT_VERIFIED -> 503;
          default -> 400;
        };
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("error", failure.code().name());
    body.put("trace_id", failure.operationId() == null ? UUID.randomUUID() : failure.operationId());
    if (failure.operationId() != null) body.put("operation_id", failure.operationId());
    return ResponseEntity.status(status).body(body);
  }

  @ExceptionHandler(MethodArgumentNotValidException.class)
  ResponseEntity<Map<String, String>> validation() {
    return ResponseEntity.badRequest()
        .body(Map.of("error", "INVALID_REQUEST", "trace_id", UUID.randomUUID().toString()));
  }
}
