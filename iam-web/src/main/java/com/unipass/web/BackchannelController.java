package com.unipass.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.bind.annotation.*;

@RestController
public final class BackchannelController {
  private final BackchannelSessions sessions;

  public BackchannelController(BackchannelSessions sessions) {
    this.sessions = sessions;
  }

  @PostMapping(path = "/logout/backchannel", consumes = "application/x-www-form-urlencoded")
  ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response) {
    response.setHeader("Cache-Control", "no-store");
    if (request.getQueryString() != null) return ResponseEntity.badRequest().build();
    String[] values = request.getParameterValues("logout_token");
    if (values == null || values.length != 1) return ResponseEntity.badRequest().build();
    try {
      sessions.accept(values[0]);
      return ResponseEntity.ok().build();
    } catch (BadJwtException invalid) {
      return ResponseEntity.badRequest().build();
    } catch (RuntimeException unavailable) {
      return ResponseEntity.status(503).build();
    }
  }
}
