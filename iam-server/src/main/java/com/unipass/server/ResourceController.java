package com.unipass.server;

import java.util.Map;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
public class ResourceController {
  @GetMapping("/api/resource/me")
  Map<String, Object> me(@AuthenticationPrincipal Jwt jwt) {
    return Map.of(
        "sub",
        jwt.getSubject(),
        "auth_epoch",
        jwt.getClaim("auth_epoch"),
        "client_id",
        jwt.getClaimAsString("client_id"));
  }
}
