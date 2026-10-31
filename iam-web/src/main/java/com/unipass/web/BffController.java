package com.unipass.web;

import jakarta.servlet.http.HttpServletRequest;
import java.util.*;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;

@RestController
public final class BffController {
  private final RpSettings settings;

  public BffController(RpSettings settings) {
    this.settings = settings;
  }

  @GetMapping("/health")
  Map<String, String> health() {
    return Map.of("status", "UP");
  }

  @GetMapping("/csrf")
  Map<String, String> csrf(CsrfToken csrf) {
    return Map.of("header_name", csrf.getHeaderName(), "token", csrf.getToken());
  }

  @GetMapping("/bff/profile")
  Map<String, String> profile(@AuthenticationPrincipal OidcUser user) {
    return Map.of("sub", user.getSubject(), "application", settings.id);
  }

  @GetMapping("/bff/data")
  ResponseEntity<String> data(HttpServletRequest request) {
    var client = (OAuth2AuthorizedClient) request.getAttribute(BffStateFilter.CLIENT);
    try {
      var headers = new org.springframework.http.HttpHeaders();
      headers.setBearerAuth(client.getAccessToken().getTokenValue());
      var response =
          RpConfiguration.http()
              .exchange(
                  settings.origin + "/api/resource/data",
                  org.springframework.http.HttpMethod.GET,
                  new org.springframework.http.HttpEntity<>(headers),
                  String.class);
      return ResponseEntity.ok()
          .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
          .body(response.getBody());
    } catch (org.springframework.web.client.RestClientException unavailable) {
      return ResponseEntity.status(503).build();
    }
  }

  @GetMapping("/api/resource/data")
  Map<String, String> resource(@AuthenticationPrincipal Jwt jwt) {
    return Map.of(
        "sub",
        jwt.getSubject(),
        "application",
        settings.id,
        "result",
        "Authorized application data");
  }
}
