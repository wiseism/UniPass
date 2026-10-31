package com.unipass.server;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/session/logins")
public final class LoginSessionController {
  private final LoginSessions sessions;
  private final String origin;

  public LoginSessionController(LoginSessions sessions, @Value("${unipass.issuer}") String issuer) {
    this.sessions = sessions;
    URI uri = URI.create(issuer);
    int port = uri.getPort();
    origin =
        uri.getScheme()
            + "://"
            + uri.getHost().toLowerCase(java.util.Locale.ROOT)
            + (port == -1
                    || port == 443 && uri.getScheme().equals("https")
                    || port == 80 && uri.getScheme().equals("http")
                ? ""
                : ":" + port);
  }

  @GetMapping
  LoginSessions.Page list(
      @AuthenticationPrincipal IdentityPrincipal principal,
      @RequestParam(required = false) UUID before) {
    return sessions.list(principal, before);
  }

  @PostMapping("/{id}/revoke")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  void revoke(
      @AuthenticationPrincipal IdentityPrincipal principal,
      @PathVariable UUID id,
      HttpServletRequest request) {
    var values = request.getHeaders("Origin");
    if (!values.hasMoreElements()
        || !origin.equals(values.nextElement())
        || values.hasMoreElements())
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Origin rejected");
    sessions.revoke(principal, id);
    if (id.equals(principal.getLoginId())) {
      if (request.getSession(false) != null) request.getSession(false).invalidate();
      SecurityContextHolder.clearContext();
    }
  }
}
