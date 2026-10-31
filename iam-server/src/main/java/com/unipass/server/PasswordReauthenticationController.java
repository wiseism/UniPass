package com.unipass.server;

import jakarta.servlet.http.*;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import java.util.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.*;

@RestController
public final class PasswordReauthenticationController {
  private final PasswordReauthentication passwords;

  public PasswordReauthenticationController(PasswordReauthentication passwords) {
    this.passwords = passwords;
  }

  public static final class Input {
    @NotNull
    @Size(min = 1, max = 1024)
    public char[] password;

    @Override
    public String toString() {
      return "PasswordReauthentication[REDACTED]";
    }
  }

  @PostMapping("/api/session/reauthenticate")
  Map<String, Boolean> verify(
      @AuthenticationPrincipal IdentityPrincipal principal,
      HttpServletRequest request,
      HttpServletResponse response,
      @Valid @RequestBody Input input) {
    try {
      IdentityPrincipal upgraded =
          passwords.verify(principal, input.password, request.getRemoteAddr());
      var context = SecurityContextHolder.createEmptyContext();
      context.setAuthentication(
          UsernamePasswordAuthenticationToken.authenticated(
              upgraded, null, upgraded.getAuthorities()));
      request.changeSessionId();
      request.getSession().removeAttribute(MfaController.CONTEXT);
      SecurityContextHolder.setContext(context);
      new HttpSessionSecurityContextRepository().saveContext(context, request, response);
      return Map.of("verified", true);
    } finally {
      if (input.password != null) Arrays.fill(input.password, '\0');
    }
  }
}
