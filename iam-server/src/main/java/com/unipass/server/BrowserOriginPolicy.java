package com.unipass.server;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.net.URI;
import java.util.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public final class BrowserOriginPolicy {
  private final String origin;

  public BrowserOriginPolicy(@Value("${unipass.issuer}") String issuer) {
    URI uri = URI.create(issuer);
    int port = uri.getPort();
    origin =
        uri.getScheme()
            + "://"
            + uri.getHost().toLowerCase(Locale.ROOT)
            + (port == -1
                    || port == 443 && uri.getScheme().equals("https")
                    || port == 80 && uri.getScheme().equals("http")
                ? ""
                : ":" + port);
  }

  OncePerRequestFilter filter(boolean protocol) {
    return new OncePerRequestFilter() {
      @Override
      protected boolean shouldNotFilter(HttpServletRequest request) {
        return Set.of("GET", "HEAD", "OPTIONS").contains(request.getMethod())
            || protocol
                && !Set.of("/oauth/authorize", "/oauth/logout").contains(request.getServletPath());
      }

      @Override
      protected void doFilterInternal(
          HttpServletRequest request, HttpServletResponse response, FilterChain chain)
          throws IOException, ServletException {
        var headers = request.getHeaders("Origin");
        if (!headers.hasMoreElements()
            || !origin.equals(headers.nextElement())
            || headers.hasMoreElements()) {
          response.setStatus(403);
          response.setContentType("application/json");
          response.getWriter().write("{\"error\":\"ORIGIN_REJECTED\"}");
          return;
        }
        chain.doFilter(request, response);
      }
    };
  }
}
