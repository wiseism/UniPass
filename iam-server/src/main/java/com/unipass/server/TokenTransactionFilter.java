package com.unipass.server;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingResponseWrapper;

/** Serialize token consumption in PG; release the successful response only after commit. */
final class TokenTransactionFilter extends OncePerRequestFilter {
  private final TransactionTemplate transactions;

  TokenTransactionFilter(TransactionTemplate transactions) {
    this.transactions = transactions;
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    return !request.getServletPath().equals("/oauth/token")
        && !request.getServletPath().equals("/oauth/revoke");
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    ContentCachingResponseWrapper buffered = new ContentCachingResponseWrapper(response);
    try {
      transactions.executeWithoutResult(
          status -> {
            try {
              chain.doFilter(request, buffered);
            } catch (IOException | ServletException e) {
              throw new IllegalStateException("Token request interrupted");
            }
          });
      buffered.copyBodyToResponse();
    } catch (RuntimeException e) {
      response.reset();
      response.setStatus(503);
      response.setContentType("application/json");
      response.getWriter().write("{\"error\":\"temporarily_unavailable\"}");
    }
  }
}
