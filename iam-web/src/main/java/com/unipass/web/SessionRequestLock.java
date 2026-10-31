package com.unipass.web;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.*;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;

/** Must run outside Spring Session, holding the lease until the updated session has been saved. */
final class SessionRequestLock implements Filter {
  private final StringRedisTemplate redis;
  private final RpSettings settings;
  private static final DefaultRedisScript<Long> RELEASE =
      new DefaultRedisScript<>(
          "if redis.call('get',KEYS[1]) == ARGV[1] then return redis.call('del',KEYS[1]) else return 0 end",
          Long.class);

  SessionRequestLock(StringRedisTemplate redis, RpSettings settings) {
    this.redis = redis;
    this.settings = settings;
  }

  @Override
  public void doFilter(ServletRequest rawRequest, ServletResponse rawResponse, FilterChain chain)
      throws IOException, ServletException {
    var request = (HttpServletRequest) rawRequest;
    var response = (HttpServletResponse) rawResponse;
    String cookie = null;
    if (request.getCookies() != null)
      for (Cookie candidate : request.getCookies())
        if (settings.cookie.equals(candidate.getName())) cookie = candidate.getValue();
    if (cookie == null
        || request.getRequestURI().startsWith("/api/resource/")
        || request.getRequestURI().equals("/logout/backchannel")) {
      chain.doFilter(request, response);
      return;
    }
    String key = settings.namespace + ":request:" + digest(cookie),
        owner = UUID.randomUUID().toString();
    try {
      if (!Boolean.TRUE.equals(
          redis.opsForValue().setIfAbsent(key, owner, Duration.ofSeconds(60)))) {
        response.setStatus(409);
        response.setHeader("Retry-After", "1");
        return;
      }
    } catch (RuntimeException unavailable) {
      response.setStatus(503);
      return;
    }
    try {
      chain.doFilter(request, response);
    } finally {
      try {
        redis.execute(RELEASE, List.of(key), owner);
      } catch (RuntimeException ignored) {
        /* Lease expires; never delete another owner's lock. */
      }
    }
  }

  private static String digest(String value) {
    try {
      return HexFormat.of()
          .formatHex(
              MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
    } catch (Exception e) {
      throw new IllegalStateException("Digest unavailable");
    }
  }
}
