package com.unipass.web;

import java.net.URI;
import java.util.Set;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

@Component
public final class RpSettings {
  final String id, issuer, origin, secret, namespace, cookie;
  final boolean local;

  public RpSettings(Environment env) {
    id = env.getRequiredProperty("unipass.rp.id");
    issuer = env.getRequiredProperty("unipass.rp.issuer");
    origin = env.getRequiredProperty("unipass.rp.origin");
    secret = env.getRequiredProperty("unipass.rp.secret");
    if (!id.matches("[A-Za-z0-9_-]{3,60}") || !secret.matches("[\\x21-\\x7e]{32,64}"))
      throw new IllegalArgumentException("Invalid RP identity or secret");
    local = env.getProperty("unipass.rp.local-http", Boolean.class, false);
    if (local
        && !Set.of("127.0.0.1", "localhost", "::1").contains(env.getProperty("server.address", "")))
      throw new IllegalArgumentException("Local RP requires a loopback bind address");
    validate(issuer);
    validate(origin);
    namespace = "unipass:rp:" + id;
    cookie = "UNIPASS_RP_" + id;
  }

  private void validate(String value) {
    URI uri = URI.create(value);
    boolean loopback =
        local
            && "http".equals(uri.getScheme())
            && Set.of("localhost", "127.0.0.1", "[::1]").contains(uri.getHost());
    if (uri.getHost() == null
        || uri.getUserInfo() != null
        || uri.getQuery() != null
        || uri.getFragment() != null
        || uri.getRawPath() != null && !uri.getRawPath().isEmpty()
        || !("https".equals(uri.getScheme()) || loopback))
      throw new IllegalArgumentException("HTTPS origin without a path required");
  }

  @Override
  public String toString() {
    return "RpSettings[REDACTED]";
  }
}
