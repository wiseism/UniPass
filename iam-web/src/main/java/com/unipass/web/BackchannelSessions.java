package com.unipass.web;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.*;
import java.util.*;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

/** Durable sid tombstones prevent a late callback or restored session from resurrecting logout. */
@Service
public final class BackchannelSessions {
  static final String EVENT = "http://schemas.openid.net/event/backchannel-logout";
  private final StringRedisTemplate redis;
  private final RpSettings settings;
  private final JwtDecoder decoder;
  private static final DefaultRedisScript<Long> BIND =
      new DefaultRedisScript<>(
          "if redis.call('exists',KEYS[1])==1 then return 0 end redis.call('hset',KEYS[2],ARGV[1],ARGV[2]); redis.call('expire',KEYS[2],90000); return 1",
          Long.class);
  private static final DefaultRedisScript<Long> LOGOUT =
      new DefaultRedisScript<>(
          "if redis.call('exists',KEYS[1])==1 then return 0 end "
              + "local bindings=redis.call('hgetall',KEYS[2]); "
              + "for i=1,#bindings,2 do if ARGV[1]~='' and bindings[i+1]~=ARGV[1] then return -1 end end "
              + "redis.call('set',KEYS[1],'used','EX',240); redis.call('set',KEYS[3],'revoked','EX',90000); "
              + "for i=1,#bindings,2 do redis.call('del',ARGV[2]..bindings[i]) end redis.call('del',KEYS[2]); return 1",
          Long.class);

  public BackchannelSessions(StringRedisTemplate redis, RpSettings settings) {
    this.redis = redis;
    this.settings = settings;
    var signed =
        NimbusJwtDecoder.withJwkSetUri(settings.issuer + "/oauth/jwks")
            .restOperations(RpConfiguration.http())
            .validateType(false)
            .build();
    signed.setJwtValidator(JwtValidators.createDefaultWithIssuer(settings.issuer));
    decoder = signed;
  }

  private String sidKey(String sid) {
    return settings.namespace + ":oidc-sid:" + digest(sid);
  }

  private String revokedKey(String sid) {
    return settings.namespace + ":revoked-sid:" + digest(sid);
  }

  public boolean bind(String session, OidcUser user) {
    String sid = user.getIdToken().getClaimAsString("sid");
    if (sid == null || sid.isBlank() || sid.length() > 200) return false;
    return Long.valueOf(1)
        .equals(
            redis.execute(BIND, List.of(revokedKey(sid), sidKey(sid)), session, user.getSubject()));
  }

  public boolean active(OidcUser user) {
    String sid = user.getIdToken().getClaimAsString("sid");
    return sid != null && !Boolean.TRUE.equals(redis.hasKey(revokedKey(sid)));
  }

  public void accept(String raw) {
    if (raw == null || raw.length() > 8192) throw new BadJwtException("Invalid logout token");
    Jwt jwt = decoder.decode(raw);
    validate(jwt, settings.id, Instant.now());
    String sid = jwt.getClaimAsString("sid");
    String sub = jwt.getSubject();
    Long result =
        redis.execute(
            LOGOUT,
            List.of(
                settings.namespace + ":logout-jti:" + digest(jwt.getId()),
                sidKey(sid),
                revokedKey(sid)),
            sub == null ? "" : sub,
            settings.namespace + ":sessions:");
    if (!Long.valueOf(1).equals(result))
      throw new BadJwtException("Logout replay or subject mismatch");
  }

  static void validate(Jwt jwt, String client, Instant now) {
    Object sid = jwt.getClaims().get("sid"),
        subject = jwt.getClaims().get("sub"),
        events = jwt.getClaims().get("events");
    if (!"logout+jwt".equals(jwt.getHeaders().get("typ"))
        || jwt.getAudience() == null
        || !jwt.getAudience().contains(client)
        || jwt.getId() == null
        || jwt.getId().isBlank()
        || jwt.getId().length() > 200
        || !(sid instanceof String session)
        || session.isBlank()
        || session.length() > 200
        || subject != null
            && (!(subject instanceof String sub) || sub.isBlank() || sub.length() > 200)
        || jwt.getClaims().containsKey("nonce")
        || !(events instanceof Map<?, ?> map)
        || map.size() != 1
        || !(map.get(EVENT) instanceof Map<?, ?> detail)
        || !detail.isEmpty()
        || jwt.getIssuedAt() == null
        || jwt.getExpiresAt() == null
        || jwt.getIssuedAt().isAfter(now.plusSeconds(30))
        || jwt.getIssuedAt().isBefore(now.minusSeconds(180))
        || !jwt.getExpiresAt().isAfter(now)
        || !jwt.getExpiresAt().isAfter(jwt.getIssuedAt())
        || jwt.getExpiresAt().isAfter(jwt.getIssuedAt().plusSeconds(180)))
      throw new BadJwtException("Invalid logout token context");
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
