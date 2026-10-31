package com.unipass.server;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/** Durable notification: only a confirmed HTTP 200 finishes the owned lease. */
@Service
public final class BackchannelLogoutWorker {
  private final JdbcTemplate jdbc;
  private final TransactionTemplate tx;
  private final JwtEncoder encoder;
  private final Clock clock;
  private final String issuer, kid;
  private final HttpClient http =
      HttpClient.newBuilder()
          .connectTimeout(Duration.ofSeconds(2))
          .followRedirects(HttpClient.Redirect.NEVER)
          .build();

  private record Task(
      UUID id, UUID user, String client, String uri, String sid, int attempts, UUID lease) {}

  public BackchannelLogoutWorker(
      JdbcTemplate jdbc,
      TransactionTemplate tx,
      JWKSource<SecurityContext> keys,
      Clock clock,
      Environment env) {
    this.jdbc = jdbc;
    this.tx = tx;
    this.encoder = new NimbusJwtEncoder(keys);
    this.clock = clock;
    issuer = env.getRequiredProperty("unipass.issuer");
    kid = env.getRequiredProperty("unipass.signing.alias");
  }

  public boolean runOnce() {
    Task task =
        tx.execute(
            status -> {
              jdbc.update(
                  "UPDATE oidc_logout_task SET state='DEAD',finished_at=? WHERE state='RUNNING' AND lease_until<=? AND attempts>=5",
                  java.sql.Timestamp.from(clock.instant()),
                  java.sql.Timestamp.from(clock.instant()));
              var rows =
                  jdbc.query(
                      "SELECT * FROM oidc_logout_task WHERE attempts<5 AND ((state='PENDING' AND next_attempt_at<=?) OR (state='RUNNING' AND lease_until<=?)) ORDER BY created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED",
                      (r, n) ->
                          new Task(
                              r.getObject("id", UUID.class),
                              r.getObject("user_id", UUID.class),
                              r.getString("client_id"),
                              r.getString("target_uri"),
                              r.getString("sid"),
                              r.getInt("attempts") + 1,
                              UUID.randomUUID()),
                      java.sql.Timestamp.from(clock.instant()),
                      java.sql.Timestamp.from(clock.instant()));
              if (rows.isEmpty()) return null;
              Task claimed = rows.get(0);
              jdbc.update(
                  "UPDATE oidc_logout_task SET state='RUNNING',attempts=?,lease_token=?,lease_until=? WHERE id=?",
                  claimed.attempts,
                  claimed.lease,
                  java.sql.Timestamp.from(clock.instant().plusSeconds(30)),
                  claimed.id);
              return claimed;
            });
    if (task == null) return false;
    boolean delivered = false;
    try {
      Instant now = clock.instant();
      String token =
          encoder
              .encode(
                  JwtEncoderParameters.from(
                      JwsHeader.with(SignatureAlgorithm.RS256)
                          .keyId(kid)
                          .type("logout+jwt")
                          .build(),
                      JwtClaimsSet.builder()
                          .issuer(issuer)
                          .subject(task.user.toString())
                          .audience(List.of(task.client))
                          .issuedAt(now)
                          .expiresAt(now.plusSeconds(120))
                          .id(UUID.randomUUID().toString())
                          .claim("sid", task.sid)
                          .claim(
                              "events",
                              Map.of(
                                  "http://schemas.openid.net/event/backchannel-logout", Map.of()))
                          .build()))
              .getTokenValue();
      var request =
          HttpRequest.newBuilder(URI.create(task.uri))
              .timeout(Duration.ofSeconds(3))
              .header("Content-Type", "application/x-www-form-urlencoded")
              .POST(
                  HttpRequest.BodyPublishers.ofString(
                      "logout_token=" + URLEncoder.encode(token, StandardCharsets.UTF_8)))
              .build();
      // Bound completion of the whole response, including a stalled response body.
      var pending = http.sendAsync(request, HttpResponse.BodyHandlers.discarding());
      try {
        delivered = pending.get(3, TimeUnit.SECONDS).statusCode() == 200;
      } finally {
        if (!pending.isDone()) pending.cancel(true);
      }
    } catch (InterruptedException interrupted) {
      Thread.currentThread().interrupt();
    } catch (Exception ignored) {
      /* No credential or remote response enters logs. */
    }
    Instant now = clock.instant();
    String state = delivered ? "SENT" : task.attempts >= 5 ? "DEAD" : "PENDING";
    jdbc.update(
        "UPDATE oidc_logout_task SET state=?,next_attempt_at=?,finished_at=?,lease_token=NULL,lease_until=NULL WHERE id=? AND state='RUNNING' AND lease_token=?",
        state,
        java.sql.Timestamp.from(
            now.plusSeconds(
                (1L << task.attempts)
                    + java.util.concurrent.ThreadLocalRandom.current().nextLong(3))),
        state.equals("PENDING") ? null : java.sql.Timestamp.from(now),
        task.id,
        task.lease);
    return true;
  }
}
