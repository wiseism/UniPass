package com.unipass.server;

import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.Clock;
import java.util.*;
import org.springframework.boot.*;
import org.springframework.core.env.Environment;
import org.springframework.data.redis.core.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/** PG is the durable authority. Redis marker + process run_id must agree before authentication. */
@Service
public final class RedisSecurityState implements ApplicationRunner {
  private final JdbcTemplate jdbc;
  private final TransactionTemplate tx;
  private final StringRedisTemplate redis;
  private final Clock clock;
  private final String key;

  public RedisSecurityState(
      JdbcTemplate jdbc,
      TransactionTemplate tx,
      StringRedisTemplate redis,
      Clock clock,
      Environment env) {
    this.jdbc = jdbc;
    this.tx = tx;
    this.redis = redis;
    this.clock = clock;
    this.key = env.getProperty("unipass.security.generation-key", "unipass:security:generation");
    if (key.isBlank() || key.length() > 200)
      throw new IllegalArgumentException("Invalid Redis generation key");
  }

  public record Observed(String generation, String runId) {}

  public Observed current() {
    Observed observed = observe();
    try {
      if (observed.generation == null
          || !UUID.fromString(observed.generation).toString().equals(observed.generation))
        throw new IllegalArgumentException();
    } catch (RuntimeException e) {
      throw new AuthenticationServiceException("Authentication state unavailable");
    }
    return observed;
  }

  private Observed observe() {
    try {
      return redis.execute(
          (RedisCallback<Observed>)
              connection -> {
                byte[] marker =
                    connection.stringCommands().get(key.getBytes(StandardCharsets.UTF_8));
                Properties info = connection.serverCommands().info("server");
                String run = info == null ? null : info.getProperty("run_id");
                if (run == null || !run.matches("[A-Za-z0-9_-]{16,100}"))
                  throw new AuthenticationServiceException("Redis process identity unavailable");
                return new Observed(
                    marker == null ? null : new String(marker, StandardCharsets.UTF_8), run);
              });
    } catch (RuntimeException e) {
      throw new AuthenticationServiceException("Authentication state unavailable");
    }
  }

  public void requireReady() {
    Observed observed = current();
    if (!Boolean.TRUE.equals(
        jdbc.queryForObject(
            "SELECT EXISTS(SELECT 1 FROM auth_runtime_state WHERE singleton AND redis_generation=?::uuid AND redis_run_id=?)",
            Boolean.class,
            observed.generation,
            observed.runId)))
      throw new AuthenticationServiceException("Authentication recovery required");
  }

  /**
   * Holding the singleton lock serializes recovery across instances; Redis writes precede PG
   * commit. Any lost reply or PG rollback leaves a mismatch, which remains denied until a later
   * recovery.
   */
  public boolean recoverIfNeeded() {
    return Boolean.TRUE.equals(
        tx.execute(
            status -> {
              var expected =
                  jdbc.queryForObject(
                      "SELECT redis_generation,redis_run_id FROM auth_runtime_state WHERE singleton FOR UPDATE",
                      (r, n) ->
                          new Observed(r.getObject(1, UUID.class).toString(), r.getString(2)));
              if (expected == null)
                throw new IllegalStateException("Authentication runtime state missing");
              Observed observed = observe();
              if (expected.equals(observed)) return false;
              UUID generation = UUID.randomUUID();
              // A blocked password operation already fenced its old credentials. Preserve its epoch
              // so a later evidence-based recovery can reopen exactly that operation's gate.
              int accounts =
                  jdbc.update(
                      "WITH targets AS MATERIALIZED (SELECT id FROM iam_user WHERE status='ACTIVE' AND password_gate='OPEN' ORDER BY id FOR UPDATE) UPDATE iam_user u SET auth_epoch=u.auth_epoch+1 FROM targets t WHERE u.id=t.id");
              int families =
                  jdbc.update("UPDATE oauth2_authorization SET revoked=true WHERE revoked=false");
              Timestamp now = Timestamp.from(clock.instant());
              jdbc.update(
                  "UPDATE auth_runtime_state SET redis_generation=?,redis_run_id=?,recovered_at=? WHERE singleton",
                  generation,
                  observed.runId,
                  now);
              jdbc.update(
                  "INSERT INTO auth_runtime_recovery(id,generation,previous_generation,redis_run_id,affected_accounts,revoked_families,recovered_at) VALUES (?,?,?,?,?,?,?)",
                  UUID.randomUUID(),
                  generation,
                  UUID.fromString(expected.generation),
                  observed.runId,
                  accounts,
                  families,
                  now);
              redis.opsForValue().set(key, generation.toString());
              // Detect a reconnect/restart during the Redis side effect. Rollback remains
              // fail-closed.
              if (!new Observed(generation.toString(), observed.runId).equals(observe()))
                throw new AuthenticationServiceException("Redis changed during recovery");
              return true;
            }));
  }

  @Override
  public void run(ApplicationArguments args) {
    recoverIfNeeded();
  }

  String generationKey() {
    return key;
  }
}
