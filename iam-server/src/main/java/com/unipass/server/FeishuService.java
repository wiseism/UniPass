package com.unipass.server;

import java.net.URI;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

/** Single application/tenant boundary; no identity is inferred from email or employee number. */
@Service
public final class FeishuService {
  private final JdbcTemplate jdbc;
  private final TransactionTemplate tx;
  private final AccountState accounts;
  private final MfaService mfa;
  private final Clock clock;
  private final FeishuClient client;

  @Autowired
  public FeishuService(
      JdbcTemplate jdbc,
      TransactionTemplate tx,
      AccountState accounts,
      MfaService mfa,
      Clock clock,
      Environment env) {
    this(jdbc, tx, accounts, mfa, clock, configured(env, clock));
  }

  FeishuService(
      JdbcTemplate jdbc,
      TransactionTemplate tx,
      AccountState accounts,
      MfaService mfa,
      Clock clock,
      FeishuClient client) {
    this.jdbc = jdbc;
    this.tx = tx;
    this.accounts = accounts;
    this.mfa = mfa;
    this.clock = clock;
    this.client = client;
  }

  private static FeishuClient configured(Environment env, Clock clock) {
    if (!env.getProperty("unipass.feishu.enabled", Boolean.class, false)) return null;
    String callback = env.getRequiredProperty("UNIPASS_FEISHU_CALLBACK");
    URI uri = URI.create(callback), issuer = URI.create(env.getRequiredProperty("unipass.issuer"));
    if (!"https".equals(uri.getScheme())
        || uri.getHost() == null
        || !Objects.equals(uri.getRawAuthority(), issuer.getRawAuthority())
        || !"/api/connector/feishu/callback".equals(uri.getRawPath())
        || uri.getRawQuery() != null
        || uri.getRawFragment() != null
        || uri.getRawUserInfo() != null)
      throw new IllegalArgumentException("Fixed HTTPS IAM callback required");
    return new FeishuClient(
        env.getRequiredProperty("UNIPASS_FEISHU_APP_ID"),
        env.getRequiredProperty("UNIPASS_FEISHU_TENANT_KEY"),
        env.getRequiredProperty("UNIPASS_FEISHU_APP_SECRET"),
        callback,
        clock);
  }

  public record Start(String authorizationUrl) {
    @Override
    public String toString() {
      return "FeishuStart[REDACTED]";
    }
  }

  private record Attempt(String mode, UUID actor, Long epoch) {}

  private void ready() {
    if (client == null
        || !Boolean.TRUE.equals(
            jdbc.queryForObject(
                """
                SELECT EXISTS(SELECT 1 FROM feishu_connector c,feishu_capability p WHERE c.singleton AND c.enabled
                AND c.app_id=? AND c.tenant_key=? AND p.capability='LOGIN' AND p.state='VERIFIED'
                AND p.verified_at<=clock_timestamp() AND p.valid_until>clock_timestamp())
                """,
                Boolean.class,
                client.app(),
                client.tenant())))
      throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Connector not verified");
  }

  private void strong(IdentityPrincipal principal) {
    if (principal == null
        || !principal.hasRecentPassword(clock.instant())
        || accounts.mustChange(principal.getUserId())
        || mfa.recoveryRequired(principal.getUserId()))
      throw new ResponseStatusException(
          HttpStatus.FORBIDDEN, "Recent password authentication required");
    mfa.requireStrong(principal);
  }

  public Start start(boolean binding, IdentityPrincipal principal, String session, String ip) {
    ready();
    if (binding) strong(principal);
    else if (principal != null)
      throw new ResponseStatusException(HttpStatus.CONFLICT, "Use explicit binding");
    byte[] bytes = new byte[32];
    new SecureRandom().nextBytes(bytes);
    String state = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    tx.executeWithoutResult(
        ignored -> {
          String address = DigestAuthorizationService.digest(ip),
              browser = DigestAuthorizationService.digest(session);
          jdbc.queryForList("SELECT pg_advisory_xact_lock(hashtextextended(?,120))", browser);
          jdbc.queryForList("SELECT pg_advisory_xact_lock(hashtextextended(?,119))", address);
          if (jdbc.queryForObject(
                      "SELECT count(*) FROM feishu_flow WHERE created_at>clock_timestamp()-interval '5 minutes' AND (ip_digest=? OR session_digest=?)",
                      Integer.class,
                      address,
                      browser)
                  >= 20
              || jdbc.queryForObject(
                      "SELECT count(*) FROM feishu_flow WHERE created_at>clock_timestamp()-interval '5 minutes' AND session_digest=?",
                      Integer.class,
                      browser)
                  >= 5)
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Flow rate limited");
          if (binding) accounts.lockAndRequire(principal);
          jdbc.update(
              "INSERT INTO feishu_flow(state_digest,session_digest,ip_digest,mode,actor_id,actor_epoch,expires_at) VALUES (?,?,?,?,?,?,clock_timestamp()+interval '5 minutes')",
              DigestAuthorizationService.digest(state),
              browser,
              address,
              binding ? "BIND" : "LOGIN",
              binding ? principal.getUserId() : null,
              binding ? principal.getEpoch() : null);
        });
    return new Start(client.authorization(state));
  }

  public IdentityPrincipal callback(
      String state, String code, String error, IdentityPrincipal principal, String session) {
    ready();
    if (state == null || !state.matches("[A-Za-z0-9_-]{43}")) throw rejected();
    if (error != null && code != null
        || error == null
            && (code == null
                || code.isEmpty()
                || code.length() > 2048
                || code.chars().anyMatch(c -> c < 0x21 || c > 0x7e))) throw rejected();
    Attempt attempt =
        tx.execute(
            ignored -> {
              var rows =
                  jdbc.query(
                      "SELECT mode,actor_id,actor_epoch FROM feishu_flow WHERE state_digest=? AND session_digest=? AND consumed_at IS NULL AND expires_at>clock_timestamp() FOR UPDATE",
                      (r, n) ->
                          new Attempt(
                              r.getString(1), r.getObject(2, UUID.class), (Long) r.getObject(3)),
                      DigestAuthorizationService.digest(state),
                      DigestAuthorizationService.digest(session));
              if (rows.size() != 1) throw rejected();
              var found = rows.get(0);
              if (found.mode.equals("LOGIN") && principal != null
                  || found.mode.equals("BIND")
                      && (principal == null
                          || !found.actor.equals(principal.getUserId())
                          || found.epoch != principal.getEpoch())) throw rejected();
              jdbc.update(
                  "UPDATE feishu_flow SET consumed_at=clock_timestamp() WHERE state_digest=?",
                  DigestAuthorizationService.digest(state));
              if (error == null
                  && jdbc.update(
                          "INSERT INTO feishu_code_use(code_digest) VALUES (?) ON CONFLICT DO NOTHING",
                          DigestAuthorizationService.digest(
                              "feishu-code:" + client.app() + ":" + code))
                      != 1)
                return null; // Burn this state even when another browser already consumed the code.
              return found;
            });
    if (attempt == null || error != null) throw rejected();
    FeishuClient.Identity external;
    try {
      external = client.exchange(code, state);
    } catch (FeishuClient.Failure failure) {
      audit(attempt.actor, "FEISHU_EXCHANGE_FAILED");
      throw new ResponseStatusException(
          HttpStatus.valueOf(failure.status()), "Identity exchange failed");
    }
    try {
      return tx.execute(
          ignored -> {
            ready();
            if (attempt.mode.equals("BIND")) {
              strong(principal);
              accounts.lockAndRequire(principal);
              var existing =
                  jdbc.queryForList(
                      "SELECT user_id,tenant_key,open_id FROM feishu_binding WHERE user_id=? OR (tenant_key=? AND open_id=?) FOR UPDATE",
                      principal.getUserId(),
                      external.tenant(),
                      external.openId());
              if (existing.stream()
                  .anyMatch(
                      row ->
                          !principal.getUserId().equals(row.get("user_id"))
                              || !external.tenant().equals(row.get("tenant_key"))
                              || !external.openId().equals(row.get("open_id"))))
                throw new ResponseStatusException(HttpStatus.CONFLICT, "Explicit unlink required");
              int written =
                  jdbc.update(
                      """
                            INSERT INTO feishu_binding(tenant_key,open_id,user_id,bound_epoch) VALUES (?,?,?,?)
                            ON CONFLICT(tenant_key,open_id) DO UPDATE SET bound_epoch=excluded.bound_epoch,confirmed_at=clock_timestamp()
                            WHERE feishu_binding.user_id=excluded.user_id
                            """,
                      external.tenant(),
                      external.openId(),
                      principal.getUserId(),
                      principal.getEpoch());
              if (written != 1)
                throw new ResponseStatusException(HttpStatus.CONFLICT, "Binding unavailable");
              audit(principal.getUserId(), "FEISHU_BINDING_CONFIRMED");
              return null;
            }
            var users =
                jdbc.queryForList(
                    "SELECT user_id,bound_epoch FROM feishu_binding WHERE tenant_key=? AND open_id=?",
                    external.tenant(),
                    external.openId());
            if (users.size() != 1) throw rejected();
            UUID user = (UUID) users.get(0).get("user_id");
            long epoch = ((Number) users.get(0).get("bound_epoch")).longValue();
            accounts.lockAndRequire(user, epoch);
            if (!accounts.federatedAllowed(user, epoch)
                || accounts.mustChange(user)
                || mfa.recoveryRequired(user)) throw rejected();
            var result =
                new IdentityPrincipal(
                    user,
                    epoch,
                    clock.instant(),
                    accounts.roles(user),
                    null,
                    IdentityPrincipal.Method.FEISHU,
                    null);
            accounts.registerLogin(result);
            accounts.audit(user, "FEISHU_LOGIN_SUCCESS");
            return result;
          });
    } catch (org.springframework.dao.DuplicateKeyException conflict) {
      throw new ResponseStatusException(HttpStatus.CONFLICT, "Binding unavailable");
    } catch (org.springframework.security.authentication.BadCredentialsException stale) {
      throw rejected();
    }
  }

  public void unlink(IdentityPrincipal principal) {
    strong(principal);
    tx.executeWithoutResult(
        ignored -> {
          accounts.lockAndRequire(principal);
          if (jdbc.update("DELETE FROM feishu_binding WHERE user_id=?", principal.getUserId())
              > 0) {
            jdbc.update(
                "UPDATE iam_user SET auth_epoch=auth_epoch+1 WHERE id=?", principal.getUserId());
            audit(principal.getUserId(), "FEISHU_BINDING_REMOVED");
          }
        });
  }

  public int cleanup() {
    return tx.execute(
        ignored -> {
          int count =
              jdbc.update(
                  "DELETE FROM feishu_flow WHERE state_digest IN (SELECT state_digest FROM feishu_flow WHERE created_at<clock_timestamp()-interval '1 day' LIMIT 100)");
          return count
              + jdbc.update(
                  "DELETE FROM feishu_code_use WHERE code_digest IN (SELECT code_digest FROM feishu_code_use WHERE consumed_at<clock_timestamp()-interval '1 day' LIMIT 100)");
        });
  }

  private void audit(UUID user, String action) {
    jdbc.update(
        "INSERT INTO feishu_audit(id,user_id,action) VALUES (?,?,?)",
        UUID.randomUUID(),
        user,
        action);
  }

  private static ResponseStatusException rejected() {
    return new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Flow or binding unavailable");
  }
}
