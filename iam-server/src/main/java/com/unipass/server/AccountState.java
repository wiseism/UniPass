package com.unipass.server;

import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;

@Service
public class AccountState {
  @org.springframework.beans.factory.annotation.Value("${unipass.feishu.enabled:false}")
  private boolean feishuEnabled;

  private final JdbcTemplate jdbc;
  private final RedisSecurityState security;

  public AccountState(JdbcTemplate jdbc, RedisSecurityState security) {
    this.jdbc = jdbc;
    this.security = security;
  }

  public record Snapshot(
      UUID id, String directoryId, String type, long epoch, boolean active, boolean mustChange) {}

  public Snapshot byEmployee(String employee) {
    security.requireReady();
    List<Snapshot> rows =
        jdbc.query(
            "SELECT * FROM iam_user WHERE employee_no=?",
            (r, n) ->
                new Snapshot(
                    r.getObject("id", UUID.class),
                    r.getString("directory_id"),
                    r.getString("directory_type"),
                    r.getLong("auth_epoch"),
                    "ACTIVE".equals(r.getString("status"))
                        && "OPEN".equals(r.getString("password_gate")),
                    r.getBoolean("must_change_password")),
            employee);
    return rows.isEmpty() ? null : rows.get(0);
  }

  public boolean allowed(UUID id, long epoch) {
    var observed = security.current();
    return Boolean.TRUE.equals(
        jdbc.queryForObject(
            "SELECT EXISTS(SELECT 1 FROM iam_user WHERE id=? AND status='ACTIVE' AND password_gate='OPEN' AND auth_epoch=? AND EXISTS(SELECT 1 FROM auth_runtime_state WHERE singleton AND redis_generation=?::uuid AND redis_run_id=?))",
            Boolean.class,
            id,
            epoch,
            observed.generation(),
            observed.runId()));
  }

  public boolean mustChange(UUID id) {
    return Boolean.TRUE.equals(
        jdbc.queryForObject(
            "SELECT must_change_password FROM iam_user WHERE id=?", Boolean.class, id));
  }

  public boolean federatedAllowed(UUID id, long epoch) {
    if (!feishuEnabled) return false;
    return Boolean.TRUE.equals(
        jdbc.queryForObject(
            """
                SELECT EXISTS(SELECT 1 FROM feishu_binding b,feishu_connector c,feishu_capability p
                WHERE c.singleton AND c.enabled AND b.tenant_key=c.tenant_key AND b.user_id=? AND b.bound_epoch=?
                AND p.capability='LOGIN' AND p.state='VERIFIED' AND p.verified_at<=clock_timestamp() AND p.valid_until>clock_timestamp())
                """,
            Boolean.class,
            id,
            epoch));
  }

  public boolean allowed(IdentityPrincipal principal) {
    return allowed(principal.getUserId(), principal.getEpoch())
        && loginAllowed(principal.getUserId(), principal.getEpoch(), principal.getLoginId())
        && (principal.getAuthenticationMethod() != IdentityPrincipal.Method.FEISHU
            || federatedAllowed(principal.getUserId(), principal.getEpoch()));
  }

  public void lockAndRequire(IdentityPrincipal principal) {
    lockAndRequire(principal.getUserId(), principal.getEpoch());
    if (!loginAllowed(principal.getUserId(), principal.getEpoch(), principal.getLoginId()))
      throw new BadCredentialsException("Login unavailable");
    if (principal.getAuthenticationMethod() == IdentityPrincipal.Method.FEISHU
        && !federatedAllowed(principal.getUserId(), principal.getEpoch()))
      throw new BadCredentialsException("Federated binding unavailable");
  }

  public IdentityPrincipal registerLogin(IdentityPrincipal principal) {
    jdbc.update(
        "INSERT INTO iam_login(id,user_id,auth_epoch,authenticated_at,last_access_at,authentication_method) VALUES (?,?,?,?,?,?)",
        principal.getLoginId(),
        principal.getUserId(),
        principal.getEpoch(),
        java.sql.Timestamp.from(principal.getAuthenticatedAt()),
        java.sql.Timestamp.from(principal.getAuthenticatedAt()),
        principal.getAuthenticationMethod().name());
    return principal;
  }

  public boolean loginAllowed(UUID user, long epoch, UUID login) {
    return login != null
        && Boolean.TRUE.equals(
            jdbc.queryForObject(
                """
                SELECT EXISTS(SELECT 1 FROM iam_login WHERE id=? AND user_id=? AND auth_epoch=? AND revoked_at IS NULL)
                """,
                Boolean.class,
                login,
                user,
                epoch));
  }

  public boolean backchannelRequiresReauthentication(IdentityPrincipal principal, String client) {
    return Boolean.TRUE.equals(
        jdbc.queryForObject(
            "SELECT EXISTS(SELECT 1 FROM oidc_logout_task WHERE user_id=? AND client_id=? AND login_authenticated_at=?)",
            Boolean.class,
            principal.getUserId(),
            client,
            java.sql.Timestamp.from(principal.getAuthenticatedAt())));
  }

  public void lockAndRequire(UUID id, long epoch) {
    var observed = security.current();
    List<Boolean> rows =
        jdbc.query(
            "SELECT status='ACTIVE' AND password_gate='OPEN' AND auth_epoch=? AND EXISTS(SELECT 1 FROM auth_runtime_state WHERE singleton AND redis_generation=?::uuid AND redis_run_id=?) FROM iam_user WHERE id=? FOR UPDATE",
            (r, n) -> r.getBoolean(1),
            epoch,
            observed.generation(),
            observed.runId(),
            id);
    if (rows.isEmpty() || !rows.get(0)) throw new BadCredentialsException("Account unavailable");
  }

  public List<String> roles(UUID id) {
    List<String> roles =
        new ArrayList<>(
            jdbc.queryForList("SELECT role FROM iam_user_role WHERE user_id=?", String.class, id));
    roles.add("ROLE_USER");
    return roles;
  }

  public void audit(UUID user, String action) {
    audit(user, action, null);
  }

  public void audit(UUID user, String action, UUID login) {
    jdbc.update(
        "INSERT INTO auth_audit(id,user_id,action,trace_id,login_id) VALUES (?,?,?,?,?)",
        UUID.randomUUID(),
        user,
        action,
        UUID.randomUUID(),
        login);
  }

  public boolean recoveryStatusAllowed(IdentityPrincipal principal, String operationId) {
    return recoveryStatusAllowed(principal, operationId, false);
  }

  public boolean recoveryRequestStatusAllowed(IdentityPrincipal principal, String key) {
    return recoveryStatusAllowed(principal, key, true);
  }

  private boolean recoveryStatusAllowed(
      IdentityPrincipal principal, String value, boolean requestKey) {
    if (!loginAllowed(principal.getUserId(), principal.getEpoch(), principal.getLoginId()))
      return false;
    var observed = security.current();
    String selector = requestKey ? "p.idempotency_key=?" : "p.id=?::uuid";
    return Boolean.TRUE.equals(
        jdbc.queryForObject(
            "SELECT EXISTS(SELECT 1 FROM password_operation p JOIN iam_user u ON u.id=p.user_id WHERE "
                + selector
                + " AND u.id=? AND u.status='ACTIVE' AND u.auth_epoch=p.fenced_epoch AND p.fenced_epoch=? AND EXISTS(SELECT 1 FROM auth_runtime_state WHERE singleton AND redis_generation=?::uuid AND redis_run_id=?))",
            Boolean.class,
            value,
            principal.getUserId(),
            principal.getEpoch() + 1,
            observed.generation(),
            observed.runId()));
  }
}
