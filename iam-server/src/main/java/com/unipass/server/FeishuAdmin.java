package com.unipass.server;

import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionTemplate;

/** Trusted database operator records evidence; this tool does not certify a remote tenant. */
public final class FeishuAdmin {
  private final JdbcTemplate jdbc;
  private final TransactionTemplate tx;

  public FeishuAdmin(JdbcTemplate jdbc, TransactionTemplate tx) {
    this.jdbc = jdbc;
    this.tx = tx;
  }

  public void configure(String app, String tenant, String operator, String evidence) {
    if (app == null
        || !app.matches("[A-Za-z0-9_-]{3,128}")
        || tenant == null
        || !tenant.matches("[A-Za-z0-9_-]{1,128}"))
      throw new IllegalArgumentException("Invalid connector identity");
    checked(operator, evidence);
    tx.executeWithoutResult(
        ignored -> {
          jdbc.update(
              "INSERT INTO feishu_connector(singleton,app_id,tenant_key) VALUES (true,?,?) ON CONFLICT DO NOTHING",
              app,
              tenant);
          if (!Boolean.TRUE.equals(
              jdbc.queryForObject(
                  "SELECT app_id=? AND tenant_key=? FROM feishu_connector WHERE singleton FOR UPDATE",
                  Boolean.class,
                  app,
                  tenant))) throw new IllegalArgumentException("Connector identity cannot change");
          audit("FEISHU_CONFIGURED", operator, evidence);
        });
  }

  public void recordLoginVerification(String operator, String evidence) {
    checked(operator, evidence);
    tx.executeWithoutResult(
        ignored -> {
          if (jdbc.queryForList("SELECT singleton FROM feishu_connector FOR UPDATE").size() != 1)
            throw new IllegalStateException("Configure connector first");
          jdbc.update(
              "UPDATE feishu_capability SET state='VERIFIED',verified_at=statement_timestamp(),valid_until=statement_timestamp()+interval '7 days',evidence_ref=? WHERE capability='LOGIN'",
              evidence);
          jdbc.update("UPDATE feishu_connector SET enabled=true WHERE singleton");
          audit("FEISHU_LOGIN_EVIDENCE_RECORDED", operator, evidence);
        });
  }

  public void disable(String operator, String evidence) {
    checked(operator, evidence);
    tx.executeWithoutResult(
        ignored -> {
          if (jdbc.update("UPDATE feishu_connector SET enabled=false WHERE singleton") != 1)
            throw new IllegalStateException("Configure connector first");
          audit("FEISHU_DISABLED", operator, evidence);
        });
  }

  public Map<String, Object> report() {
    var capabilities =
        jdbc.queryForList(
            "SELECT capability,state,permissions,official_url,verified_at::text,valid_until::text,evidence_ref,(state='VERIFIED' AND verified_at<=clock_timestamp() AND valid_until>clock_timestamp()) AS current FROM feishu_capability ORDER BY capability");
    return Map.of(
        "connector",
        jdbc.queryForList("SELECT app_id,tenant_key,enabled FROM feishu_connector"),
        "capabilities",
        capabilities,
        "binding_count",
        jdbc.queryForObject("SELECT count(*) FROM feishu_binding", Long.class));
  }

  private static void checked(String operator, String evidence) {
    if (operator == null
        || operator.isBlank()
        || operator.length() > 200
        || evidence == null
        || evidence.isBlank()
        || evidence.length() > 500
        || operator.chars().anyMatch(Character::isISOControl)
        || evidence.chars().anyMatch(Character::isISOControl))
      throw new IllegalArgumentException("Operator and evidence reference required");
  }

  private void audit(String action, String operator, String evidence) {
    jdbc.update(
        "INSERT INTO feishu_audit(id,action,operator_ref,evidence_ref) VALUES (?,?,?,?)",
        UUID.randomUUID(),
        action,
        operator,
        evidence);
  }
}
