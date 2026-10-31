package com.unipass.server;

import static org.junit.jupiter.api.Assertions.*;

import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import java.nio.file.*;
import java.util.UUID;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

class LoginMigrationIT {
  @Test
  void upgradeFencesLegacyGrantsButPreservesAnUnknownPasswordOperation() throws Exception {
    System.setProperty(
        "ot.epg.working-dir",
        Files.createDirectories(Path.of("target", "login-migration", "postgres"))
            .toAbsolutePath()
            .toString());
    try (var pg =
        EmbeddedPostgres.builder()
            .setPort(0)
            .setServerConfig("listen_addresses", "127.0.0.1")
            .start()) {
      var data = pg.getPostgresDatabase();
      var jdbc = new JdbcTemplate(data);
      Flyway.configure().dataSource(data).target("11").load().migrate();
      UUID open = UUID.randomUUID(), blocked = UUID.randomUUID(), operation = UUID.randomUUID();
      jdbc.update("INSERT INTO import_source(source_id,cursor_value) VALUES ('migration','1')");
      for (UUID id : new UUID[] {open, blocked})
        jdbc.update(
            "INSERT INTO iam_user(id,employee_no,directory_id,directory_type,ldap_dn,display_name,status,source_id,source_version,auth_epoch) VALUES (?,?,?,'OPENLDAP','uid=test','Test','ACTIVE','migration',1,7)",
            id,
            id.toString(),
            id);
      jdbc.update("UPDATE iam_user SET password_gate='BLOCKED' WHERE id=?", blocked);
      jdbc.update(
          "INSERT INTO password_operation(id,user_id,idempotency_key,state,operation_type,fenced_epoch,lease_until,created_at) VALUES (?,?,'unknown-test','UNKNOWN','CHANGE',7,now()-interval '1 minute',now())",
          operation,
          blocked);
      for (UUID id : new UUID[] {open, blocked}) {
        String family = UUID.randomUUID().toString();
        jdbc.update(
            "INSERT INTO oauth2_authorization(id,registered_client_id,principal_name,authorization_grant_type) VALUES (?,'fixture',?,'authorization_code')",
            family,
            id.toString());
        jdbc.update(
            "INSERT INTO oidc_rp_session(authorization_id,user_id,client_id,target_uri,sid,login_authenticated_at) VALUES (?,?,'fixture','https://rp.example/backchannel',?,now())",
            family,
            id,
            family);
      }
      Flyway.configure().dataSource(data).load().migrate();
      assertEquals(
          8L, jdbc.queryForObject("SELECT auth_epoch FROM iam_user WHERE id=?", Long.class, open));
      assertEquals(
          7L,
          jdbc.queryForObject("SELECT auth_epoch FROM iam_user WHERE id=?", Long.class, blocked));
      assertEquals(
          "BLOCKED",
          jdbc.queryForObject(
              "SELECT password_gate FROM iam_user WHERE id=?", String.class, blocked));
      assertEquals(
          7L,
          jdbc.queryForObject(
              "SELECT fenced_epoch FROM password_operation WHERE id=? AND state='UNKNOWN'",
              Long.class,
              operation));
      assertEquals(
          2,
          jdbc.queryForObject(
              "SELECT count(*) FROM oauth2_authorization WHERE revoked", Integer.class));
      assertEquals(
          2,
          jdbc.queryForObject(
              "SELECT count(*) FROM oidc_logout_task WHERE state='PENDING'", Integer.class));
      assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM iam_login", Integer.class));
      Flyway.configure().dataSource(data).load().migrate();
      assertEquals(
          8L, jdbc.queryForObject("SELECT auth_epoch FROM iam_user WHERE id=?", Long.class, open));
    }
  }
}
