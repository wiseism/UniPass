package com.unipass.server;

import static org.junit.jupiter.api.Assertions.*;

import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import java.nio.file.*;
import java.util.UUID;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

class BackchannelMigrationIT {
  @Test
  void upgradingV7FencesOldSessionsPreservesBlockedEpochAndInstallsTransactionalTriggers()
      throws Exception {
    System.setProperty(
        "ot.epg.working-dir",
        Files.createDirectories(Path.of("target", "backchannel-migration", "postgres"))
            .toAbsolutePath()
            .toString());
    try (var pg =
        EmbeddedPostgres.builder()
            .setPort(0)
            .setServerConfig("listen_addresses", "127.0.0.1")
            .start()) {
      var source = pg.getPostgresDatabase();
      var jdbc = new JdbcTemplate(source);
      Flyway.configure().dataSource(source).target("7").load().migrate();
      jdbc.update(
          "INSERT INTO import_source(source_id,cursor_value) VALUES ('migration-test','1')");
      UUID open = UUID.randomUUID(), blocked = UUID.randomUUID();
      for (UUID user : new UUID[] {open, blocked}) {
        jdbc.update(
            "INSERT INTO iam_user(id,employee_no,directory_id,directory_type,ldap_dn,display_name,status,source_id,source_version,auth_epoch,password_gate) VALUES (?,?,?,'OPENLDAP','uid=test','Test','ACTIVE','migration-test',1,10,?)",
            user,
            user.toString(),
            UUID.randomUUID(),
            user.equals(open) ? "OPEN" : "BLOCKED");
        jdbc.update(
            "INSERT INTO oauth2_authorization(id,registered_client_id,principal_name,authorization_grant_type) VALUES (?,'client',?,'authorization_code')",
            user.toString(),
            user.toString());
      }
      Flyway.configure().dataSource(source).target("8").load().migrate();
      assertEquals(
          11L, jdbc.queryForObject("SELECT auth_epoch FROM iam_user WHERE id=?", Long.class, open));
      assertEquals(
          10L,
          jdbc.queryForObject("SELECT auth_epoch FROM iam_user WHERE id=?", Long.class, blocked));
      assertEquals(
          2,
          jdbc.queryForObject(
              "SELECT count(*) FROM oauth2_authorization WHERE revoked", Integer.class));
      assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM oidc_logout_task", Integer.class));

      // Later migrations may deliberately fence logins again. Verify V8's
      // boundary above, then exercise its triggers on the current schema.
      Flyway.configure().dataSource(source).load().migrate();
      assertEquals(
          12L, jdbc.queryForObject("SELECT auth_epoch FROM iam_user WHERE id=?", Long.class, open));
      assertEquals(
          10L,
          jdbc.queryForObject("SELECT auth_epoch FROM iam_user WHERE id=?", Long.class, blocked));

      jdbc.update(
          "INSERT INTO oauth2_authorization(id,registered_client_id,principal_name,authorization_grant_type) VALUES ('fresh','client',?,'authorization_code')",
          open.toString());
      jdbc.update(
          "INSERT INTO oidc_rp_session(authorization_id,user_id,client_id,target_uri,sid,login_authenticated_at) VALUES ('fresh',?,'crm','https://crm.example.test/logout/backchannel','sid-test',now())",
          open);
      jdbc.update("UPDATE iam_user SET password_gate='BLOCKED' WHERE id=?", open);
      assertEquals(
          Boolean.TRUE,
          jdbc.queryForObject(
              "SELECT revoked FROM oauth2_authorization WHERE id='fresh'", Boolean.class));
      assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM oidc_logout_task", Integer.class));
      jdbc.update("UPDATE iam_user SET auth_epoch=auth_epoch+1,status='DISABLED' WHERE id=?", open);
      assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM oidc_logout_task", Integer.class));
      jdbc.update("DELETE FROM oauth2_authorization WHERE id='fresh'");
      assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM oidc_rp_session", Integer.class));
      assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM oidc_logout_task", Integer.class));
    }
  }
}
