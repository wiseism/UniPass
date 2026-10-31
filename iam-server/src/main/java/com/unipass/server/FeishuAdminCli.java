package com.unipass.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.unipass.identity.Database;
import java.sql.*;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.*;
import org.springframework.transaction.support.TransactionTemplate;

/** Offline, no HTTP listener or external exchange. Secrets are never command arguments. */
public final class FeishuAdminCli {
  private FeishuAdminCli() {}

  public static void main(String[] args) {
    try {
      if (args.length != 1
          || !Set.of("report", "configure", "record-login-verification", "disable")
              .contains(args[0])) throw new IllegalArgumentException("Invalid connector command");
      var db =
          new Database(
              required("UNIPASS_DB_URL"),
              required("UNIPASS_DB_USER"),
              required("UNIPASS_DB_PASSWORD"));
      var source =
          new AbstractDataSource() {
            @Override
            public Connection getConnection() throws SQLException {
              return db.open();
            }

            @Override
            public Connection getConnection(String user, String password) {
              throw new UnsupportedOperationException();
            }
          };
      var admin =
          new FeishuAdmin(
              new JdbcTemplate(source),
              new TransactionTemplate(new DataSourceTransactionManager(source)));
      if (!args[0].equals("report")) {
        String operator = required("UNIPASS_OPERATOR_REF"),
            evidence = required("UNIPASS_EVIDENCE_REF");
        switch (args[0]) {
          case "configure" ->
              admin.configure(
                  required("UNIPASS_FEISHU_APP_ID"),
                  required("UNIPASS_FEISHU_TENANT_KEY"),
                  operator,
                  evidence);
          case "record-login-verification" -> admin.recordLoginVerification(operator, evidence);
          case "disable" -> admin.disable(operator, evidence);
          default -> throw new IllegalArgumentException();
        }
      }
      System.out.println(new ObjectMapper().writeValueAsString(admin.report()));
    } catch (Exception failure) {
      System.err.println(
          "Connector operation failed (" + failure.getClass().getSimpleName() + ").");
      System.exit(1);
    }
  }

  private static String required(String name) {
    String value = System.getenv(name);
    if (value == null || value.isBlank())
      throw new IllegalArgumentException("Missing configuration");
    return value;
  }
}
