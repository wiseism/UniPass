package com.unipass.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.unipass.identity.Database;
import java.sql.*;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.*;
import org.springframework.transaction.support.TransactionTemplate;

/** No web context, directory, Redis or external adapter is started by this command. */
public final class SyncTaskAdminCli {
  private SyncTaskAdminCli() {}

  public static void main(String[] args) {
    try {
      if (args.length == 0
          || !Set.of("report", "tasks", "retry").contains(args[0])
          || args.length != (args[0].equals("retry") ? 2 : 1))
        throw new IllegalArgumentException("Invalid sync command");
      String operator = args[0].equals("retry") ? required("UNIPASS_OPERATOR_REF") : null;
      String evidence = args[0].equals("retry") ? required("UNIPASS_EVIDENCE_REF") : null;
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
      var tx = new TransactionTemplate(new DataSourceTransactionManager(source));
      var service = new SyncTaskAdmin(new JdbcTemplate(source), tx);
      Object result =
          switch (args[0]) {
            case "report" -> service.report();
            case "tasks" -> service.tasks(100);
            case "retry" ->
                Map.of("changed", service.retry(UUID.fromString(args[1]), operator, evidence));
            default -> throw new IllegalArgumentException("Invalid sync command");
          };
      System.out.println(new ObjectMapper().writeValueAsString(result));
    } catch (Exception failure) {
      System.err.println("Sync operation failed (" + failure.getClass().getSimpleName() + ").");
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
