package com.unipass.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.unipass.identity.Database;
import java.sql.*;
import java.util.Map;
import org.springframework.core.env.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.*;
import org.springframework.transaction.support.TransactionTemplate;

/** Offline database operator boundary; key bytes are accepted only via protected environment. */
public final class MfaKeyAdminCli {
  private static final Map<String, Integer> COMMANDS =
      Map.of(
          "migrate",
          1,
          "status",
          1,
          "verify",
          1,
          "introduce",
          2,
          "activate",
          2,
          "rekey",
          2,
          "retire",
          2);

  private MfaKeyAdminCli() {}

  public static void main(String[] args) {
    try {
      if (args.length == 0
          || !COMMANDS.containsKey(args[0])
          || args.length != COMMANDS.get(args[0]))
        throw new IllegalArgumentException("Invalid key command");
      boolean mutation = !java.util.Set.of("status", "verify", "migrate").contains(args[0]);
      String actor = mutation ? required("UNIPASS_OPERATOR_REF") : null,
          evidence = mutation ? required("UNIPASS_EVIDENCE_REF") : null;
      var db =
          new Database(
              required("UNIPASS_DB_URL"),
              required("UNIPASS_DB_USER"),
              required("UNIPASS_DB_PASSWORD"));
      if (args[0].equals("migrate")) {
        db.migrate();
        return;
      }
      var source =
          new AbstractDataSource() {
            @Override
            public Connection getConnection() throws SQLException {
              return db.open();
            }

            @Override
            public Connection getConnection(String user, String password) throws SQLException {
              throw new UnsupportedOperationException();
            }
          };
      var env = new StandardEnvironment();
      env.getPropertySources()
          .addFirst(
              new MapPropertySource(
                  "factor-keys",
                  Map.of(
                      "unipass.mfa.key",
                      System.getenv().getOrDefault("UNIPASS_MFA_KEY", ""),
                      "unipass.mfa.keys-json",
                      System.getenv().getOrDefault("UNIPASS_MFA_KEYS_JSON", ""))));
      var tx = new TransactionTemplate(new DataSourceTransactionManager(source));
      tx.setTimeout(10);
      var service = new MfaKeyService(new JdbcTemplate(source), tx, env);
      Object result =
          switch (args[0]) {
            case "status" -> service.status();
            case "verify" -> Map.of("verified_rows", service.verify());
            case "introduce" -> Map.of("changed", service.introduce(args[1], actor, evidence));
            case "activate" -> Map.of("changed", service.activate(args[1], actor, evidence));
            case "rekey" ->
                Map.of("changed_rows", service.rekey(Integer.parseInt(args[1]), actor, evidence));
            case "retire" -> Map.of("changed", service.retire(args[1], actor, evidence));
            default -> throw new IllegalArgumentException("Invalid key command");
          };
      System.out.println(new ObjectMapper().writeValueAsString(result));
    } catch (Exception failure) {
      System.err.println(
          "Factor key operation failed (" + failure.getClass().getSimpleName() + ").");
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
