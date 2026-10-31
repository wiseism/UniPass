package com.unipass.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.unipass.identity.Database;
import java.nio.file.Path;
import java.sql.*;
import java.time.Clock;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.*;
import org.springframework.transaction.support.TransactionTemplate;

public final class RecoveryAdminCli {
  private record Contact(UUID userId, String email, String evidenceRef) {
    @Override
    public String toString() {
      return "Contact[REDACTED]";
    }
  }

  public static void main(String[] args) {
    try {
      if (args.length != 2 || !"provision-contact".equals(args[0]))
        throw new IllegalArgumentException("provision-contact <json-file>");
      Database db =
          new Database(env("UNIPASS_DB_URL"), env("UNIPASS_DB_USER"), env("UNIPASS_DB_PASSWORD"));
      var source =
          new AbstractDataSource() {
            public Connection getConnection() throws SQLException {
              return db.open();
            }

            public Connection getConnection(String u, String p) throws SQLException {
              throw new UnsupportedOperationException();
            }
          };
      Contact contact = new ObjectMapper().readValue(Path.of(args[1]).toFile(), Contact.class);
      var tx = new TransactionTemplate(new DataSourceTransactionManager(source));
      tx.setTimeout(10);
      new RecoveryContactProvisioner(new JdbcTemplate(source), tx, Clock.systemUTC())
          .provision(contact.userId(), contact.email(), contact.evidenceRef());
      System.out.println("Recovery contact provisioned.");
    } catch (Exception e) {
      System.err.println(
          "Recovery contact operation failed (" + e.getClass().getSimpleName() + ").");
      System.exit(1);
    }
  }

  private static String env(String key) {
    String value = System.getenv(key);
    if (value == null || value.isBlank())
      throw new IllegalArgumentException("Missing configuration");
    return value;
  }
}
