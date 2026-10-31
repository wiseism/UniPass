package com.unipass.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.unipass.identity.Database;
import java.nio.file.Path;
import java.sql.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.AbstractDataSource;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;

/** Offline operator tool. No HTTP management endpoint is implicitly exposed. */
public final class ClientAdminCli {
  private ClientAdminCli() {}

  public static void main(String[] args) {
    try {
      Database db =
          new Database(env("UNIPASS_DB_URL"), env("UNIPASS_DB_USER"), env("UNIPASS_DB_PASSWORD"));
      if (args.length == 1 && args[0].equals("migrate")) {
        db.migrate();
        return;
      }
      if (args.length != 2 || !args[0].equals("register"))
        throw new IllegalArgumentException("migrate | register <json-file>");
      var spec =
          new ObjectMapper()
              .readValue(Path.of(args[1]).toFile(), ClientRegistrationService.Spec.class);
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
      var service =
          new ClientRegistrationService(
              new JdbcRegisteredClientRepository(new JdbcTemplate(source)),
              Boolean.parseBoolean(System.getenv("UNIPASS_ALLOW_LOCAL_CALLBACKS")));
      String id = service.register(spec, System.getenv("UNIPASS_CLIENT_SECRET"));
      System.out.println("registered_client_id=" + id);
    } catch (Exception e) {
      System.err.println("Client operation failed (" + e.getClass().getSimpleName() + ").");
      System.exit(1);
    }
  }

  private static String env(String name) {
    String value = System.getenv(name);
    if (value == null || value.isBlank())
      throw new IllegalArgumentException("Missing configuration");
    return value;
  }
}
