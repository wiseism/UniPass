package com.unipass.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import java.net.*;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import java.util.concurrent.TimeUnit;
import org.springframework.boot.SpringApplication;
import org.springframework.core.env.MapPropertySource;
import org.springframework.jdbc.core.JdbcTemplate;

/** Explicit local UI fixture. This test class is never packaged in the IAM application. */
public final class PortalBrowserFixture {
  private static int port() throws Exception {
    try (var socket = new java.net.ServerSocket(0)) {
      return socket.getLocalPort();
    }
  }

  public static void main(String[] args) throws Exception {
    if (args.length != 2)
      throw new IllegalArgumentException("Expected output directory and Redis executable");
    Path base = Files.createDirectories(Path.of(args[0]).toAbsolutePath()),
        root = Files.createDirectories(base.resolve("fixture-" + UUID.randomUUID()));
    System.setProperty(
        "ot.epg.working-dir", Files.createDirectories(root.resolve("postgres")).toString());
    int serverPort = port(), redisPort = port();
    String redisPassword = UUID.randomUUID().toString();
    String origin = "http://localhost:" + serverPort;
    Path store = root.resolve("signing.p12");
    String keytool =
        Path.of(
                System.getProperty("java.home"),
                "bin",
                System.getProperty("os.name").startsWith("Windows") ? "keytool.exe" : "keytool")
            .toString();
    Process key =
        new ProcessBuilder(
                keytool,
                "-genkeypair",
                "-alias",
                "current",
                "-keyalg",
                "RSA",
                "-keysize",
                "2048",
                "-validity",
                "30",
                "-dname",
                "CN=Local Portal Fixture",
                "-storetype",
                "PKCS12",
                "-keystore",
                store.toString(),
                "-storepass",
                "local-fixture-only",
                "-noprompt")
            .redirectErrorStream(true)
            .redirectOutput(root.resolve("keytool.log").toFile())
            .start();
    try {
      if (!key.waitFor(20, TimeUnit.SECONDS) || key.exitValue() != 0)
        throw new IllegalStateException("Fixture signing key unavailable");
    } finally {
      if (key.isAlive()) key.destroyForcibly();
    }
    try (var postgres =
        EmbeddedPostgres.builder()
            .setPort(0)
            .setServerConfig("listen_addresses", "127.0.0.1")
            .start()) {
      Process redis =
          new ProcessBuilder(
                  args[1],
                  "--bind",
                  "127.0.0.1",
                  "--port",
                  Integer.toString(redisPort),
                  "--save",
                  "",
                  "--appendonly",
                  "no",
                  "--requirepass",
                  redisPassword,
                  "--dir",
                  root.toString().replace('\\', '/'))
              .redirectErrorStream(true)
              .redirectOutput(root.resolve("redis.log").toFile())
              .start();
      try {
        boolean ready = false;
        for (int attempt = 0; attempt < 100; attempt++) {
          if (!redis.isAlive()) throw new IllegalStateException("Fixture Redis exited");
          try (var socket = new Socket()) {
            socket.connect(new InetSocketAddress("127.0.0.1", redisPort), 100);
            ready = true;
            break;
          } catch (java.io.IOException unavailable) {
            Thread.sleep(50);
          }
        }
        if (!ready) throw new IllegalStateException("Fixture Redis startup timeout");
        Map<String, Object> settings = new HashMap<>();
        settings.put("spring.datasource.url", postgres.getJdbcUrl("postgres", "postgres"));
        settings.put("spring.datasource.username", "postgres");
        settings.put("spring.datasource.password", "test");
        settings.put("spring.data.redis.host", "127.0.0.1");
        settings.put("spring.data.redis.port", redisPort);
        settings.put("spring.data.redis.password", redisPassword);
        settings.put(
            "spring.session.redis.namespace", "unipass:portal-fixture:" + UUID.randomUUID());
        settings.put("server.port", serverPort);
        settings.put("server.address", "127.0.0.1");
        settings.put("unipass.issuer", origin);
        settings.put("unipass.local-http", true);
        settings.put("unipass.directory.enabled", false);
        settings.put("unipass.jobs.enabled", false);
        settings.put("unipass.feishu.enabled", false);
        settings.put("unipass.password.history-verified", true);
        settings.put("unipass.password.reset-history-verified", true);
        settings.put("unipass.mfa.key", Base64.getEncoder().encodeToString(new byte[32]));
        settings.put("unipass.signing.store", store.toString());
        settings.put("unipass.signing.password", "local-fixture-only");
        settings.put("unipass.signing.alias", "current");
        var app = new SpringApplication(UniPassApplication.class, OidcFlowIT.TestDirectory.class);
        app.addInitializers(
            context ->
                context
                    .getEnvironment()
                    .getPropertySources()
                    .addFirst(new MapPropertySource("local-portal-fixture", settings)));
        try (var context = app.run()) {
          var jdbc = context.getBean(JdbcTemplate.class);
          var tx =
              context.getBean(org.springframework.transaction.support.TransactionTemplate.class);
          context.getBean(OidcFlowIT.FakeDirectory.class).password = "Qx!7vN2$pk";
          jdbc.update(
              "INSERT INTO import_source(source_id,cursor_value) VALUES ('portal-fixture','1')");
          UUID user = UUID.randomUUID();
          jdbc.update(
              "INSERT INTO iam_user(id,employee_no,directory_id,directory_type,ldap_dn,display_name,status,source_id,source_version) VALUES (?,'E001',?,'OPENLDAP','uid=fixture','Fixture User','ACTIVE','portal-fixture',1)",
              user,
              user);
          new RecoveryContactProvisioner(jdbc, tx, Clock.systemUTC())
              .provision(user, "fixture@example.test", "ticket:local-browser-fixture");
          var json = new ObjectMapper();
          Files.writeString(
              base.resolve("fixture.json"),
              json.writeValueAsString(
                  Map.of(
                      "origin",
                      origin,
                      "root",
                      root.toString(),
                      "stop",
                      root.resolve("stop").toString(),
                      "mail",
                      root.resolve("mail.txt").toString())));
          var mail = context.getBean(OidcFlowIT.TestMail.class);
          var worker = context.getBean(RecoveryMailWorker.class);
          int delivered = 0;
          System.out.println("Local portal fixture ready at " + origin);
          while (!Files.exists(root.resolve("stop"))) {
            worker.runOnce();
            if (mail.links.size() > delivered) {
              Files.writeString(root.resolve("mail.txt"), mail.links.get(mail.links.size() - 1));
              delivered = mail.links.size();
            }
            Thread.sleep(200);
          }
        }
      } finally {
        redis.destroy();
        if (!redis.waitFor(5, TimeUnit.SECONDS)) redis.destroyForcibly();
      }
    }
  }
}
