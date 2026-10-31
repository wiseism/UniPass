package com.unipass.server;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.*;
import com.unipass.directory.*;
import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import java.io.*;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.*;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.client.*;
import org.springframework.security.oauth2.server.authorization.settings.*;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.*;

@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    classes = {UniPassApplication.class, OidcFlowIT.TestDirectory.class})
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class OidcFlowIT {
  private static EmbeddedPostgres postgres;
  private static Process redis;
  private static Path signingStore;
  private static int redisPort;
  private static String redisPassword;
  private static final String ISSUER = "http://localhost:9999",
      CALLBACK = "https://rp.example.test/callback";
  private static final String OLD = "Qx!7vN2$pk", NEW = "Rz@8mP4#st", SECRET = "test-client-only";
  @LocalServerPort int port;
  @Autowired JdbcTemplate jdbc;
  @Autowired RegisteredClientRepository clients;
  @Autowired FakeDirectory directory;
  @Autowired PasswordReauthentication reauthentication;
  @Autowired DigestAuthorizationService authorizations;
  @Autowired MfaService mfa;
  @Autowired AccountState accounts;
  @Autowired LoginSessions loginSessions;
  @Autowired MfaKeyService factorKeys;
  @Autowired MfaLifecycleService factors;
  @Autowired EmailRecoveryService recovery;
  @Autowired RecoveryMailWorker mailWorker;
  @Autowired TestMail mail;
  @Autowired org.springframework.data.redis.core.StringRedisTemplate redisTemplate;
  @Autowired org.springframework.transaction.support.TransactionTemplate transactions;
  @Autowired RedisSecurityState securityState;
  @Autowired FeishuFixture feishuRemote;
  @Autowired com.unipass.password.PasswordChangeService passwords;
  private final ObjectMapper json = new ObjectMapper();
  private UUID user;

  @DynamicPropertySource
  static void properties(DynamicPropertyRegistry props) throws Exception {
    Path root = Files.createDirectories(Path.of("target", "protocol-test")).toAbsolutePath();
    System.setProperty(
        "ot.epg.working-dir", Files.createDirectories(root.resolve("postgres")).toString());
    postgres =
        EmbeddedPostgres.builder()
            .setPort(0)
            .setServerConfig("listen_addresses", "127.0.0.1")
            .start();
    try (ServerSocket socket = new ServerSocket(0)) {
      redisPort = socket.getLocalPort();
    }
    redisPassword = UUID.randomUUID().toString();
    String executable =
        System.getProperty(
            "test.redis.executable",
            System.getenv().getOrDefault("UNIPASS_TEST_REDIS_EXECUTABLE", "redis-server"));
    redis =
        new ProcessBuilder(
                executable,
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
    Process ownedRedis = redis;
    Runtime.getRuntime()
        .addShutdownHook(
            new Thread(
                () -> {
                  if (ownedRedis.isAlive()) ownedRedis.destroy();
                }));
    boolean ready = false;
    for (int i = 0; i < 100; i++) {
      if (!redis.isAlive())
        throw new IllegalStateException(
            "Test Redis exited: " + Files.readString(root.resolve("redis.log")));
      try (Socket socket = new Socket()) {
        socket.connect(new InetSocketAddress("127.0.0.1", redisPort), 100);
        ready = true;
        break;
      } catch (IOException e) {
        Thread.sleep(50);
      }
    }
    if (!ready) throw new IllegalStateException("Test Redis startup timed out");
    signingStore = root.resolve("signing.p12");
    if (!Files.exists(signingStore)) {
      String keytool =
          Path.of(System.getProperty("java.home"), "bin", windows() ? "keytool.exe" : "keytool")
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
                  "CN=UniPass Test",
                  "-storetype",
                  "PKCS12",
                  "-keystore",
                  signingStore.toString(),
                  "-storepass",
                  "test-only-password",
                  "-noprompt")
              .redirectErrorStream(true)
              .redirectOutput(root.resolve("keytool.log").toFile())
              .start();
      if (!key.waitFor(20, TimeUnit.SECONDS) || key.exitValue() != 0)
        throw new IllegalStateException("Test signing-key creation failed");
    }
    props.add("spring.datasource.url", () -> postgres.getJdbcUrl("postgres", "postgres"));
    props.add("spring.datasource.username", () -> "postgres");
    props.add("spring.datasource.password", () -> "test");
    props.add("spring.data.redis.host", () -> "127.0.0.1");
    props.add("spring.data.redis.port", () -> redisPort);
    props.add("spring.data.redis.password", () -> redisPassword);
    props.add("unipass.issuer", () -> ISSUER);
    props.add("unipass.local-http", () -> true);
    props.add("unipass.directory.enabled", () -> false);
    props.add("server.address", () -> "127.0.0.1");
    props.add("unipass.signing.store", () -> signingStore.toString());
    props.add("unipass.signing.password", () -> "test-only-password");
    props.add("unipass.signing.alias", () -> "current");
    props.add("unipass.password.history-verified", () -> true);
    props.add("unipass.mfa.key", () -> Base64.getEncoder().encodeToString(new byte[32]));
    props.add("unipass.mfa.keys-json", () -> "{\"next\":\"" + nextFactorKey() + "\"}");
    props.add("unipass.jobs.enabled", () -> false);
    props.add("unipass.feishu.enabled", () -> true);
    props.add("UNIPASS_FEISHU_APP_ID", () -> FeishuFixture.APP);
    props.add("UNIPASS_FEISHU_TENANT_KEY", () -> FeishuFixture.TENANT);
    props.add("UNIPASS_FEISHU_APP_SECRET", () -> FeishuFixture.SECRET);
    props.add(
        "UNIPASS_FEISHU_CALLBACK", () -> "https://localhost:9999/api/connector/feishu/callback");
    props.add("unipass.password.reset-history-verified", () -> true);
  }

  @BeforeEach
  void seed() {
    factorKeys.activate("legacy", "test:fixture", "test:reset");
    jdbc.execute("TRUNCATE oauth2_authorization CASCADE");
    jdbc.execute("TRUNCATE import_source CASCADE");
    jdbc.execute("TRUNCATE feishu_flow,feishu_code_use");
    feishuRemote.reset();
    var feishuAdmin = new FeishuAdmin(jdbc, transactions);
    feishuAdmin.configure(
        FeishuFixture.APP, FeishuFixture.TENANT, "operator:fixture", "ticket:fixture");
    feishuAdmin.recordLoginVerification("operator:fixture", "ticket:fixture-not-real-tenant");
    user = UUID.randomUUID();
    directory.password = OLD;
    directory.afterVerify = () -> {};
    mail.reset();
    var resetKeys = redisTemplate.keys("unipass:reset:*");
    if (resetKeys != null && !resetKeys.isEmpty()) redisTemplate.delete(resetKeys);
    jdbc.update("INSERT INTO import_source(source_id,cursor_value) VALUES ('hr','1')");
    jdbc.update(
        "INSERT INTO iam_user(id,employee_no,directory_id,directory_type,ldap_dn,display_name,status,source_id,source_version) VALUES (?,'E001',?,'OPENLDAP','uid=one,dc=example','Test','ACTIVE','hr',1)",
        user,
        user);
    for (String id : List.of("web", "native", "web-two"))
      if (clients.findByClientId(id) == null) {
        var builder =
            RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(id)
                .redirectUri(CALLBACK)
                .postLogoutRedirectUri("https://rp.example.test/")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .scope("openid")
                .scope("profile")
                .scope("api.read")
                .clientSettings(
                    ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(false)
                        .setting("unipass.native", id.equals("native"))
                        .build())
                .tokenSettings(
                    TokenSettings.builder()
                        .authorizationCodeTimeToLive(Duration.ofSeconds(60))
                        .accessTokenTimeToLive(Duration.ofHours(1))
                        .refreshTokenTimeToLive(Duration.ofDays(30))
                        .reuseRefreshTokens(false)
                        .build());
        if (id.equals("native"))
          builder.clientAuthenticationMethod(ClientAuthenticationMethod.NONE);
        else
          builder
              .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
              .clientSecret("{noop}" + SECRET + "-" + id);
        clients.save(builder.build());
      }
  }

  private HttpClient browser() {
    return HttpClient.newBuilder()
        .cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL))
        .followRedirects(HttpClient.Redirect.NEVER)
        .build();
  }

  private URI uri(String path) {
    return URI.create("http://localhost:" + port + path);
  }

  private HttpResponse<String> get(HttpClient client, String path) throws Exception {
    return client.send(
        HttpRequest.newBuilder(uri(path)).GET().build(), HttpResponse.BodyHandlers.ofString());
  }

  private HttpResponse<String> post(
      HttpClient client, String path, Map<String, String> form, String clientId) throws Exception {
    String body =
        form.entrySet().stream()
            .map(e -> enc(e.getKey()) + "=" + enc(e.getValue()))
            .collect(java.util.stream.Collectors.joining("&"));
    var request =
        HttpRequest.newBuilder(uri(path))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(body));
    if (clientId == null) request.header("Origin", ISSUER);
    if (clientId != null && !clientId.equals("native"))
      request.header(
          "Authorization",
          "Basic "
              + Base64.getEncoder()
                  .encodeToString(
                      (clientId + ":" + SECRET + "-" + clientId).getBytes(StandardCharsets.UTF_8)));
    return client.send(request.build(), HttpResponse.BodyHandlers.ofString());
  }

  private String authorize(String client, String verifier) throws Exception {
    String challenge =
        Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(
                MessageDigest.getInstance("SHA-256")
                    .digest(verifier.getBytes(StandardCharsets.US_ASCII)));
    return "/oauth/authorize?response_type=code&client_id="
        + client
        + "&redirect_uri="
        + enc(CALLBACK)
        + "&scope=openid%20profile%20api.read&state=test-state-123&nonce=test-nonce-123&code_challenge_method=S256&code_challenge="
        + challenge;
  }

  private String code(HttpClient client, String clientId, String verifier) throws Exception {
    String path = authorize(clientId, verifier);
    var first = get(client, path);
    if (first.statusCode() != 302
        || !first.headers().firstValue("Location").orElse("").startsWith(CALLBACK)) {
      login(client);
      first = get(client, path);
    }
    assertEquals(302, first.statusCode(), first.body());
    String location = first.headers().firstValue("Location").orElseThrow();
    assertTrue(location.startsWith(CALLBACK), location);
    for (String pair : URI.create(location).getRawQuery().split("&"))
      if (pair.startsWith("code="))
        return URLDecoder.decode(pair.substring(5), StandardCharsets.UTF_8);
    throw new AssertionError(location);
  }

  private void login(HttpClient client) throws Exception {
    login(client, "E001");
  }

  private void login(HttpClient client, String employee) throws Exception {
    var proof = get(client, "/api/public/csrf");
    assertEquals(200, proof.statusCode(), proof.body());
    var csrf = json.readTree(proof.body());
    var response =
        post(
            client,
            "/login",
            Map.of(
                "username",
                employee,
                "password",
                directory.password,
                csrf.get("parameter_name").asText(),
                csrf.get("token").asText()),
            null);
    assertEquals(302, response.statusCode(), response.body());
  }

  private HttpResponse<String> postJson(HttpClient client, String path, Object value)
      throws Exception {
    var csrfResponse = get(client, "/api/session/csrf");
    assertEquals(200, csrfResponse.statusCode(), csrfResponse.body());
    var csrf = json.readTree(csrfResponse.body());
    return client.send(
        HttpRequest.newBuilder(uri(path))
            .header("Content-Type", "application/json")
            .header("Origin", ISSUER)
            .header(csrf.get("header_name").asText(), csrf.get("token").asText())
            .POST(HttpRequest.BodyPublishers.ofString(json.writeValueAsString(value)))
            .build(),
        HttpResponse.BodyHandlers.ofString());
  }

  private HttpResponse<String> recoveryJson(
      HttpClient client, String path, Object value, String key) throws Exception {
    var csrf = json.readTree(get(client, "/api/public/csrf").body());
    var request =
        HttpRequest.newBuilder(uri(path))
            .header("Content-Type", "application/json")
            .header("Origin", ISSUER)
            .header(csrf.get("header_name").asText(), csrf.get("token").asText());
    if (key != null) request.header("Idempotency-Key", key);
    return client.send(
        request.POST(HttpRequest.BodyPublishers.ofString(json.writeValueAsString(value))).build(),
        HttpResponse.BodyHandlers.ofString());
  }

  private void contact() {
    jdbc.update(
        "INSERT INTO recovery_contact(user_id,email,contact_version,verified_at,evidence_ref) VALUES (?,'verified@example.test',?,now(),'ticket:verified-roster')",
        user,
        UUID.randomUUID());
  }

  private String emailProof() throws Exception {
    assertEquals(
        202,
        recoveryJson(browser(), "/api/password/reset/request", Map.of("employee_no", "E001"), null)
            .statusCode());
    assertTrue(mailWorker.runOnce());
    URI link = URI.create(mail.links.get(mail.links.size() - 1));
    assertNull(link.getRawQuery());
    return link.getFragment().substring("token=".length());
  }

  @Test
  void emailRecoveryDoesNotEnumerateAndBindsOneTimeGrantToVerifyingBrowser() throws Exception {
    contact();
    var old = tokens(browser(), "web");
    HttpClient owner = browser(), stranger = browser();
    assertEquals(
        403,
        owner
            .send(
                HttpRequest.newBuilder(uri("/api/password/reset/request"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString("{\"employee_no\":\"E001\"}"))
                    .build(),
                HttpResponse.BodyHandlers.ofString())
            .statusCode());
    var known =
        recoveryJson(owner, "/api/password/reset/request", Map.of("employee_no", "E001"), null);
    var unknown =
        recoveryJson(
            stranger, "/api/password/reset/request", Map.of("employee_no", "missing"), null);
    assertEquals(202, known.statusCode());
    assertEquals(known.body(), unknown.body());
    assertTrue(mail.links.isEmpty());
    assertTrue(mailWorker.runOnce());
    assertEquals(List.of("verified@example.test"), mail.recipients);
    String proof = URI.create(mail.links.get(0)).getFragment().substring("token=".length());
    assertEquals(
        0,
        jdbc.queryForObject(
            "SELECT count(*) FROM reset_email_challenge WHERE token_digest=?",
            Integer.class,
            proof));
    assertEquals(405, get(owner, "/api/password/reset/verify").statusCode());
    var verified = recoveryJson(owner, "/api/password/reset/verify", Map.of("token", proof), null);
    assertEquals(200, verified.statusCode(), verified.body());
    String grant = json.readTree(verified.body()).get("reset_token").asText();
    assertEquals(
        400,
        recoveryJson(owner, "/api/password/reset/verify", Map.of("token", proof), null)
            .statusCode());
    var body = Map.of("reset_token", grant, "new_password", NEW, "confirm_password", NEW);
    String key = UUID.randomUUID().toString();
    assertEquals(
        400, recoveryJson(stranger, "/api/password/reset/confirm", body, key).statusCode());
    var changed = recoveryJson(owner, "/api/password/reset/confirm", body, key);
    assertEquals(200, changed.statusCode(), changed.body());
    var replay = recoveryJson(owner, "/api/password/reset/confirm", body, key);
    assertEquals(200, replay.statusCode(), replay.body());
    assertEquals(json.readTree(changed.body()).get("id"), json.readTree(replay.body()).get("id"));
    String operation = json.readTree(changed.body()).get("id").asText();
    assertEquals(200, get(owner, "/api/password/reset/operations/" + operation).statusCode());
    assertEquals(404, get(stranger, "/api/password/reset/operations/" + operation).statusCode());
    assertEquals(401, api(old.get("access_token").asText()).statusCode());
    assertEquals(NEW, directory.password);
  }

  @Test
  void expiredEmailProofAndContactChangeCannotAuthorizeResetOrUseOldDeliveryTask()
      throws Exception {
    contact();
    String expired = emailProof();
    jdbc.execute("UPDATE reset_email_challenge SET expires_at=now()-interval '1 second'");
    assertEquals(
        400,
        recoveryJson(browser(), "/api/password/reset/verify", Map.of("token", expired), null)
            .statusCode());
    String old = emailProof();
    recovery.request("E001", "local-test");
    new RecoveryContactProvisioner(jdbc, transactions, Clock.systemUTC())
        .provision(user, "changed@example.test", "ticket:verified-change");
    assertEquals(
        400,
        recoveryJson(browser(), "/api/password/reset/verify", Map.of("token", old), null)
            .statusCode());
    int deliveries = mail.links.size();
    assertTrue(mailWorker.runOnce());
    assertEquals(deliveries, mail.links.size());
    assertEquals(
        1,
        jdbc.queryForObject(
            "SELECT count(*) FROM reset_mail_request WHERE state='BLOCKED'", Integer.class));
  }

  @Test
  void failedEmailDeliveryRetriesWithNewProofAndStaleLeaseCannotRecordSuccess() throws Exception {
    contact();
    mail.fail = true;
    String old = emailProof();
    assertEquals(
        "PENDING", jdbc.queryForObject("SELECT state FROM reset_mail_request", String.class));
    jdbc.execute("UPDATE reset_mail_request SET next_attempt_at=now()-interval '1 second'");
    assertTrue(mailWorker.runOnce());
    String fresh = URI.create(mail.links.get(1)).getFragment().substring("token=".length());
    assertNotEquals(old, fresh);
    assertEquals(
        400,
        recoveryJson(browser(), "/api/password/reset/verify", Map.of("token", old), null)
            .statusCode());
    mail.fail = false;
    mail.beforeSend =
        () ->
            jdbc.update(
                "UPDATE reset_mail_request SET lease_token=?,lease_until=now()+interval '1 minute'",
                UUID.randomUUID());
    jdbc.execute("UPDATE reset_mail_request SET next_attempt_at=now()-interval '1 second'");
    assertTrue(mailWorker.runOnce());
    assertEquals(
        "RUNNING", jdbc.queryForObject("SELECT state FROM reset_mail_request", String.class));
    jdbc.execute("UPDATE reset_mail_request SET lease_until=now()-interval '1 second',attempts=5");
    assertFalse(mailWorker.runOnce());
    assertEquals("DEAD", jdbc.queryForObject("SELECT state FROM reset_mail_request", String.class));
  }

  @Test
  void concurrentEmailVerificationConsumesProofOnlyOnce() throws Exception {
    contact();
    String proof = emailProof();
    ExecutorService pool = Executors.newFixedThreadPool(2);
    java.util.concurrent.Callable<Boolean> verify =
        () -> {
          try {
            recovery.verify(proof, "browser-session");
            return true;
          } catch (org.springframework.web.server.ResponseStatusException e) {
            return false;
          }
        };
    try {
      var first = pool.submit(verify);
      var second = pool.submit(verify);
      assertNotEquals(first.get(10, TimeUnit.SECONDS), second.get(10, TimeUnit.SECONDS));
    } finally {
      pool.shutdownNow();
    }
    assertEquals(
        1, jdbc.queryForObject("SELECT count(*) FROM password_reset_grant", Integer.class));
  }

  @Test
  void anonymousRecoveryRateLimitReturnsSameAcceptanceWithoutExcessMailTasks() throws Exception {
    contact();
    HttpClient browser = browser();
    for (int attempt = 0; attempt < 6; attempt++) {
      var response =
          recoveryJson(browser, "/api/password/reset/request", Map.of("employee_no", "E001"), null);
      assertEquals(202, response.statusCode(), response.body());
    }
    assertEquals(5, jdbc.queryForObject("SELECT count(*) FROM reset_mail_request", Integer.class));
    assertTrue(mail.links.isEmpty());
  }

  @Test
  void packagedContactCliRequiresVerifiedEvidenceAndFencesExistingCredentials() throws Exception {
    Path input = Path.of("target", "protocol-test", "recovery-contact.json"),
        log = Path.of("target", "protocol-test", "recovery-cli.log");
    Files.writeString(
        input,
        json.writeValueAsString(
            Map.of(
                "userId",
                user.toString(),
                "email",
                "cli-verified@example.test",
                "evidenceRef",
                "ticket:roster-verification")));
    var command =
        new ProcessBuilder(
            Path.of(System.getProperty("java.home"), "bin", windows() ? "java.exe" : "java")
                .toString(),
            "-Dloader.main=com.unipass.server.RecoveryAdminCli",
            "-cp",
            Path.of(
                    System.getProperty(
                        "test.server.exec.jar", "target/iam-server-0.1.0-SNAPSHOT-exec.jar"))
                .toAbsolutePath()
                .toString(),
            "org.springframework.boot.loader.launch.PropertiesLauncher",
            "provision-contact",
            input.toAbsolutePath().toString());
    command.environment().put("UNIPASS_DB_URL", postgres.getJdbcUrl("postgres", "postgres"));
    command.environment().put("UNIPASS_DB_USER", "postgres");
    command.environment().put("UNIPASS_DB_PASSWORD", "test");
    Process process = command.redirectErrorStream(true).redirectOutput(log.toFile()).start();
    try {
      assertTrue(process.waitFor(20, TimeUnit.SECONDS));
      assertEquals(0, process.exitValue(), Files.readString(log));
      assertEquals(
          1L, jdbc.queryForObject("SELECT auth_epoch FROM iam_user WHERE id=?", Long.class, user));
      assertEquals(
          "cli-verified@example.test",
          jdbc.queryForObject(
              "SELECT email FROM recovery_contact WHERE user_id=?", String.class, user));
      assertFalse(Files.readString(log).contains("cli-verified@example.test"));
    } finally {
      if (process.isAlive()) process.destroyForcibly();
    }
  }

  private HttpClient administrator() throws Exception {
    jdbc.update(
        "INSERT INTO iam_user_role(user_id,role) VALUES (?,'ROLE_ADMIN_PASSWORD_RESET'),(?,'ROLE_ADMIN_PASSWORD_RECOVERY')",
        user,
        user);
    byte[] secret = seedFactor();
    HttpClient browser = browser();
    login(browser);
    String context =
        json.readTree(postJson(browser, "/api/mfa/context", Map.of()).body())
            .get("context")
            .asText();
    String challenge =
        json.readTree(postJson(browser, "/api/mfa/challenges", Map.of("context", context)).body())
            .get("challenge")
            .asText();
    var verified =
        postJson(
            browser,
            "/api/mfa/verify",
            Map.of("context", context, "challenge", challenge, "code", otp(secret, Instant.now())));
    assertEquals(200, verified.statusCode(), verified.body());
    return browser;
  }

  private UUID target() {
    UUID target = UUID.randomUUID();
    jdbc.update(
        "INSERT INTO iam_user(id,employee_no,directory_id,directory_type,ldap_dn,display_name,status,source_id,source_version) VALUES (?,'E002',?,'OPENLDAP','uid=two,dc=example','Target','ACTIVE','hr',1)",
        target,
        target);
    return target;
  }

  @Test
  void missingRedisGenerationDeniesOldCredentialsBeforeAndAfterRecovery() throws Exception {
    HttpClient browser = browser();
    var before = tokens(browser, "web");
    redisTemplate.delete(securityState.generationKey());
    assertEquals(401, api(before.get("access_token").asText()).statusCode());
    assertEquals(503, get(browser, "/api/session/me").statusCode());
    assertTrue(securityState.recoverIfNeeded());
    assertFalse(securityState.recoverIfNeeded());
    assertEquals(
        1L, jdbc.queryForObject("SELECT auth_epoch FROM iam_user WHERE id=?", Long.class, user));
    assertEquals(401, api(before.get("access_token").asText()).statusCode());
    assertEquals(400, refresh("web", before.get("refresh_token").asText()).statusCode());
    assertEquals(401, get(browser, "/api/session/me").statusCode());
    assertEquals(200, api(tokens(browser(), "web").get("access_token").asText()).statusCode());
  }

  @Test
  void actualRedisDataLossCannotRehabilitateJwtOrRefreshToken() throws Exception {
    var before = tokens(browser(), "web");
    redisTemplate.execute(
        (org.springframework.data.redis.core.RedisCallback<Void>)
            connection -> {
              connection.serverCommands().flushDb();
              return null;
            });
    assertEquals(401, api(before.get("access_token").asText()).statusCode());
    assertTrue(securityState.recoverIfNeeded());
    assertEquals(401, api(before.get("access_token").asText()).statusCode());
    assertEquals(400, refresh("web", before.get("refresh_token").asText()).statusCode());
  }

  @Test
  void redisProcessRestartIsDetectedEvenWhenGenerationMarkerIsRestored() throws Exception {
    var before = tokens(browser(), "web");
    String marker = redisTemplate.opsForValue().get(securityState.generationKey());
    String previousRun = securityState.current().runId();
    redis.destroy();
    assertTrue(redis.waitFor(10, TimeUnit.SECONDS));
    Path root = Path.of("target", "protocol-test").toAbsolutePath();
    String executable =
        System.getProperty(
            "test.redis.executable",
            System.getenv().getOrDefault("UNIPASS_TEST_REDIS_EXECUTABLE", "redis-server"));
    redis =
        new ProcessBuilder(
                executable,
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
            .redirectOutput(root.resolve("redis-restart.log").toFile())
            .start();
    Process owned = redis;
    Runtime.getRuntime()
        .addShutdownHook(
            new Thread(
                () -> {
                  if (owned.isAlive()) owned.destroy();
                }));
    boolean ready = false;
    for (int attempt = 0; attempt < 100; attempt++) {
      if (!redis.isAlive()) throw new IllegalStateException("Restarted Redis exited");
      try {
        redisTemplate.opsForValue().set(securityState.generationKey(), marker);
        ready = true;
        break;
      } catch (RuntimeException e) {
        Thread.sleep(50);
      }
    }
    assertTrue(ready);
    assertNotEquals(previousRun, securityState.current().runId());
    assertEquals(401, api(before.get("access_token").asText()).statusCode());
    assertTrue(securityState.recoverIfNeeded());
    assertEquals(401, api(before.get("access_token").asText()).statusCode());
    assertEquals(400, refresh("web", before.get("refresh_token").asText()).statusCode());
  }

  @Test
  void concurrentRecoveryFencesAnIdentityExactlyOnce() throws Exception {
    tokens(browser(), "web");
    long baseline = jdbc.queryForObject("SELECT count(*) FROM auth_runtime_recovery", Long.class);
    redisTemplate.delete(securityState.generationKey());
    ExecutorService pool = Executors.newFixedThreadPool(2);
    try {
      var first = pool.submit(() -> securityState.recoverIfNeeded());
      var second = pool.submit(() -> securityState.recoverIfNeeded());
      assertNotEquals(first.get(10, TimeUnit.SECONDS), second.get(10, TimeUnit.SECONDS));
    } finally {
      pool.shutdownNow();
    }
    assertEquals(
        1L, jdbc.queryForObject("SELECT auth_epoch FROM iam_user WHERE id=?", Long.class, user));
    assertEquals(
        baseline + 1,
        jdbc.queryForObject("SELECT count(*) FROM auth_runtime_recovery", Long.class));
  }

  @Test
  void redisSideEffectFollowedByPgCommitFailureStaysDeniedUntilRecovery() throws Exception {
    var before = tokens(browser(), "web");
    String original =
        jdbc.queryForObject("SELECT redis_generation::text FROM auth_runtime_state", String.class);
    jdbc.execute(
        "CREATE FUNCTION fail_auth_runtime_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test commit failure'; END $$");
    jdbc.execute(
        "CREATE CONSTRAINT TRIGGER fail_auth_runtime_commit AFTER UPDATE ON auth_runtime_state DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION fail_auth_runtime_commit()");
    redisTemplate.delete(securityState.generationKey());
    try {
      assertThrows(RuntimeException.class, () -> securityState.recoverIfNeeded());
      assertEquals(
          original,
          jdbc.queryForObject(
              "SELECT redis_generation::text FROM auth_runtime_state", String.class));
      assertNotEquals(original, redisTemplate.opsForValue().get(securityState.generationKey()));
      assertEquals(
          0L, jdbc.queryForObject("SELECT auth_epoch FROM iam_user WHERE id=?", Long.class, user));
      assertEquals(401, api(before.get("access_token").asText()).statusCode());
    } finally {
      jdbc.execute("DROP TRIGGER fail_auth_runtime_commit ON auth_runtime_state");
      jdbc.execute("DROP FUNCTION fail_auth_runtime_commit()");
    }
    assertTrue(securityState.recoverIfNeeded());
    assertEquals(401, api(before.get("access_token").asText()).statusCode());
  }

  @Test
  void redisRecoveryPreservesBlockedPasswordFenceForEvidenceRecovery() throws Exception {
    var before = tokens(browser(), "web");
    UUID admin = target(), operation = UUID.randomUUID();
    jdbc.update("UPDATE iam_user SET password_gate='BLOCKED',auth_epoch=1 WHERE id=?", user);
    jdbc.update(
        "INSERT INTO password_operation(id,user_id,idempotency_key,state,operation_type,fenced_epoch,lease_until,created_at) VALUES (?,?,'test-blocked-fence','UNKNOWN','CHANGE',1,now()-interval '1 minute',now())",
        operation,
        user);
    redisTemplate.delete(securityState.generationKey());
    assertTrue(securityState.recoverIfNeeded());
    assertEquals(
        1L, jdbc.queryForObject("SELECT auth_epoch FROM iam_user WHERE id=?", Long.class, user));
    var adminLogin = register(new IdentityPrincipal(admin, 1, Instant.now(), List.of("ROLE_USER")));
    var actor =
        new com.unipass.password.AuthenticatedActor(
            admin,
            1,
            Instant.now(),
            Set.of("PASSWORD_RECOVERY"),
            Instant.now(),
            adminLogin.getLoginId());
    assertEquals(
        com.unipass.password.PasswordOperation.State.REJECTED,
        passwords.recover(actor, operation, false, "ticket:redis-incident/evidence").state());
    assertEquals(
        "OPEN",
        jdbc.queryForObject("SELECT password_gate FROM iam_user WHERE id=?", String.class, user));
    assertEquals(401, api(before.get("access_token").asText()).statusCode());
  }

  @Test
  void administrativeResetRequiresFreshMfaAndLiveRoleAndPersistsReason() throws Exception {
    HttpClient weak = browser();
    login(weak);
    UUID target = target();
    var body =
        Map.of(
            "reason", "Helpdesk identity verified", "new_password", NEW, "confirm_password", NEW);
    String key = UUID.randomUUID().toString();
    assertEquals(
        403,
        recoveryJson(weak, "/api/admin/password/users/" + target + "/reset", body, key)
            .statusCode());
    HttpClient admin = administrator();
    var response = recoveryJson(admin, "/api/admin/password/users/" + target + "/reset", body, key);
    assertEquals(200, response.statusCode(), response.body());
    assertTrue(
        jdbc.queryForObject(
            "SELECT must_change_password FROM iam_user WHERE id=?", Boolean.class, target));
    assertEquals(
        "Helpdesk identity verified",
        jdbc.queryForObject("SELECT reason FROM admin_password_action", String.class));
    String operation = json.readTree(response.body()).get("id").asText();
    assertEquals(200, get(admin, "/api/admin/password/operations/" + operation).statusCode());
    jdbc.update(
        "DELETE FROM iam_user_role WHERE user_id=? AND role='ROLE_ADMIN_PASSWORD_RESET'", user);
    assertEquals(
        403,
        recoveryJson(admin, "/api/admin/password/users/" + target + "/reset", body, key)
            .statusCode());
  }

  @Test
  void administrativeRecoveryRequiresEvidenceExpiredLeaseAndIdempotentDecision() throws Exception {
    UUID target = target(), operation = UUID.randomUUID();
    HttpClient admin = administrator();
    jdbc.update("UPDATE iam_user SET password_gate='BLOCKED',auth_epoch=1 WHERE id=?", target);
    jdbc.update(
        "INSERT INTO password_operation(id,user_id,idempotency_key,state,operation_type,fenced_epoch,lease_until,created_at) VALUES (?,?,'test-unknown-operation','UNKNOWN','CHANGE',1,now()+interval '1 minute',now())",
        operation,
        target);
    String path = "/api/admin/password/operations/" + operation + "/recover",
        key = UUID.randomUUID().toString();
    var body =
        Map.of(
            "confirmed_committed",
            false,
            "reason",
            "Directory evidence reviewed",
            "evidence_ref",
            "ticket:SEC-200/evidence");
    assertEquals(403, recoveryJson(admin, path, body, key).statusCode());
    jdbc.update(
        "UPDATE password_operation SET lease_until=now()-interval '1 second' WHERE id=?",
        operation);
    var response = recoveryJson(admin, path, body, key);
    assertEquals(200, response.statusCode(), response.body());
    assertEquals("REJECTED", json.readTree(response.body()).get("state").asText());
    assertEquals(200, recoveryJson(admin, path, body, key).statusCode());
    assertEquals(
        "OPEN",
        jdbc.queryForObject("SELECT password_gate FROM iam_user WHERE id=?", String.class, target));
    assertEquals(
        403,
        recoveryJson(
                admin,
                path,
                Map.of(
                    "confirmed_committed",
                    true,
                    "reason",
                    "Contradictory decision",
                    "evidence_ref",
                    "ticket:SEC-200/evidence"),
                UUID.randomUUID().toString())
            .statusCode());
  }

  private String otp(byte[] secret, Instant instant) throws Exception {
    return new com.eatthepath.otp.TimeBasedOneTimePasswordGenerator()
        .generateOneTimePasswordString(
            new javax.crypto.spec.SecretKeySpec(secret, "HmacSHA1"), instant, Locale.ROOT);
  }

  private byte[] seedFactor() {
    return seedFactor(user);
  }

  private byte[] seedFactor(UUID identity) {
    byte[] secret = new byte[20];
    new java.security.SecureRandom().nextBytes(secret);
    var cipher = new MfaSecretCipher(Base64.getEncoder().encodeToString(new byte[32]));
    jdbc.update(
        "INSERT INTO mfa_totp(user_id,secret_cipher,enabled) VALUES (?,?,true)",
        identity,
        cipher.encrypt(identity, secret));
    return secret;
  }

  private IdentityPrincipal register(IdentityPrincipal principal) {
    return accounts.registerLogin(principal);
  }

  private IdentityPrincipal principal() {
    return register(new IdentityPrincipal(user, 0, Instant.now(), List.of("ROLE_USER")));
  }

  private IdentityPrincipal strongPrincipal() {
    return principal().withMfa(Instant.now());
  }

  private static String nextFactorKey() {
    byte[] raw = new byte[32];
    Arrays.fill(raw, (byte) 1);
    return Base64.getEncoder().encodeToString(raw);
  }

  @Test
  void masterKeySwitchKeepsLiveAuthorizationAndConfirmsLegacyPendingWithCurrentWriter()
      throws Exception {
    HttpClient strong = administrator();
    var old = tokens(strong, "web");
    var started = postJson(strong, "/api/mfa/rotation", Map.of());
    assertEquals(200, started.statusCode(), started.body());
    var replacement = json.readTree(started.body());
    byte[] secret =
        new org.apache.commons.codec.binary.Base32().decode(replacement.get("secret").asText());
    assertTrue(factorKeys.activate("next", "test:operator", "ticket:master-key"));
    assertEquals(
        0L, jdbc.queryForObject("SELECT auth_epoch FROM iam_user WHERE id=?", Long.class, user));
    assertEquals(200, api(old.get("access_token").asText()).statusCode());
    assertEquals(
        200,
        postJson(
                strong,
                "/api/mfa/changes/" + replacement.get("id").asText() + "/confirm",
                Map.of("code", otp(secret, Instant.now())))
            .statusCode());
    assertEquals(
        "next",
        MfaSecretCipher.keyId(
            jdbc.queryForObject(
                "SELECT secret_cipher FROM mfa_totp WHERE user_id=?", byte[].class, user)));
    assertEquals(401, api(old.get("access_token").asText()).statusCode());
    HttpClient fresh = browser();
    login(fresh);
    stepUp(fresh, secret, Instant.now().plusSeconds(30));
    assertEquals(200, api(tokens(fresh, "web").get("access_token").asText()).statusCode());
  }

  private IdentityPrincipal recoveryOperator() {
    jdbc.update(
        "INSERT INTO iam_user_role(user_id,role) VALUES (?,'ROLE_ADMIN_MFA_RECOVERY')", user);
    seedFactor();
    return strongPrincipal();
  }

  private void stepUp(HttpClient client, byte[] secret, Instant at) throws Exception {
    String context =
        json.readTree(postJson(client, "/api/mfa/context", Map.of()).body())
            .get("context")
            .asText();
    String challenge =
        json.readTree(postJson(client, "/api/mfa/challenges", Map.of("context", context)).body())
            .get("challenge")
            .asText();
    var result =
        postJson(
            client,
            "/api/mfa/verify",
            Map.of("context", context, "challenge", challenge, "code", otp(secret, at)));
    assertEquals(200, result.statusCode(), result.body());
  }

  @Test
  void factorRotationRetainsCurrentFactorUntilConfirmationThenFencesOldCredentials()
      throws Exception {
    HttpClient strong = administrator();
    var old = tokens(strong, "web");
    byte[] original =
        jdbc.queryForObject(
            "SELECT secret_cipher FROM mfa_totp WHERE user_id=?", byte[].class, user);
    HttpClient weak = browser();
    login(weak);
    assertEquals(403, postJson(weak, "/api/mfa/rotation", Map.of()).statusCode());
    assertEquals(
        403,
        strong
            .send(
                HttpRequest.newBuilder(uri("/api/mfa/rotation"))
                    .POST(HttpRequest.BodyPublishers.ofString("{}"))
                    .build(),
                HttpResponse.BodyHandlers.ofString())
            .statusCode());
    var started = postJson(strong, "/api/mfa/rotation", Map.of());
    assertEquals(200, started.statusCode(), started.body());
    assertTrue(started.headers().firstValue("Cache-Control").orElse("").contains("no-store"));
    var replacement = json.readTree(started.body());
    String path = "/api/mfa/changes/" + replacement.get("id").asText() + "/confirm";
    byte[] secret =
        new org.apache.commons.codec.binary.Base32().decode(replacement.get("secret").asText());
    assertArrayEquals(
        original,
        jdbc.queryForObject(
            "SELECT secret_cipher FROM mfa_totp WHERE user_id=?", byte[].class, user));
    assertEquals(200, api(old.get("access_token").asText()).statusCode());
    assertEquals(
        400, postJson(weak, path, Map.of("code", otp(secret, Instant.now()))).statusCode());
    assertEquals(
        200, postJson(strong, path, Map.of("code", otp(secret, Instant.now()))).statusCode());
    assertEquals(401, get(strong, "/api/session/me").statusCode());
    assertEquals(401, api(old.get("access_token").asText()).statusCode());
    assertEquals(400, refresh("web", old.get("refresh_token").asText()).statusCode());
    assertArrayEquals(
        secret,
        new MfaSecretCipher(Base64.getEncoder().encodeToString(new byte[32]))
            .decrypt(
                user,
                jdbc.queryForObject(
                    "SELECT secret_cipher FROM mfa_totp WHERE user_id=?", byte[].class, user)));
    assertEquals(
        1,
        jdbc.queryForObject(
            "SELECT count(*) FROM mfa_factor_change WHERE state='COMMITTED' AND secret_cipher IS NULL",
            Integer.class));
    HttpClient fresh = browser();
    login(fresh);
    stepUp(fresh, secret, Instant.now().plusSeconds(30));
    assertEquals(200, api(tokens(fresh, "web").get("access_token").asText()).statusCode());
  }

  @Test
  void factorReplacementFailuresPersistAcrossSupersedingChangesAndLockForThirtyMinutes()
      throws Exception {
    seedFactor();
    var actor = strongPrincipal();
    for (int attempt = 0; attempt < 5; attempt++) {
      var change = factors.rotate(actor, "rotation-session");
      assertThrows(
          org.springframework.web.server.ResponseStatusException.class,
          () -> factors.confirm(actor, "rotation-session", change.id(), "invalid"));
    }
    assertEquals(
        5,
        jdbc.queryForObject(
            "SELECT failed_attempts FROM mfa_lifecycle_guard WHERE user_id=?",
            Integer.class,
            user));
    var locked =
        assertThrows(
            org.springframework.web.server.ResponseStatusException.class,
            () -> factors.rotate(actor, "new-session"));
    assertEquals(429, locked.getStatusCode().value());
    assertEquals(
        0L, jdbc.queryForObject("SELECT auth_epoch FROM iam_user WHERE id=?", Long.class, user));
    assertTrue(mfa.enrolled(user));
    jdbc.execute("UPDATE mfa_lifecycle_guard SET locked_until=now()-interval '1 second'");
    var change = factors.rotate(actor, "rotation-session");
    byte[] secret = new org.apache.commons.codec.binary.Base32().decode(change.secret());
    factors.confirm(actor, "rotation-session", change.id(), otp(secret, Instant.now()));
    assertEquals(
        0,
        jdbc.queryForObject(
            "SELECT failed_attempts FROM mfa_lifecycle_guard WHERE user_id=?",
            Integer.class,
            user));
  }

  @Test
  void replacementSupersessionCancellationExpiryAndRecencyDoNotModifyActiveFactor() {
    seedFactor();
    var actor = strongPrincipal();
    byte[] original =
        jdbc.queryForObject(
            "SELECT secret_cipher FROM mfa_totp WHERE user_id=?", byte[].class, user);
    var first = factors.rotate(actor, "owner");
    var second = factors.rotate(actor, "owner");
    assertThrows(
        org.springframework.web.server.ResponseStatusException.class,
        () -> factors.confirm(actor, "owner", first.id(), "123456"));
    assertThrows(
        org.springframework.web.server.ResponseStatusException.class,
        () -> factors.cancel(actor, "stranger", second.id()));
    factors.cancel(actor, "owner", second.id());
    var expired = factors.rotate(actor, "owner");
    jdbc.update(
        "UPDATE mfa_factor_change SET expires_at=now()-interval '1 second' WHERE id=?",
        expired.id());
    assertThrows(
        org.springframework.web.server.ResponseStatusException.class,
        () -> factors.confirm(actor, "owner", expired.id(), "123456"));
    assertEquals(1, factors.expire());
    assertEquals(
        3,
        jdbc.queryForObject(
            "SELECT count(*) FROM mfa_factor_change WHERE secret_cipher IS NULL", Integer.class));
    assertThrows(
        org.springframework.web.server.ResponseStatusException.class,
        () -> factors.rotate(actor.withMfa(Instant.now().minusSeconds(600)), "owner"));
    var stalePassword =
        register(
            new IdentityPrincipal(
                user, 0, Instant.now().minusSeconds(600), List.of("ROLE_USER"), Instant.now()));
    assertThrows(
        org.springframework.web.server.ResponseStatusException.class,
        () -> factors.rotate(stalePassword, "owner"));
    assertArrayEquals(
        original,
        jdbc.queryForObject(
            "SELECT secret_cipher FROM mfa_totp WHERE user_id=?", byte[].class, user));
  }

  @Test
  void concurrentFactorConfirmationCommitsOnlyOneReplacement() throws Exception {
    seedFactor();
    var actor = strongPrincipal();
    var change = factors.rotate(actor, "owner");
    String code =
        otp(new org.apache.commons.codec.binary.Base32().decode(change.secret()), Instant.now());
    ExecutorService pool = Executors.newFixedThreadPool(2);
    Callable<Boolean> confirm =
        () -> {
          try {
            factors.confirm(actor, "owner", change.id(), code);
            return true;
          } catch (org.springframework.web.server.ResponseStatusException
              | org.springframework.security.authentication.BadCredentialsException denied) {
            return false;
          }
        };
    try {
      var first = pool.submit(confirm);
      var second = pool.submit(confirm);
      assertNotEquals(first.get(10, TimeUnit.SECONDS), second.get(10, TimeUnit.SECONDS));
    } finally {
      pool.shutdownNow();
    }
    assertEquals(
        1L, jdbc.queryForObject("SELECT auth_epoch FROM iam_user WHERE id=?", Long.class, user));
    assertEquals(
        1,
        jdbc.queryForObject(
            "SELECT count(*) FROM auth_audit WHERE action='MFA_ROTATE_COMMITTED'", Integer.class));
  }

  @Test
  void administrativeFactorRecoveryRequiresCapabilityAndNewFactorBeforeTokenIssuance()
      throws Exception {
    HttpClient admin = administrator();
    jdbc.update(
        "INSERT INTO iam_user_role(user_id,role) VALUES (?,'ROLE_ADMIN_MFA_RECOVERY')", user);
    UUID target = target();
    byte[] previous = seedFactor(target);
    HttpClient oldBrowser = browser();
    login(oldBrowser, "E002");
    stepUp(oldBrowser, previous, Instant.now());
    var old = tokens(oldBrowser, "web");
    String path = "/api/admin/mfa/users/" + target + "/recovery",
        key = UUID.randomUUID().toString();
    var body =
        Map.of(
            "reason",
            "Verified employee through independent helpdesk procedure",
            "evidence_ref",
            "ticket:MFA-100/evidence");
    var issued = recoveryJson(admin, path, body, key);
    assertEquals(200, issued.statusCode(), issued.body());
    var grant = json.readTree(issued.body());
    String token = grant.get("token").asText();
    assertTrue(issued.headers().firstValue("Cache-Control").orElse("").contains("no-store"));
    assertEquals(
        DigestAuthorizationService.digest(token),
        jdbc.queryForObject("SELECT token_digest FROM mfa_recovery_grant", String.class));
    var repeated = recoveryJson(admin, path, body, key);
    assertEquals(200, repeated.statusCode());
    assertTrue(json.readTree(repeated.body()).get("token").isNull());
    assertEquals(
        409,
        recoveryJson(
                admin,
                path,
                Map.of("reason", "Different decision", "evidence_ref", "ticket:MFA-100/evidence"),
                key)
            .statusCode());
    assertEquals(
        1L, jdbc.queryForObject("SELECT auth_epoch FROM iam_user WHERE id=?", Long.class, target));
    assertEquals(401, get(oldBrowser, "/api/session/me").statusCode());
    assertEquals(401, api(old.get("access_token").asText()).statusCode());
    assertEquals(400, refresh("web", old.get("refresh_token").asText()).statusCode());
    HttpClient owner = browser(), stranger = browser();
    login(owner, "E002");
    login(stranger, "E002");
    assertEquals(403, postJson(owner, "/api/mfa/enrollment", Map.of()).statusCode());
    assertEquals(401, get(owner, authorize("web", "v".repeat(64))).statusCode());
    assertTrue(json.readTree(get(owner, "/api/mfa").body()).get("recovery_required").asBoolean());
    assertEquals(
        400, postJson(admin, "/api/mfa/recovery", Map.of("recovery_token", token)).statusCode());
    var started = postJson(owner, "/api/mfa/recovery", Map.of("recovery_token", token));
    assertEquals(200, started.statusCode(), started.body());
    var replacement = json.readTree(started.body());
    assertEquals(
        400, postJson(stranger, "/api/mfa/recovery", Map.of("recovery_token", token)).statusCode());
    String confirm = "/api/mfa/changes/" + replacement.get("id").asText() + "/confirm";
    byte[] secret =
        new org.apache.commons.codec.binary.Base32().decode(replacement.get("secret").asText());
    assertEquals(
        400, postJson(stranger, confirm, Map.of("code", otp(secret, Instant.now()))).statusCode());
    assertEquals(401, get(owner, authorize("web", "v".repeat(64))).statusCode());
    assertEquals(
        200, postJson(owner, confirm, Map.of("code", otp(secret, Instant.now()))).statusCode());
    assertFalse(mfa.recoveryRequired(target));
    assertEquals(
        2L, jdbc.queryForObject("SELECT auth_epoch FROM iam_user WHERE id=?", Long.class, target));
    HttpClient fresh = browser();
    login(fresh, "E002");
    stepUp(fresh, secret, Instant.now().plusSeconds(30));
    assertEquals(200, api(tokens(fresh, "web").get("access_token").asText()).statusCode());
  }

  @Test
  void recoveryAuthorizationChecksLiveRoleSelfSeparationCsrfAndTargetPasswordGate()
      throws Exception {
    HttpClient admin = administrator();
    UUID target = target();
    seedFactor(target);
    String key = UUID.randomUUID().toString();
    var body =
        Map.of(
            "reason",
            "Verified helpdesk case",
            "evidence_ref",
            "ticket:MFA-200/evidence",
            "actor_id",
            user.toString(),
            "roles",
            List.of("ROLE_ADMIN_MFA_RECOVERY"));
    String path = "/api/admin/mfa/users/" + target + "/recovery";
    assertEquals(403, recoveryJson(admin, path, body, key).statusCode());
    jdbc.update(
        "INSERT INTO iam_user_role(user_id,role) VALUES (?,'ROLE_ADMIN_MFA_RECOVERY')", user);
    assertEquals(
        403,
        recoveryJson(admin, "/api/admin/mfa/users/" + user + "/recovery", body, key).statusCode());
    assertEquals(
        403,
        admin
            .send(
                HttpRequest.newBuilder(uri(path))
                    .header("Content-Type", "application/json")
                    .header("Idempotency-Key", key)
                    .POST(HttpRequest.BodyPublishers.ofString(json.writeValueAsString(body)))
                    .build(),
                HttpResponse.BodyHandlers.ofString())
            .statusCode());
    HttpClient weak = browser();
    login(weak);
    assertEquals(403, recoveryJson(weak, path, body, key).statusCode());
    var stale =
        register(
            new IdentityPrincipal(
                user,
                0,
                Instant.now().minusSeconds(600),
                List.of("ROLE_ADMIN_MFA_RECOVERY"),
                Instant.now()));
    assertThrows(
        org.springframework.web.server.ResponseStatusException.class,
        () ->
            factors.authorizeRecovery(
                stale, target, key, "Verified case", "ticket:MFA-200/evidence"));
    jdbc.update("UPDATE iam_user SET password_gate='BLOCKED' WHERE id=?", target);
    assertEquals(409, recoveryJson(admin, path, body, key).statusCode());
    jdbc.update("UPDATE iam_user SET password_gate='OPEN' WHERE id=?", target);
    jdbc.update(
        "DELETE FROM iam_user_role WHERE user_id=? AND role='ROLE_ADMIN_MFA_RECOVERY'", user);
    assertEquals(403, recoveryJson(admin, path, body, key).statusCode());
    assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM mfa_recovery_grant", Integer.class));
  }

  @Test
  void recoveryGrantAndPendingConfirmationRejectExpiredRevokedOrStaleIssuers() throws Exception {
    var admin = recoveryOperator();
    UUID target = target();
    seedFactor(target);
    var expired =
        factors.authorizeRecovery(
            admin,
            target,
            UUID.randomUUID().toString(),
            "Verified case",
            "ticket:MFA-300/evidence");
    jdbc.update(
        "UPDATE mfa_recovery_grant SET expires_at=now()-interval '1 second' WHERE id=?",
        expired.id());
    var targetPrincipal =
        register(new IdentityPrincipal(target, 1, Instant.now(), List.of("ROLE_USER")));
    assertThrows(
        org.springframework.web.server.ResponseStatusException.class,
        () -> factors.recover(targetPrincipal, "owner", expired.token()));
    var fresh =
        factors.authorizeRecovery(
            admin,
            target,
            UUID.randomUUID().toString(),
            "Reverified case",
            "ticket:MFA-301/evidence");
    var current = register(new IdentityPrincipal(target, 2, Instant.now(), List.of("ROLE_USER")));
    jdbc.update(
        "DELETE FROM iam_user_role WHERE user_id=? AND role='ROLE_ADMIN_MFA_RECOVERY'", user);
    assertThrows(
        org.springframework.web.server.ResponseStatusException.class,
        () -> factors.recover(current, "owner", fresh.token()));
    jdbc.update(
        "INSERT INTO iam_user_role(user_id,role) VALUES (?,'ROLE_ADMIN_MFA_RECOVERY')", user);
    var pending = factors.recover(current, "owner", fresh.token());
    jdbc.update(
        "DELETE FROM iam_user_role WHERE user_id=? AND role='ROLE_ADMIN_MFA_RECOVERY'", user);
    assertThrows(
        org.springframework.web.server.ResponseStatusException.class,
        () ->
            factors.confirm(
                current,
                "owner",
                pending.id(),
                otp(
                    new org.apache.commons.codec.binary.Base32().decode(pending.secret()),
                    Instant.now())));
    jdbc.update(
        "INSERT INTO iam_user_role(user_id,role) VALUES (?,'ROLE_ADMIN_MFA_RECOVERY')", user);
    jdbc.update("UPDATE iam_user SET auth_epoch=auth_epoch+1 WHERE id=?", user);
    assertThrows(
        org.springframework.web.server.ResponseStatusException.class,
        () ->
            factors.confirm(
                current,
                "owner",
                pending.id(),
                otp(
                    new org.apache.commons.codec.binary.Base32().decode(pending.secret()),
                    Instant.now())));
    assertTrue(mfa.recoveryRequired(target));
    assertFalse(mfa.enrolled(target));
  }

  @Test
  void concurrentRecoveryRedemptionConsumesOneCapabilityAndExpiryNeverEnablesPasswordOnlyAccess()
      throws Exception {
    var admin = recoveryOperator();
    UUID target = target();
    seedFactor(target);
    var grant =
        factors.authorizeRecovery(
            admin,
            target,
            UUID.randomUUID().toString(),
            "Verified case",
            "ticket:MFA-400/evidence");
    var actor = register(new IdentityPrincipal(target, 1, Instant.now(), List.of("ROLE_USER")));
    ExecutorService pool = Executors.newFixedThreadPool(2);
    Callable<Boolean> redeem =
        () -> {
          try {
            factors.recover(actor, UUID.randomUUID().toString(), grant.token());
            return true;
          } catch (org.springframework.web.server.ResponseStatusException e) {
            return false;
          }
        };
    try {
      var first = pool.submit(redeem);
      var second = pool.submit(redeem);
      assertNotEquals(first.get(10, TimeUnit.SECONDS), second.get(10, TimeUnit.SECONDS));
    } finally {
      pool.shutdownNow();
    }
    assertEquals(
        1,
        jdbc.queryForObject(
            "SELECT count(*) FROM mfa_factor_change WHERE state='PENDING'", Integer.class));
    jdbc.execute("UPDATE mfa_factor_change SET expires_at=now()-interval '1 second'");
    assertEquals(1, factors.expire());
    assertThrows(
        org.springframework.web.server.ResponseStatusException.class, () -> mfa.enroll(actor));
    assertTrue(mfa.recoveryRequired(target));
    assertTrue(mfa.required(actor));
  }

  @Test
  void recoveryCancellationAndTargetEpochChangesNeverRemoveTheEnrollmentBarrier() {
    var admin = recoveryOperator();
    UUID target = target();
    seedFactor(target);
    var grant =
        factors.authorizeRecovery(
            admin,
            target,
            UUID.randomUUID().toString(),
            "Verified case",
            "ticket:MFA-500/evidence");
    var actor = register(new IdentityPrincipal(target, 1, Instant.now(), List.of("ROLE_USER")));
    var stale =
        register(
            new IdentityPrincipal(
                target, 1, Instant.now().minusSeconds(600), List.of("ROLE_USER")));
    assertThrows(
        org.springframework.web.server.ResponseStatusException.class,
        () -> factors.recover(stale, "owner", grant.token()));
    var pending = factors.recover(actor, "owner", grant.token());
    factors.cancel(actor, "owner", pending.id());
    assertThrows(
        org.springframework.web.server.ResponseStatusException.class,
        () -> factors.recover(actor, "owner", grant.token()));
    assertThrows(
        org.springframework.web.server.ResponseStatusException.class, () -> mfa.enroll(actor));
    assertTrue(mfa.recoveryRequired(target));
    assertFalse(mfa.enrolled(target));
    var fresh =
        factors.authorizeRecovery(
            admin,
            target,
            UUID.randomUUID().toString(),
            "Reverified case",
            "ticket:MFA-501/evidence");
    jdbc.update("UPDATE iam_user SET auth_epoch=auth_epoch+1 WHERE id=?", target);
    var changed = register(new IdentityPrincipal(target, 3, Instant.now(), List.of("ROLE_USER")));
    assertThrows(
        org.springframework.web.server.ResponseStatusException.class,
        () -> factors.recover(changed, "owner", fresh.token()));
    assertTrue(mfa.recoveryRequired(target));
    assertEquals(
        0,
        jdbc.queryForObject(
            "SELECT count(*) FROM mfa_factor_change WHERE secret_cipher IS NOT NULL",
            Integer.class));
  }

  @Test
  void factorConfirmationCommitFailureRestoresOriginalFactorAndCanBeSafelyRetried()
      throws Exception {
    seedFactor();
    var actor = strongPrincipal();
    byte[] original =
        jdbc.queryForObject(
            "SELECT secret_cipher FROM mfa_totp WHERE user_id=?", byte[].class, user);
    var pending = factors.rotate(actor, "owner");
    byte[] secret = new org.apache.commons.codec.binary.Base32().decode(pending.secret());
    jdbc.execute(
        "CREATE FUNCTION fail_mfa_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test factor commit failure'; END $$");
    jdbc.execute(
        "CREATE CONSTRAINT TRIGGER fail_mfa_commit AFTER UPDATE ON iam_user DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION fail_mfa_commit()");
    try {
      assertThrows(
          RuntimeException.class,
          () -> factors.confirm(actor, "owner", pending.id(), otp(secret, Instant.now())));
      assertArrayEquals(
          original,
          jdbc.queryForObject(
              "SELECT secret_cipher FROM mfa_totp WHERE user_id=?", byte[].class, user));
      assertEquals(
          0L, jdbc.queryForObject("SELECT auth_epoch FROM iam_user WHERE id=?", Long.class, user));
      assertEquals(
          "PENDING",
          jdbc.queryForObject(
              "SELECT state FROM mfa_factor_change WHERE id=?", String.class, pending.id()));
    } finally {
      jdbc.execute("DROP TRIGGER fail_mfa_commit ON iam_user");
      jdbc.execute("DROP FUNCTION fail_mfa_commit()");
    }
    factors.confirm(actor, "owner", pending.id(), otp(secret, Instant.now()));
    assertEquals(
        1L, jdbc.queryForObject("SELECT auth_epoch FROM iam_user WHERE id=?", Long.class, user));
  }

  @Test
  void totpEnrollmentFencesOldTokensAndAuthorizationRequiresBoundMfaChallenge() throws Exception {
    HttpClient browser = browser();
    var previous = tokens(browser, "web");
    assertEquals(
        403,
        browser
            .send(
                HttpRequest.newBuilder(uri("/api/mfa/enrollment"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString("{}"))
                    .build(),
                HttpResponse.BodyHandlers.ofString())
            .statusCode());
    var enrollment = postJson(browser, "/api/mfa/enrollment", Map.of());
    assertEquals(200, enrollment.statusCode(), enrollment.body());
    var details = json.readTree(enrollment.body());
    byte[] raw =
        new org.apache.commons.codec.binary.Base32().decode(details.get("secret").asText());
    assertFalse(
        Arrays.equals(
            raw,
            jdbc.queryForObject(
                "SELECT secret_cipher FROM mfa_totp WHERE user_id=?", byte[].class, user)));
    var confirmed =
        postJson(
            browser,
            "/api/mfa/enrollment/confirm",
            Map.of("code", otp(raw, Instant.now().minusSeconds(30))));
    assertEquals(200, confirmed.statusCode(), confirmed.body());
    assertEquals(401, api(previous.get("access_token").asText()).statusCode());
    assertEquals(401, get(browser, "/api/session/me").statusCode());
    login(browser);
    var required = get(browser, authorize("web", "v".repeat(64)));
    assertEquals(401, required.statusCode(), required.body());
    String context = json.readTree(required.body()).get("context").asText();
    var challenge = postJson(browser, "/api/mfa/challenges", Map.of("context", context));
    assertEquals(200, challenge.statusCode(), challenge.body());
    String challengeId = json.readTree(challenge.body()).get("challenge").asText();
    assertEquals(
        400,
        postJson(
                browser,
                "/api/mfa/verify",
                Map.of(
                    "context",
                    UUID.randomUUID().toString(),
                    "challenge",
                    challengeId,
                    "code",
                    otp(raw, Instant.now())))
            .statusCode());
    var verified =
        postJson(
            browser,
            "/api/mfa/verify",
            Map.of("context", context, "challenge", challengeId, "code", otp(raw, Instant.now())));
    assertEquals(200, verified.statusCode(), verified.body());
    assertEquals(
        400,
        postJson(
                browser,
                "/api/mfa/verify",
                Map.of(
                    "context", context, "challenge", challengeId, "code", otp(raw, Instant.now())))
            .statusCode());
    var strong = tokens(browser, "web");
    JsonNode claims =
        json.readTree(
            Base64.getUrlDecoder().decode(strong.get("id_token").asText().split("\\.")[1]));
    assertEquals(List.of("pwd", "otp"), json.convertValue(claims.get("amr"), List.class));
    assertEquals(200, refresh("web", strong.get("refresh_token").asText()).statusCode());
  }

  @Test
  void mfaChallengeCannotMoveBetweenSessionsOrContextsAndExpires() throws Exception {
    byte[] secret = seedFactor();
    var principal = principal();
    UUID context = UUID.randomUUID(),
        challenge = mfa.challenge(principal, "first-session", context);
    assertThrows(
        org.springframework.web.server.ResponseStatusException.class,
        () ->
            mfa.verifyChallenge(
                principal, "another-session", context, challenge, otp(secret, Instant.now())));
    assertThrows(
        org.springframework.web.server.ResponseStatusException.class,
        () ->
            mfa.verifyChallenge(
                principal,
                "first-session",
                UUID.randomUUID(),
                challenge,
                otp(secret, Instant.now())));
    jdbc.update(
        "UPDATE mfa_challenge SET expires_at=now()-interval '1 minute' WHERE id=?", challenge);
    assertThrows(
        org.springframework.web.server.ResponseStatusException.class,
        () ->
            mfa.verifyChallenge(
                principal, "first-session", context, challenge, otp(secret, Instant.now())));
    UUID fresh = mfa.challenge(principal, "first-session", context);
    String acceptedCode = otp(secret, Instant.now());
    assertNotNull(mfa.verifyChallenge(principal, "first-session", context, fresh, acceptedCode));
    UUID reuse = mfa.challenge(principal, "first-session", context);
    assertThrows(
        org.springframework.web.server.ResponseStatusException.class,
        () -> mfa.verifyChallenge(principal, "first-session", context, reuse, acceptedCode));
  }

  @Test
  void mfaFailureLockPersistsAcrossNewChallengesAndCommitsOnRejection() throws Exception {
    byte[] secret = seedFactor();
    var principal = principal();
    UUID context = UUID.randomUUID();
    for (int attempt = 0; attempt < 5; attempt++) {
      UUID challenge = mfa.challenge(principal, "session", context);
      assertThrows(
          org.springframework.web.server.ResponseStatusException.class,
          () -> mfa.verifyChallenge(principal, "session", context, challenge, "invalid"));
    }
    assertEquals(
        5,
        jdbc.queryForObject(
            "SELECT failed_attempts FROM mfa_totp WHERE user_id=?", Integer.class, user));
    UUID challenge = mfa.challenge(principal, "session", context);
    assertThrows(
        org.springframework.web.server.ResponseStatusException.class,
        () ->
            mfa.verifyChallenge(
                principal, "session", context, challenge, otp(secret, Instant.now())));
    jdbc.update("UPDATE mfa_totp SET locked_until=now()-interval '1 minute' WHERE user_id=?", user);
    assertNotNull(
        mfa.verifyChallenge(principal, "session", context, challenge, otp(secret, Instant.now())));
    assertEquals(
        0,
        jdbc.queryForObject(
            "SELECT failed_attempts FROM mfa_totp WHERE user_id=?", Integer.class, user));
  }

  @Test
  void concurrentMfaVerificationConsumesTheStepAndChallengeExactlyOnce() throws Exception {
    byte[] secret = seedFactor();
    var principal = principal();
    UUID context = UUID.randomUUID(), challenge = mfa.challenge(principal, "session", context);
    String code = otp(secret, Instant.now());
    ExecutorService pool = Executors.newFixedThreadPool(2);
    java.util.concurrent.Callable<Boolean> action =
        () -> {
          try {
            mfa.verifyChallenge(principal, "session", context, challenge, code);
            return true;
          } catch (org.springframework.web.server.ResponseStatusException e) {
            return false;
          }
        };
    try {
      var first = pool.submit(action);
      var second = pool.submit(action);
      assertNotEquals(first.get(10, TimeUnit.SECONDS), second.get(10, TimeUnit.SECONDS));
    } finally {
      pool.shutdownNow();
    }
  }

  private JsonNode tokens(HttpClient browser, String clientId) throws Exception {
    String verifier = "v".repeat(64), code = code(browser, clientId, verifier);
    var response = exchange(clientId, code, verifier);
    assertEquals(200, response.statusCode(), response.body());
    return json.readTree(response.body());
  }

  private HttpResponse<String> exchange(String clientId, String code, String verifier)
      throws Exception {
    return post(
        browser(),
        "/oauth/token",
        Map.of(
            "grant_type",
            "authorization_code",
            "code",
            code,
            "redirect_uri",
            CALLBACK,
            "code_verifier",
            verifier,
            "client_id",
            clientId),
        clientId);
  }

  private HttpResponse<String> refresh(String clientId, String token) throws Exception {
    return post(
        browser(),
        "/oauth/token",
        Map.of("grant_type", "refresh_token", "refresh_token", token, "client_id", clientId),
        clientId);
  }

  private HttpResponse<String> api(String token) throws Exception {
    return browser()
        .send(
            HttpRequest.newBuilder(uri("/api/resource/me"))
                .header("Authorization", "Bearer " + token)
                .GET()
                .build(),
            HttpResponse.BodyHandlers.ofString());
  }

  private HttpResponse<String> html(HttpClient client, String path) throws Exception {
    return client.send(
        HttpRequest.newBuilder(uri(path)).header("Accept", "text/html").GET().build(),
        HttpResponse.BodyHandlers.ofString());
  }

  private HttpResponse<String> signIn(HttpClient client, String employee) throws Exception {
    var csrf = json.readTree(get(client, "/api/public/csrf").body());
    return post(
        client,
        "/login",
        Map.of(
            "username",
            employee,
            "password",
            directory.password,
            csrf.get("parameter_name").asText(),
            csrf.get("token").asText()),
        null);
  }

  private UUID continuationId(HttpResponse<String> response) {
    assertEquals(302, response.statusCode(), response.body());
    String location = response.headers().firstValue("Location").orElseThrow();
    return UUID.fromString(
        FeishuFixture.parameters(URI.create(location).getRawQuery()).get("continue"));
  }

  private HttpResponse<String> continueFlow(HttpClient client, UUID id) throws Exception {
    var csrf = json.readTree(get(client, "/api/public/csrf").body());
    return post(
        client,
        "/portal/continue",
        Map.of(
            "id",
            id.toString(),
            "return_to",
            "https://evil.example",
            csrf.get("parameter_name").asText(),
            csrf.get("token").asText()),
        null);
  }

  @Test
  void portalShellIsPublicAndContainsOnlyLocalAssetsWithNoStoreAndCsp() throws Exception {
    for (String path :
        List.of(
            "/login",
            "/reset",
            "/portal/",
            "/portal/password",
            "/portal/mfa",
            "/portal/factors",
            "/portal/sessions",
            "/portal/binding")) {
      var page = html(browser(), path);
      assertEquals(200, page.statusCode(), page.body());
      assertTrue(page.headers().firstValue("Content-Type").orElse("").contains("text/html"));
      assertTrue(page.headers().firstValue("Cache-Control").orElse("").contains("no-store"));
      assertEquals("same-origin", page.headers().firstValue("Referrer-Policy").orElseThrow());
      assertTrue(
          page.headers()
              .firstValue("Content-Security-Policy")
              .orElse("")
              .contains("form-action 'self'"));
      assertTrue(page.body().contains("/portal/assets/"));
      assertFalse(page.body().contains("cdn."));
    }
    var root = get(browser(), "/");
    assertEquals(302, root.statusCode());
    assertTrue(root.headers().firstValue("Location").orElseThrow().endsWith("/portal/"));
    assertEquals(401, get(browser(), "/api/session/me").statusCode());
    // Assets must actually resolve from the packaged classpath, not only be referenced.
    var shell = html(browser(), "/portal/");
    var asset = Pattern.compile("(?:href|src)=\"(/portal/assets/[^\"]+)\"").matcher(shell.body());
    assertTrue(asset.find(), "no local asset referenced: " + shell.body());
    var contents =
        browser()
            .send(
                HttpRequest.newBuilder(uri(asset.group(1))).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    assertEquals(200, contents.statusCode(), asset.group(1));
    assertTrue(
        contents
            .headers()
            .firstValue("Content-Type")
            .orElse("")
            .matches("(?:(?:text|application)/javascript|text/css)(?:;.*)?"),
        contents.headers().firstValue("Content-Type").orElse(""));
    assertEquals(404, html(browser(), "/portal/assets/missing-never-built.js").statusCode());
  }

  @Test
  void everyBrowserWriteRejectsMissingForeignNullOrRepeatedOriginBeforeMutation() throws Exception {
    var client = browser();
    var csrf = json.readTree(get(client, "/api/public/csrf").body());
    for (String origin : List.of("", "null", "https://evil.example", ISSUER + "/")) {
      var request =
          HttpRequest.newBuilder(uri("/login"))
              .header("Content-Type", "application/x-www-form-urlencoded");
      if (!origin.isEmpty()) request.header("Origin", origin);
      var response =
          client.send(
              request
                  .POST(
                      HttpRequest.BodyPublishers.ofString(
                          "username=E001&password="
                              + enc(OLD)
                              + "&_csrf="
                              + enc(csrf.get("token").asText())))
                  .build(),
              HttpResponse.BodyHandlers.ofString());
      assertEquals(403, response.statusCode(), response.body());
    }
    var duplicated =
        HttpRequest.newBuilder(uri("/api/password/reset/request"))
            .header("Origin", ISSUER)
            .header("Origin", ISSUER)
            .header(csrf.get("header_name").asText(), csrf.get("token").asText())
            .header("Content-Type", "application/json");
    assertEquals(
        403,
        client
            .send(
                duplicated
                    .POST(HttpRequest.BodyPublishers.ofString("{\"employee_no\":\"E001\"}"))
                    .build(),
                HttpResponse.BodyHandlers.ofString())
            .statusCode());
    assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM iam_login", Integer.class));
    assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM reset_mail_request", Integer.class));
    assertEquals(302, signIn(client, "E001").statusCode());
  }

  @Test
  void htmlMfaContinuationSurvivesSidRotationAndCannotOverrideOrReplayItsTarget() throws Exception {
    byte[] secret = seedFactor();
    var client = browser();
    login(client);
    var blocked = html(client, authorize("web", "v".repeat(64)));
    UUID id = continuationId(blocked);
    assertTrue(blocked.headers().firstValue("Location").orElseThrow().contains("/portal/mfa"));
    stepUp(client, secret, Instant.now());
    var resumed = continueFlow(client, id);
    assertEquals(302, resumed.statusCode(), resumed.body());
    String target = resumed.headers().firstValue("Location").orElseThrow();
    assertTrue(
        target.startsWith("/oauth/authorize?")
            || target.startsWith("http://localhost:" + port + "/oauth/authorize?"),
        target);
    assertFalse(target.contains("evil.example"));
    assertEquals(400, continueFlow(client, id).statusCode());
    var authorized =
        html(client, URI.create(target).getRawPath() + "?" + URI.create(target).getRawQuery());
    assertEquals(302, authorized.statusCode(), authorized.body());
    assertTrue(authorized.headers().firstValue("Location").orElseThrow().startsWith(CALLBACK));
  }

  @Test
  void passwordCompletionPreservesOnlyValidatedContinuationAcrossAnonymousSessionReplacement()
      throws Exception {
    var client = browser();
    login(client);
    jdbc.update("UPDATE iam_user SET must_change_password=true WHERE id=?", user);
    var blocked = html(client, authorize("web", "v".repeat(64)));
    UUID id = continuationId(blocked);
    assertTrue(blocked.headers().firstValue("Location").orElseThrow().contains("/portal/password"));
    String key = UUID.randomUUID().toString();
    var changed =
        recoveryJson(
            client,
            "/api/password/change",
            Map.of("old_password", OLD, "new_password", NEW, "confirm_password", NEW),
            key);
    assertEquals(200, changed.statusCode(), changed.body());
    var status = get(client, "/api/password/requests/" + key + "/operation");
    assertEquals(200, status.statusCode(), status.body());
    assertEquals(json.readTree(changed.body()).get("id"), json.readTree(status.body()).get("id"));
    assertEquals(200, html(client, "/login?continue=" + id).statusCode());
    assertEquals(401, get(client, "/api/session/me").statusCode());
    var fresh = signIn(client, "E001");
    assertEquals(302, fresh.statusCode(), fresh.body());
    String target = fresh.headers().firstValue("Location").orElseThrow();
    assertTrue(target.contains("/oauth/authorize?"), target);
    var me = json.readTree(get(client, "/api/session/me").body());
    assertEquals(1, me.get("auth_epoch").asInt());
    assertTrue(me.get("password_recent").asBoolean());
    assertEquals(
        302,
        html(client, URI.create(target).getRawPath() + "?" + URI.create(target).getRawQuery())
            .statusCode());
    assertEquals(400, continueFlow(client, id).statusCode());
  }

  @Test
  void recoveryRequestLookupIsReadOnlyAndBoundToTheBrowserThatVerifiedEmail() throws Exception {
    contact();
    String proof = emailProof();
    var owner = browser();
    var verified = recoveryJson(owner, "/api/password/reset/verify", Map.of("token", proof), null);
    assertEquals(200, verified.statusCode(), verified.body());
    String key = UUID.randomUUID().toString();
    var changed =
        recoveryJson(
            owner,
            "/api/password/reset/confirm",
            Map.of(
                "reset_token",
                json.readTree(verified.body()).get("reset_token").asText(),
                "new_password",
                NEW,
                "confirm_password",
                NEW),
            key);
    assertEquals(200, changed.statusCode(), changed.body());
    String path = "/api/password/reset/requests/" + key + "/operation";
    assertEquals(200, get(owner, path).statusCode());
    assertEquals(404, get(browser(), path).statusCode());
    assertEquals(200, get(owner, path).statusCode());
    assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM password_operation", Integer.class));
    assertEquals(NEW, directory.password);
  }

  @Test
  void pendingAuthorizationCannotBeContinuedByADifferentFreshIdentity() throws Exception {
    target();
    var owner = browser();
    login(owner);
    jdbc.update("UPDATE iam_user SET must_change_password=true WHERE id=?", user);
    UUID id = continuationId(html(owner, authorize("web", "v".repeat(64))));
    var switched = signIn(owner, "E002");
    assertEquals(302, switched.statusCode(), switched.body());
    assertTrue(switched.headers().firstValue("Location").orElseThrow().endsWith("/portal/"));
    assertEquals(400, continueFlow(owner, id).statusCode());
    assertEquals(
        0, jdbc.queryForObject("SELECT count(*) FROM oauth2_authorization", Integer.class));
  }

  @Test
  void readOnlyRequestLookupDoesNotExposeAnotherIdentityOrAcceptARevokedLogin() throws Exception {
    UUID other = target();
    var owner = browser();
    login(owner);
    String key = UUID.randomUUID().toString();
    var changed =
        recoveryJson(
            owner,
            "/api/password/change",
            Map.of("old_password", OLD, "new_password", NEW, "confirm_password", NEW),
            key);
    assertEquals(200, changed.statusCode(), changed.body());
    var foreign = browser();
    login(foreign, "E002");
    assertEquals(404, get(foreign, "/api/password/requests/" + key + "/operation").statusCode());
    jdbc.update("UPDATE iam_login SET revoked_at=now() WHERE user_id=?", user);
    assertEquals(401, get(owner, "/api/password/requests/" + key + "/operation").statusCode());
    assertEquals(200, get(foreign, "/api/session/me").statusCode());
    assertEquals(
        other.toString(),
        json.readTree(get(foreign, "/api/session/me").body()).get("sub").asText());
  }

  @Test
  void discoveryAndJwksArePublicAndPrivateKeyNeverLeavesServer() throws Exception {
    var discovery = get(browser(), "/.well-known/openid-configuration");
    assertEquals(200, discovery.statusCode(), discovery.body());
    assertEquals(ISSUER, json.readTree(discovery.body()).get("issuer").asText());
    var keys = get(browser(), "/oauth/jwks");
    assertEquals(200, keys.statusCode());
    assertFalse(json.readTree(keys.body()).get("keys").get(0).has("d"));
  }

  @Test
  void strictRedirectPkceAndStateAreCheckedBeforeLoginRedirect() throws Exception {
    String path = authorize("web", "v".repeat(64));
    assertEquals(
        400,
        get(browser(), path.replace("code_challenge_method=S256", "code_challenge_method=plain"))
            .statusCode());
    assertEquals(
        400, get(browser(), path.replace(enc(CALLBACK), enc(CALLBACK + "/evil"))).statusCode());
    assertEquals(400, get(browser(), path.replace("state=test-state-123", "state=")).statusCode());
  }

  @Test
  void authorizationCodeIssuesSignedJwtAndStoresOnlyDigests() throws Exception {
    var tokens = tokens(browser(), "web");
    String access = tokens.get("access_token").asText(),
        refresh = tokens.get("refresh_token").asText();
    assertEquals(200, api(access).statusCode());
    assertEquals(
        0,
        jdbc.queryForObject(
            "SELECT count(*) FROM oauth2_authorization WHERE access_token_value=? OR refresh_token_value=?",
            Integer.class,
            access,
            refresh));
    assertTrue(
        jdbc.queryForObject("SELECT refresh_token_value FROM oauth2_authorization", String.class)
            .startsWith("sha256:"));
    assertNotNull(
        authorizations.findByToken(
            refresh,
            org.springframework.security.oauth2.server.authorization.OAuth2TokenType
                .REFRESH_TOKEN));
    var userinfo =
        browser()
            .send(
                HttpRequest.newBuilder(uri("/oauth/userinfo"))
                    .header("Authorization", "Bearer " + access)
                    .GET()
                    .build(),
                HttpResponse.BodyHandlers.ofString());
    assertEquals(200, userinfo.statusCode(), userinfo.body());
    assertEquals(user.toString(), json.readTree(userinfo.body()).get("sub").asText());
  }

  @Test
  void refreshRotationDetectsReuseAndRevokesTheFamily() throws Exception {
    var first = tokens(browser(), "web");
    var rotated = refresh("web", first.get("refresh_token").asText());
    assertEquals(200, rotated.statusCode(), rotated.body());
    var next = json.readTree(rotated.body());
    assertNotEquals(first.get("refresh_token"), next.get("refresh_token"));
    assertEquals(400, refresh("web", first.get("refresh_token").asText()).statusCode());
    assertEquals(401, api(next.get("access_token").asText()).statusCode());
    assertEquals(400, refresh("web", next.get("refresh_token").asText()).statusCode());
  }

  @Test
  void nativePublicClientReceivesAndRotatesRefreshWithoutSecret() throws Exception {
    var first = tokens(browser(), "native");
    assertTrue(first.has("refresh_token"));
    var next = refresh("native", first.get("refresh_token").asText());
    assertEquals(200, next.statusCode(), next.body());
    assertNotEquals(first.get("refresh_token"), json.readTree(next.body()).get("refresh_token"));
  }

  @Test
  void accessTokenCannotBeUsedAsRefreshToken() throws Exception {
    var first = tokens(browser(), "web");
    assertEquals(400, refresh("web", first.get("access_token").asText()).statusCode());
    assertEquals(200, api(first.get("access_token").asText()).statusCode());
  }

  @Test
  void codeIsConsumedExactlyOnceUnderConcurrentExchange() throws Exception {
    String verifier = "v".repeat(64), code = code(browser(), "web", verifier);
    ExecutorService pool = Executors.newFixedThreadPool(2);
    try {
      var a = pool.submit(() -> exchange("web", code, verifier));
      var b = pool.submit(() -> exchange("web", code, verifier));
      List<Integer> statuses =
          List.of(
              a.get(15, TimeUnit.SECONDS).statusCode(), b.get(15, TimeUnit.SECONDS).statusCode());
      assertEquals(1, statuses.stream().filter(s -> s == 200).count(), statuses.toString());
    } finally {
      pool.shutdownNow();
    }
  }

  @Test
  void wrongPkceVerifierAndWrongClientCannotRedeemCredentials() throws Exception {
    String verifier = "v".repeat(64), code = code(browser(), "web", verifier);
    assertEquals(400, exchange("web", code, "w".repeat(64)).statusCode());
    var first = tokens(browser(), "web");
    assertEquals(400, refresh("web-two", first.get("refresh_token").asText()).statusCode());
    assertEquals(200, refresh("web", first.get("refresh_token").asText()).statusCode());
    assertEquals(401, api(first.get("id_token").asText()).statusCode());
  }

  private UUID currentLogin(HttpClient browser) throws Exception {
    var response = get(browser, "/api/session/logins");
    assertEquals(200, response.statusCode(), response.body());
    for (var entry : json.readTree(response.body()).get("entries"))
      if (entry.get("current").asBoolean()) return UUID.fromString(entry.get("id").asText());
    throw new AssertionError("Current login missing");
  }

  @Test
  void individualRevocationDeniesOnlyThatLoginAndEveryAssociatedClientGrant() throws Exception {
    var owner = browser();
    var ownerToken = tokens(owner, "web");
    var victim = browser();
    var first = tokens(victim, "web");
    var second = tokens(victim, "web-two");
    var survivor = browser();
    var surviving = tokens(survivor, "web");
    UUID login = currentLogin(victim);
    assertEquals(
        204, postJson(owner, "/api/session/logins/" + login + "/revoke", Map.of()).statusCode());
    assertEquals(
        204, postJson(owner, "/api/session/logins/" + login + "/revoke", Map.of()).statusCode());
    assertEquals(401, get(victim, "/api/session/me").statusCode());
    assertEquals(401, api(first.get("access_token").asText()).statusCode());
    assertEquals(401, api(second.get("access_token").asText()).statusCode());
    assertEquals(400, refresh("web", first.get("refresh_token").asText()).statusCode());
    assertEquals(400, refresh("web-two", second.get("refresh_token").asText()).statusCode());
    assertEquals(200, api(ownerToken.get("access_token").asText()).statusCode());
    assertEquals(200, api(surviving.get("access_token").asText()).statusCode());
    assertEquals(
        0L, jdbc.queryForObject("SELECT auth_epoch FROM iam_user WHERE id=?", Long.class, user));
    assertEquals(
        1,
        jdbc.queryForObject(
            "SELECT count(*) FROM auth_audit WHERE action='LOGIN_REVOKED'", Integer.class));
    assertEquals(
        2,
        jdbc.queryForObject(
            "SELECT count(*) FROM oauth2_authorization WHERE revoked AND id IN (SELECT authorization_id FROM iam_login_grant WHERE login_id=?)",
            Integer.class,
            login));
  }

  @Test
  void sessionManagementRequiresCsrfOriginOwnershipAndRecentPassword() throws Exception {
    var owner = browser();
    login(owner);
    UUID current = currentLogin(owner);
    UUID foreign =
        register(new IdentityPrincipal(target(), 0, Instant.now(), List.of("ROLE_USER")))
            .getLoginId();
    String path = "/api/session/logins/" + current + "/revoke";
    var csrf = json.readTree(get(owner, "/api/session/csrf").body());
    for (String origin : List.of("", "null", "https://evil.example", ISSUER + "/")) {
      var request =
          HttpRequest.newBuilder(uri(path))
              .header("Content-Type", "application/json")
              .header(csrf.get("header_name").asText(), csrf.get("token").asText());
      if (!origin.isEmpty()) request.header("Origin", origin);
      assertEquals(
          403,
          owner
              .send(
                  request.POST(HttpRequest.BodyPublishers.ofString("{}")).build(),
                  HttpResponse.BodyHandlers.ofString())
              .statusCode());
    }
    assertEquals(
        403,
        owner
            .send(
                HttpRequest.newBuilder(uri(path))
                    .header("Origin", ISSUER)
                    .POST(HttpRequest.BodyPublishers.noBody())
                    .build(),
                HttpResponse.BodyHandlers.ofString())
            .statusCode());
    assertEquals(
        404, postJson(owner, "/api/session/logins/" + foreign + "/revoke", Map.of()).statusCode());
    assertEquals(
        404,
        postJson(owner, "/api/session/logins/" + UUID.randomUUID() + "/revoke", Map.of())
            .statusCode());
    assertEquals(404, get(owner, "/api/session/logins?before=" + foreign).statusCode());
    var stale =
        register(
            new IdentityPrincipal(user, 0, Instant.now().minusSeconds(600), List.of("ROLE_USER")));
    assertEquals(
        403,
        assertThrows(
                org.springframework.web.server.ResponseStatusException.class,
                () -> loginSessions.revoke(stale, current))
            .getStatusCode()
            .value());
    assertEquals(200, get(owner, "/api/session/me").statusCode());
  }

  @Test
  void sessionRevocationRequiresMfaAndStableLoginSurvivesBothStepUps() throws Exception {
    var owner = browser();
    login(owner);
    UUID login = currentLogin(owner);
    byte[] secret = seedFactor();
    assertEquals(
        403, postJson(owner, "/api/session/logins/" + login + "/revoke", Map.of()).statusCode());
    stepUp(owner, secret, Instant.now());
    assertEquals(login, currentLogin(owner));
    assertEquals(
        200, postJson(owner, "/api/session/reauthenticate", Map.of("password", OLD)).statusCode());
    assertEquals(login, currentLogin(owner));
    assertEquals(
        204, postJson(owner, "/api/session/logins/" + login + "/revoke", Map.of()).statusCode());
    assertNotEquals(200, get(owner, "/api/session/me").statusCode());
  }

  @Test
  void sessionListingUsesOwnerScopedPaginationAndNeverReturnsCredentials() throws Exception {
    var owner = browser();
    login(owner);
    UUID current = currentLogin(owner);
    for (int count = 0; count < 54; count++) principal();
    var page = get(owner, "/api/session/logins");
    assertEquals(200, page.statusCode(), page.body());
    var first = json.readTree(page.body());
    assertEquals(50, first.get("entries").size());
    assertFalse(first.get("nextCursor").isNull());
    var next = get(owner, "/api/session/logins?before=" + first.get("nextCursor").asText());
    var last = json.readTree(next.body());
    assertEquals(5, last.get("entries").size());
    assertTrue(last.get("nextCursor").isNull());
    Set<String> ids = new HashSet<>();
    for (var entry : first.get("entries")) assertTrue(ids.add(entry.get("id").asText()));
    for (var entry : last.get("entries")) assertTrue(ids.add(entry.get("id").asText()));
    assertTrue(ids.contains(current.toString()));
    assertFalse(page.body().contains("password"));
    assertFalse(page.body().contains("UNIPASS_SSO"));
    assertFalse(page.body().contains("token"));
  }

  @Test
  void deferredRevocationCommitFailureLeavesLoginAndTokensUsable() throws Exception {
    var owner = browser();
    login(owner);
    var victim = browser();
    var issued = tokens(victim, "web");
    UUID login = currentLogin(victim);
    jdbc.execute(
        "CREATE FUNCTION reject_login_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test login commit failure'; END $$");
    jdbc.execute(
        "CREATE CONSTRAINT TRIGGER reject_login_commit AFTER UPDATE ON iam_login DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.revoked_at IS NOT NULL AND OLD.revoked_at IS NULL) EXECUTE FUNCTION reject_login_commit()");
    try {
      assertEquals(
          503, postJson(owner, "/api/session/logins/" + login + "/revoke", Map.of()).statusCode());
      assertTrue(
          jdbc.queryForObject(
              "SELECT revoked_at IS NULL FROM iam_login WHERE id=?", Boolean.class, login));
      assertEquals(200, api(issued.get("access_token").asText()).statusCode());
      assertEquals(200, get(victim, "/api/session/me").statusCode());
    } finally {
      jdbc.execute("DROP TRIGGER reject_login_commit ON iam_login");
      jdbc.execute("DROP FUNCTION reject_login_commit()");
    }
    assertEquals(
        204, postJson(owner, "/api/session/logins/" + login + "/revoke", Map.of()).statusCode());
    assertEquals(401, api(issued.get("access_token").asText()).statusCode());
  }

  @Test
  void concurrentRefreshCannotEscapeIndividualRevocation() throws Exception {
    var owner = principal();
    var victim = browser();
    var issued = tokens(victim, "web");
    UUID login = currentLogin(victim);
    var pool = Executors.newFixedThreadPool(2);
    var start = new CountDownLatch(1);
    try {
      var refreshed =
          pool.submit(
              () -> {
                start.await();
                return refresh("web", issued.get("refresh_token").asText());
              });
      var revoked =
          pool.submit(
              () -> {
                start.await();
                loginSessions.revoke(owner, login);
                return true;
              });
      start.countDown();
      var response = refreshed.get(15, TimeUnit.SECONDS);
      assertTrue(revoked.get(15, TimeUnit.SECONDS));
      assertTrue(Set.of(200, 400).contains(response.statusCode()), response.body());
      if (response.statusCode() == 200) {
        var rotated = json.readTree(response.body());
        assertEquals(401, api(rotated.get("access_token").asText()).statusCode());
        assertEquals(400, refresh("web", rotated.get("refresh_token").asText()).statusCode());
      }
      assertEquals(401, api(issued.get("access_token").asText()).statusCode());
    } finally {
      pool.shutdownNow();
    }
  }

  @Test
  void individualRevocationDuringDirectoryVerificationPreventsPasswordWrite() throws Exception {
    var victim = principal();
    var owner = principal();
    var actor =
        com.unipass.password.AuthenticatedActor.user(
            user, 0, victim.getPasswordAuthenticatedAt(), victim.getLoginId());
    directory.afterVerify = () -> loginSessions.revoke(owner, victim.getLoginId());
    var failure =
        assertThrows(
            com.unipass.password.PasswordFailure.class,
            () ->
                passwords.change(
                    actor,
                    UUID.randomUUID().toString(),
                    OLD.toCharArray(),
                    NEW.toCharArray(),
                    NEW.toCharArray()));
    assertEquals(com.unipass.password.PasswordFailure.Code.STALE_SESSION, failure.code());
    assertEquals(OLD, directory.password);
    assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM password_operation", Integer.class));
    assertEquals(
        0L, jdbc.queryForObject("SELECT auth_epoch FROM iam_user WHERE id=?", Long.class, user));
  }

  @Test
  void unknownDeviceIsSampledOnceAndActivityCannotExtendOriginalLoginTime() {
    var actor = principal();
    UUID login = actor.getLoginId();
    loginSessions.seen(actor, "x".repeat(1025));
    var recorded =
        jdbc.queryForMap(
            "SELECT device,last_access_at,authenticated_at FROM iam_login WHERE id=?", login);
    assertEquals("Unknown", recorded.get("device"));
    loginSessions.seen(actor, "Mozilla/5.0 (Windows NT 10.0) Chrome/150.0 private-data");
    assertEquals(
        recorded,
        jdbc.queryForMap(
            "SELECT device,last_access_at,authenticated_at FROM iam_login WHERE id=?", login));
    jdbc.update("UPDATE iam_login SET last_access_at=now()-interval '2 minutes' WHERE id=?", login);
    loginSessions.seen(actor, null);
    var updated =
        jdbc.queryForMap(
            "SELECT device,last_access_at,authenticated_at FROM iam_login WHERE id=?", login);
    assertEquals(recorded.get("device"), updated.get("device"));
    assertEquals(recorded.get("authenticated_at"), updated.get("authenticated_at"));
    assertTrue(
        ((java.sql.Timestamp) updated.get("last_access_at"))
            .after((java.sql.Timestamp) recorded.get("last_access_at")));
  }

  @Test
  void individualRevocationEnqueuesBackchannelForThatLoginOnly() throws Exception {
    var client = clients.findByClientId("web");
    clients.save(
        RegisteredClient.from(client)
            .clientSettings(
                ClientSettings.withSettings(client.getClientSettings().getSettings())
                    .setting(
                        "unipass.backchannel_logout_uri", "https://rp.example.test/backchannel")
                    .build())
            .build());
    try {
      var owner = browser();
      var kept = tokens(owner, "web");
      var victim = browser();
      tokens(victim, "web");
      UUID login = currentLogin(victim);
      assertEquals(
          204, postJson(owner, "/api/session/logins/" + login + "/revoke", Map.of()).statusCode());
      assertEquals(
          1,
          jdbc.queryForObject(
              "SELECT count(*) FROM oidc_logout_task WHERE state='PENDING'", Integer.class));
      assertEquals(200, api(kept.get("access_token").asText()).statusCode());
    } finally {
      clients.save(client);
    }
  }

  @Test
  void revocationMakesJwtAndRefreshUnusable() throws Exception {
    var first = tokens(browser(), "web");
    var revoked =
        post(
            browser(),
            "/oauth/revoke",
            Map.of(
                "token", first.get("refresh_token").asText(), "token_type_hint", "refresh_token"),
            "web");
    assertEquals(200, revoked.statusCode(), revoked.body());
    assertEquals(401, api(first.get("access_token").asText()).statusCode());
    assertEquals(400, refresh("web", first.get("refresh_token").asText()).statusCode());
  }

  @Test
  void oidcLogoutValidatesCallbackAndGloballyFencesTokensAndSessions() throws Exception {
    HttpClient browser = browser();
    var first = tokens(browser, "web");
    String idToken = first.get("id_token").asText();
    JsonNode claims = json.readTree(Base64.getUrlDecoder().decode(idToken.split("\\.")[1]));
    assertTrue(claims.has("sid"));
    assertNotEquals(claims.get("sid"), claims.get("unipass_family"));
    var second = tokens(browser, "web-two");
    String logout = "/oauth/logout?id_token_hint=" + enc(idToken) + "&post_logout_redirect_uri=";
    var invalid = get(browser, logout + enc("https://evil.example/"));
    assertEquals(400, invalid.statusCode(), invalid.body());
    assertEquals(200, api(first.get("access_token").asText()).statusCode());
    var response = get(browser, logout + enc("https://rp.example.test/") + "&state=logout-state");
    assertEquals(302, response.statusCode(), response.body());
    assertEquals(
        "https://rp.example.test/?state=logout-state",
        response.headers().firstValue("Location").orElseThrow());
    assertEquals(401, api(first.get("access_token").asText()).statusCode());
    assertEquals(401, api(second.get("access_token").asText()).statusCode());
    assertEquals(400, refresh("web", first.get("refresh_token").asText()).statusCode());
  }

  @Test
  void expiredPasswordAllowsSelfServiceButPreventsAuthorizationAndTokenExchange() throws Exception {
    HttpClient browser = browser();
    String verifier = "v".repeat(64), code = code(browser, "web", verifier);
    jdbc.update("UPDATE iam_user SET must_change_password=true WHERE id=?", user);
    assertEquals(403, get(browser, authorize("web", verifier)).statusCode());
    assertEquals(200, get(browser, "/api/session/csrf").statusCode());
    assertEquals(400, exchange("web", code, verifier).statusCode());
  }

  @Test
  void missingAccountStateFailsClosedForApiAndBrowser() throws Exception {
    HttpClient browser = browser();
    var first = tokens(browser, "web");
    jdbc.execute("ALTER TABLE iam_user RENAME TO iam_user_fault_test");
    try {
      assertEquals(401, api(first.get("access_token").asText()).statusCode());
      var response = get(browser, "/api/session/me");
      assertEquals(503, response.statusCode());
      assertFalse(response.body().contains("SELECT"));
    } finally {
      jdbc.execute("ALTER TABLE iam_user_fault_test RENAME TO iam_user");
    }
  }

  @Test
  void packagedOperatorCliRegistersClientWithoutStartingWebServer() throws Exception {
    Path input = Path.of("target", "protocol-test", "client.json");
    Files.writeString(
        input,
        "{\"client_id\":\"cli-client\",\"name\":\"CLI test\",\"kind\":\"CONFIDENTIAL\",\"redirect_uris\":[\"https://cli.example/cb\"],\"post_logout_redirect_uris\":[],\"scopes\":[\"openid\"]}");
    Path log = Path.of("target", "protocol-test", "client-cli.log");
    var command =
        new ProcessBuilder(
            Path.of(System.getProperty("java.home"), "bin", windows() ? "java.exe" : "java")
                .toString(),
            "-Dloader.main=com.unipass.server.ClientAdminCli",
            "-cp",
            Path.of(
                    System.getProperty(
                        "test.server.exec.jar", "target/iam-server-0.1.0-SNAPSHOT-exec.jar"))
                .toAbsolutePath()
                .toString(),
            "org.springframework.boot.loader.launch.PropertiesLauncher",
            "register",
            input.toAbsolutePath().toString());
    command.environment().put("UNIPASS_DB_URL", postgres.getJdbcUrl("postgres", "postgres"));
    command.environment().put("UNIPASS_DB_USER", "postgres");
    command.environment().put("UNIPASS_DB_PASSWORD", "test");
    command
        .environment()
        .put("UNIPASS_CLIENT_SECRET", "test-only-generated-client-secret-0123456789");
    Process process = command.redirectErrorStream(true).redirectOutput(log.toFile()).start();
    try {
      assertTrue(process.waitFor(20, TimeUnit.SECONDS));
      assertEquals(0, process.exitValue(), Files.readString(log));
      assertNotNull(clients.findByClientId("cli-client"));
      assertFalse(Files.readString(log).contains("test-only-generated-client-secret"));
    } finally {
      if (process.isAlive()) process.destroyForcibly();
    }
  }

  @Test
  void passwordChangeRequiresCsrfAndRejectsOldJwtAndSession() throws Exception {
    HttpClient browser = browser();
    var token = tokens(browser, "web");
    JsonNode csrf = json.readTree(get(browser, "/api/session/csrf").body());
    String body =
        "{\"old_password\":\""
            + OLD
            + "\",\"new_password\":\""
            + NEW
            + "\",\"confirm_password\":\""
            + NEW
            + "\"}";
    var request =
        HttpRequest.newBuilder(uri("/api/password/change"))
            .header("Content-Type", "application/json")
            .header("Origin", ISSUER)
            .header("Idempotency-Key", UUID.randomUUID().toString());
    assertEquals(
        403,
        browser
            .send(
                request.POST(HttpRequest.BodyPublishers.ofString(body)).build(),
                HttpResponse.BodyHandlers.ofString())
            .statusCode());
    var changed =
        browser.send(
            request
                .header(csrf.get("header_name").asText(), csrf.get("token").asText())
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build(),
            HttpResponse.BodyHandlers.ofString());
    assertEquals(200, changed.statusCode(), changed.body());
    var op = json.readTree(changed.body());
    assertEquals(
        200, get(browser, "/api/password/operations/" + op.get("id").asText()).statusCode());
    assertEquals(401, api(token.get("access_token").asText()).statusCode());
    assertEquals(401, get(browser, "/api/session/me").statusCode());
    assertEquals(200, api(tokens(browser(), "web").get("access_token").asText()).statusCode());
  }

  static boolean windows() {
    return System.getProperty("os.name").startsWith("Windows");
  }

  @Test
  void passwordReauthenticationRequiresCsrfAndRotatesAnAuthenticatedSession() throws Exception {
    HttpClient browser = browser();
    login(browser);
    var cookies = ((CookieManager) browser.cookieHandler().orElseThrow()).getCookieStore();
    String before =
        cookies.getCookies().stream()
            .filter(cookie -> cookie.getName().equals("UNIPASS_SSO"))
            .findFirst()
            .orElseThrow()
            .getValue();
    assertEquals(
        403,
        browser
            .send(
                HttpRequest.newBuilder(uri("/api/session/reauthenticate"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString("{\"password\":\"unused\"}"))
                    .build(),
                HttpResponse.BodyHandlers.ofString())
            .statusCode());
    assertEquals(
        401,
        postJson(browser, "/api/session/reauthenticate", Map.of("password", "wrong-password"))
            .statusCode());
    assertEquals(
        200,
        postJson(browser, "/api/session/reauthenticate", Map.of("password", OLD)).statusCode());
    String after =
        cookies.getCookies().stream()
            .filter(cookie -> cookie.getName().equals("UNIPASS_SSO"))
            .findFirst()
            .orElseThrow()
            .getValue();
    assertNotEquals(before, after);
    assertEquals(200, get(browser, "/api/session/me").statusCode());
    assertEquals(
        1,
        jdbc.queryForObject(
            "SELECT count(*) FROM auth_audit WHERE action='PASSWORD_REAUTH_SUCCESS'",
            Integer.class));
  }

  @Test
  void federatedOtpCannotReplacePasswordProofAndReauthenticationKeepsLoginLifetime()
      throws Exception {
    feishuBind();
    var login = Instant.now().minusSeconds(600);
    var external =
        register(
            new IdentityPrincipal(
                user,
                0,
                login,
                List.of("ROLE_USER"),
                Instant.now(),
                IdentityPrincipal.Method.FEISHU,
                null));
    assertThrows(
        org.springframework.web.server.ResponseStatusException.class, () -> mfa.enroll(external));
    assertThrows(
        org.springframework.web.server.ResponseStatusException.class,
        () -> factors.rotate(external, "external-session"));
    char[] input = OLD.toCharArray();
    var upgraded = reauthentication.verify(external, input, "test:external");
    assertArrayEquals(new char[input.length], input);
    assertEquals(login, upgraded.getAuthenticatedAt());
    assertTrue(upgraded.hasRecentPassword(Instant.now()));
    assertEquals(List.of("feishu", "pwd", "otp"), upgraded.getAuthenticationMethods());
    assertEquals(
        0L, jdbc.queryForObject("SELECT auth_epoch FROM iam_user WHERE id=?", Long.class, user));
  }

  @Test
  void passwordReauthenticationRejectsEpochChangeDuringDirectoryVerification() {
    var principal = principal();
    char[] input = OLD.toCharArray();
    directory.afterVerify =
        () -> jdbc.update("UPDATE iam_user SET auth_epoch=auth_epoch+1 WHERE id=?", user);
    var failure =
        assertThrows(
            org.springframework.web.server.ResponseStatusException.class,
            () -> reauthentication.verify(principal, input, "test:race"));
    assertEquals(401, failure.getStatusCode().value());
    assertArrayEquals(new char[input.length], input);
    assertEquals(
        0,
        jdbc.queryForObject(
            "SELECT count(*) FROM auth_audit WHERE action='PASSWORD_REAUTH_SUCCESS'",
            Integer.class));
  }

  static String enc(String value) {
    return URLEncoder.encode(value, StandardCharsets.UTF_8);
  }

  private String feishuStart(HttpClient browser, boolean binding) throws Exception {
    var response =
        recoveryJson(
            browser,
            "/api/connector/feishu/" + (binding ? "binding" : "login") + "/start",
            Map.of(),
            null);
    assertEquals(200, response.statusCode(), response.body());
    return FeishuFixture.parameters(
            URI.create(json.readTree(response.body()).get("authorizationUrl").asText())
                .getRawQuery())
        .get("state");
  }

  private void feishuBind() throws Exception {
    var owner = browser();
    login(owner);
    String state = feishuStart(owner, true);
    var bound =
        get(
            owner,
            "/api/connector/feishu/callback?state=" + state + "&code=bind_" + UUID.randomUUID());
    assertEquals(200, bound.statusCode(), bound.body());
    assertTrue(json.readTree(bound.body()).get("bound").asBoolean());
  }

  private HttpClient feishuLogin() throws Exception {
    var browser = browser();
    String state = feishuStart(browser, false);
    var anonymousCsrf = json.readTree(get(browser, "/api/public/csrf").body());
    var cookies = ((CookieManager) browser.cookieHandler().orElseThrow()).getCookieStore();
    String before =
        cookies.getCookies().stream()
            .filter(cookie -> cookie.getName().equals("UNIPASS_SSO"))
            .findFirst()
            .orElseThrow()
            .getValue();
    var response =
        get(
            browser,
            "/api/connector/feishu/callback?state=" + state + "&code=login_" + UUID.randomUUID());
    assertEquals(200, response.statusCode(), response.body());
    String after =
        cookies.getCookies().stream()
            .filter(cookie -> cookie.getName().equals("UNIPASS_SSO"))
            .findFirst()
            .orElseThrow()
            .getValue();
    assertNotEquals(before, after);
    var oldProof =
        browser.send(
            HttpRequest.newBuilder(uri("/api/mfa/context"))
                .header("Content-Type", "application/json")
                .header(
                    anonymousCsrf.get("header_name").asText(), anonymousCsrf.get("token").asText())
                .POST(HttpRequest.BodyPublishers.ofString("{}"))
                .build(),
            HttpResponse.BodyHandlers.ofString());
    assertEquals(403, oldProof.statusCode(), oldProof.body());
    return browser;
  }

  private JsonNode feishuTokens(HttpClient browser) throws Exception {
    String verifier = "f".repeat(64);
    var response = get(browser, authorize("web", verifier));
    assertEquals(302, response.statusCode(), response.body());
    URI callback = URI.create(response.headers().firstValue("Location").orElseThrow());
    assertTrue(callback.toString().startsWith(CALLBACK), callback.toString());
    var exchanged =
        exchange("web", FeishuFixture.parameters(callback.getRawQuery()).get("code"), verifier);
    assertEquals(200, exchanged.statusCode(), exchanged.body());
    return json.readTree(exchanged.body());
  }

  @Test
  void feishuBrowserLoginIssuesFederatedOidcTokensAndRequiresPasswordForSensitiveActions()
      throws Exception {
    feishuBind();
    var browser = feishuLogin();
    assertEquals(200, get(browser, "/api/session/me").statusCode());
    var tokens = feishuTokens(browser);
    var claims =
        json.readTree(
            Base64.getUrlDecoder().decode(tokens.get("id_token").asText().split("\\.")[1]));
    assertEquals(json.readTree("[\"feishu\"]"), claims.get("amr"));
    assertEquals(200, api(tokens.get("access_token").asText()).statusCode());
    assertEquals(403, postJson(browser, "/api/mfa/enrollment", Map.of()).statusCode());
    assertEquals(
        403, postJson(browser, "/api/connector/feishu/binding/start", Map.of()).statusCode());
    assertEquals(
        200,
        postJson(browser, "/api/session/reauthenticate", Map.of("password", OLD)).statusCode());
    assertEquals(
        200, postJson(browser, "/api/connector/feishu/binding/start", Map.of()).statusCode());
    assertEquals(
        200, postJson(browser, "/api/connector/feishu/binding/remove", Map.of()).statusCode());
    assertEquals(401, api(tokens.get("access_token").asText()).statusCode());
    assertEquals(401, get(browser, "/api/session/me").statusCode());
  }

  @Test
  void feishuPermissionExpiryAndDisableInvalidateBrowserJwtIntrospectionAndRefresh()
      throws Exception {
    feishuBind();
    var browser = feishuLogin();
    var tokens = feishuTokens(browser);
    String access = tokens.get("access_token").asText();
    assertTrue(
        json.readTree(post(browser(), "/oauth/introspect", Map.of("token", access), "web").body())
            .get("active")
            .asBoolean());
    // Expiry without an UPDATE must also deny live credentials; no epoch trigger is needed.
    jdbc.execute("ALTER TABLE feishu_capability DISABLE TRIGGER feishu_capability_fence");
    try {
      jdbc.execute(
          "UPDATE feishu_capability SET verified_at=now()-interval '8 days',valid_until=now()-interval '1 day' WHERE capability='LOGIN'");
    } finally {
      jdbc.execute("ALTER TABLE feishu_capability ENABLE TRIGGER feishu_capability_fence");
    }
    assertEquals(401, api(access).statusCode());
    assertEquals(401, get(browser, "/api/session/me").statusCode());
    assertFalse(
        json.readTree(post(browser(), "/oauth/introspect", Map.of("token", access), "web").body())
            .get("active")
            .asBoolean());
    assertEquals(400, refresh("web", tokens.get("refresh_token").asText()).statusCode());
    new FeishuAdmin(jdbc, transactions)
        .recordLoginVerification("operator:fixture", "ticket:reverification");
    assertEquals(401, api(access).statusCode());
    assertEquals(
        0,
        jdbc.queryForObject(
            "SELECT count(*) FROM feishu_binding b JOIN iam_user u ON u.id=b.user_id AND b.bound_epoch=u.auth_epoch",
            Integer.class));
    feishuBind();
    var renewed = feishuLogin();
    var current = feishuTokens(renewed);
    new FeishuAdmin(jdbc, transactions).disable("operator:fixture", "ticket:disabled");
    assertEquals(401, api(current.get("access_token").asText()).statusCode());
    assertEquals(401, get(renewed, "/api/session/me").statusCode());
  }

  @Test
  void feishuCallbackRejectsCrossBrowserDuplicateQueryAndReplayAndStartNeedsCsrf()
      throws Exception {
    var owner = browser();
    assertEquals(
        403,
        owner
            .send(
                HttpRequest.newBuilder(uri("/api/connector/feishu/login/start"))
                    .POST(HttpRequest.BodyPublishers.noBody())
                    .build(),
                HttpResponse.BodyHandlers.ofString())
            .statusCode());
    String state = feishuStart(owner, false);
    var stranger = browser();
    get(stranger, "/api/public/csrf");
    String path = "/api/connector/feishu/callback?state=" + state + "&code=unbound_code";
    assertEquals(401, get(stranger, path).statusCode());
    assertEquals(401, get(owner, path + "&state=" + state).statusCode());
    assertEquals(0, feishuRemote.calls.get());
    assertEquals(401, get(owner, path).statusCode());
    assertEquals(401, get(owner, path).statusCode());
    assertEquals(1, feishuRemote.calls.get());
  }

  @Test
  void feishuLoginRetainsExistingMfaChallengeRequirement() throws Exception {
    feishuBind();
    byte[] secret = seedFactor(user);
    var passwordBrowser = browser();
    login(passwordBrowser);
    assertEquals(
        403,
        postJson(passwordBrowser, "/api/connector/feishu/binding/start", Map.of()).statusCode());
    var browser = feishuLogin();
    var required = get(browser, authorize("web", "v".repeat(64)));
    assertEquals(401, required.statusCode(), required.body());
    assertEquals(
        403, postJson(browser, "/api/connector/feishu/binding/start", Map.of()).statusCode());
    stepUp(browser, secret, Instant.now());
    var tokens = feishuTokens(browser);
    var claims =
        json.readTree(
            Base64.getUrlDecoder().decode(tokens.get("id_token").asText().split("\\.")[1]));
    assertEquals(json.readTree("[\"feishu\",\"otp\"]"), claims.get("amr"));
    assertEquals(403, postJson(browser, "/api/mfa/rotation", Map.of()).statusCode());
  }

  @Test
  void directoryPasswordChangeRequiresExplicitRenewalBeforeFeishuCanLoginAgain() throws Exception {
    feishuBind();
    var external = feishuLogin();
    var old = feishuTokens(external);
    var owner = browser();
    login(owner);
    var changed =
        recoveryJson(
            owner,
            "/api/password/change",
            Map.of("old_password", OLD, "new_password", NEW, "confirm_password", NEW),
            UUID.randomUUID().toString());
    assertEquals(200, changed.statusCode(), changed.body());
    assertEquals(401, api(old.get("access_token").asText()).statusCode());
    assertEquals(401, get(external, "/api/session/me").statusCode());
    var denied = browser();
    String state = feishuStart(denied, false);
    assertEquals(
        401,
        get(denied, "/api/connector/feishu/callback?state=" + state + "&code=stale_binding")
            .statusCode());
    feishuBind();
    assertEquals(200, get(feishuLogin(), "/api/session/me").statusCode());
  }

  @TestConfiguration
  static class TestDirectory {
    @Bean
    FakeDirectory fakeDirectory() {
      return new FakeDirectory();
    }

    @Bean
    @org.springframework.context.annotation.Primary
    TestMail testMail() {
      return new TestMail();
    }

    @Bean
    FeishuFixture feishuFixture() throws Exception {
      return new FeishuFixture();
    }

    @Bean
    @org.springframework.context.annotation.Primary
    FeishuService testFeishuService(
        JdbcTemplate jdbc,
        org.springframework.transaction.support.TransactionTemplate tx,
        AccountState accounts,
        MfaService mfa,
        Clock clock,
        FeishuFixture fixture) {
      return new FeishuService(jdbc, tx, accounts, mfa, clock, fixture.client());
    }
  }

  static class TestMail implements RecoveryEmailSender {
    final List<String> links = new ArrayList<>(), recipients = new ArrayList<>();
    boolean fail;
    Runnable beforeSend = () -> {};

    void reset() {
      links.clear();
      recipients.clear();
      fail = false;
      beforeSend = () -> {};
    }

    public boolean available() {
      return true;
    }

    public void send(String recipient, String link) {
      links.add(link);
      recipients.add(recipient);
      beforeSend.run();
      if (fail) throw new IllegalStateException("Test transport failure");
    }
  }

  static class FakeDirectory implements DirectoryGateway {
    volatile String password;
    volatile Runnable afterVerify = () -> {};

    @Override
    public DirectoryConfig.Type type() {
      return DirectoryConfig.Type.OPENLDAP;
    }

    @Override
    public Optional<DirectoryUser> findByStableId(String id) {
      return Optional.of(new DirectoryUser(id, "E001", "uid=one,dc=example", false));
    }

    @Override
    public boolean verifyCredential(String id, char[] value) {
      boolean matches = password.equals(new String(value));
      afterVerify.run();
      return matches;
    }

    @Override
    public void changePassword(String id, char[] old, char[] next) {
      if (!verifyCredential(id, old)) throw new DirectoryFailure(DirectoryFailure.Kind.REJECTED);
      password = new String(next);
    }

    @Override
    public void disableUser(String id) {}

    @Override
    public boolean supportsPasswordReset() {
      return true;
    }

    @Override
    public void resetPassword(String id, char[] next) {
      password = new String(next);
    }
  }
}
