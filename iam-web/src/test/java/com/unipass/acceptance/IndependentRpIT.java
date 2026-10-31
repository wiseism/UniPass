package com.unipass.acceptance;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.*;
import com.sun.net.httpserver.*;
import com.unboundid.ldap.listener.*;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.util.ssl.*;
import com.unipass.server.ClientRegistrationService;
import com.unipass.web.EncryptedSessionSerializer;
import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import java.io.*;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.regex.*;
import org.junit.jupiter.api.*;
import org.springframework.data.redis.connection.*;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;

/** Real executable IAM + two RP JVMs. No in-process authentication or fake directory adapter. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class IndependentRpIT {
  private static final String PASSWORD = "Qx!7vN2$pk",
      NEXT = "Rz@8mP4#st",
      STORE_PASSWORD = "rp-test-store-password";
  private final ObjectMapper json = new ObjectMapper();
  private final List<Process> owned = new ArrayList<>();
  private final Map<String, String> sessionKeys = new HashMap<>();
  private Path signingStore;
  private com.unipass.server.BackchannelLogoutWorker logoutWorker;
  private Path root;
  private EmbeddedPostgres pg;
  private InMemoryDirectoryServer ldap;
  private HttpServer proxy;
  private ExecutorService proxyPool;
  private LettuceConnectionFactory redis;
  private JdbcTemplate jdbc;
  private UUID user, anchor;
  private int iamPort, proxyPort, redisPort;
  private String redisPassword;
  private final Map<String, Integer> rpPorts = new LinkedHashMap<>();
  private final AtomicBoolean introspectionUnavailable = new AtomicBoolean(),
      dropRefreshResponse = new AtomicBoolean();
  private final AtomicInteger refreshCalls = new AtomicInteger();
  private final List<Long> revocationMillis = new ArrayList<>();

  private static String encode(String value) {
    return URLEncoder.encode(value, StandardCharsets.UTF_8);
  }

  private static int port() throws IOException {
    try (var socket = new ServerSocket(0)) {
      return socket.getLocalPort();
    }
  }

  private static String java() {
    return Path.of(
            System.getProperty("java.home"),
            "bin",
            System.getProperty("os.name").startsWith("Windows") ? "java.exe" : "java")
        .toString();
  }

  private String issuer() {
    return "http://localhost:" + proxyPort;
  }

  private String rp(String name) {
    return "http://localhost:" + rpPorts.get(name);
  }

  private HttpClient browser() {
    return HttpClient.newBuilder()
        .cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL))
        .connectTimeout(Duration.ofSeconds(2))
        .followRedirects(HttpClient.Redirect.NEVER)
        .build();
  }

  private HttpResponse<String> get(HttpClient client, String uri) throws Exception {
    return client.send(
        HttpRequest.newBuilder(URI.create(uri)).timeout(Duration.ofSeconds(15)).GET().build(),
        HttpResponse.BodyHandlers.ofString());
  }

  private HttpResponse<String> form(HttpClient client, String uri, Map<String, String> values)
      throws Exception {
    String body =
        values.entrySet().stream()
            .map(e -> encode(e.getKey()) + "=" + encode(e.getValue()))
            .collect(java.util.stream.Collectors.joining("&"));
    var request =
        HttpRequest.newBuilder(URI.create(uri))
            .timeout(Duration.ofSeconds(15))
            .header("Content-Type", "application/x-www-form-urlencoded");
    if (uri.equals(issuer() + "/login")) request.header("Origin", issuer());
    return client.send(
        request.POST(HttpRequest.BodyPublishers.ofString(body)).build(),
        HttpResponse.BodyHandlers.ofString());
  }

  private Process launch(String name, List<String> arguments, Map<String, String> environment)
      throws Exception {
    List<String> command = new ArrayList<>(List.of(java()));
    command.addAll(arguments);
    var builder = new ProcessBuilder(command);
    builder.environment().keySet().removeIf(key -> key.startsWith("UNIPASS_"));
    builder.environment().putAll(environment);
    Process process =
        builder
            .redirectErrorStream(true)
            .redirectOutput(root.resolve(name + ".log").toFile())
            .start();
    owned.add(process);
    return process;
  }

  private void ready(Process process, String uri, String name) throws Exception {
    long deadline = System.nanoTime() + Duration.ofSeconds(45).toNanos();
    while (System.nanoTime() < deadline) {
      if (!process.isAlive())
        throw new AssertionError(
            name + " exited: " + Files.readString(root.resolve(name + ".log")));
      try {
        if (get(browser(), uri).statusCode() == 200) return;
      } catch (IOException ignored) {
      }
      Thread.sleep(100);
    }
    throw new AssertionError(
        name + " startup timed out: " + Files.readString(root.resolve(name + ".log")));
  }

  @BeforeAll
  void start() throws Exception {
    root = Files.createDirectories(Path.of("target", "independent-rp")).toAbsolutePath();
    iamPort = port();
    proxyPort = port();
    redisPort = port();
    rpPorts.put("crm", port());
    rpPorts.put("hrm", port());
    Path keys = root.resolve("test-" + UUID.randomUUID() + ".p12");
    signingStore = keys;
    Process keytool =
        new ProcessBuilder(
                Path.of(
                        System.getProperty("java.home"),
                        "bin",
                        System.getProperty("os.name").startsWith("Windows")
                            ? "keytool.exe"
                            : "keytool")
                    .toString(),
                "-genkeypair",
                "-alias",
                "current",
                "-keyalg",
                "RSA",
                "-keysize",
                "2048",
                "-validity",
                "2",
                "-dname",
                "CN=localhost",
                "-ext",
                "SAN=dns:localhost",
                "-storetype",
                "PKCS12",
                "-keystore",
                keys.toString(),
                "-storepass",
                STORE_PASSWORD,
                "-noprompt")
            .redirectErrorStream(true)
            .redirectOutput(root.resolve("keytool.log").toFile())
            .start();
    try {
      assertTrue(keytool.waitFor(20, TimeUnit.SECONDS));
      assertEquals(0, keytool.exitValue());
    } finally {
      if (keytool.isAlive()) keytool.destroyForcibly();
    }
    var ssl =
        new SSLUtil(
            new KeyStoreKeyManager(
                keys.toFile(), STORE_PASSWORD.toCharArray(), "PKCS12", "current"),
            new TrustStoreTrustManager(
                keys.toFile(), STORE_PASSWORD.toCharArray(), "PKCS12", true));
    var config = new InMemoryDirectoryServerConfig("dc=example,dc=test");
    config.setSchema(null);
    config.addAdditionalBindCredentials("cn=reader", "reader-test-only");
    config.addAdditionalBindCredentials("cn=writer", "writer-test-only");
    config.setListenerConfigs(
        InMemoryListenerConfig.createLDAPSConfig(
            "ldaps",
            InetAddress.getLoopbackAddress(),
            0,
            ssl.createSSLServerSocketFactory(),
            ssl.createSSLSocketFactory()));
    ldap = new InMemoryDirectoryServer(config);
    ldap.startListening();
    anchor = UUID.randomUUID();
    ldap.add("dn: dc=example,dc=test", "objectClass: domain", "dc: example");
    ldap.add(
        "dn: uid=one,dc=example,dc=test",
        "objectClass: inetOrgPerson",
        "cn: One",
        "sn: User",
        "uid: one",
        "employeeNumber: E001",
        "entryUUID: " + anchor,
        "userPassword: " + PASSWORD);
    System.setProperty(
        "ot.epg.working-dir", Files.createDirectories(root.resolve("postgres")).toString());
    pg =
        EmbeddedPostgres.builder()
            .setPort(0)
            .setServerConfig("listen_addresses", "127.0.0.1")
            .start();
    redisPassword = UUID.randomUUID().toString();
    String executable =
        System.getProperty(
            "test.redis.executable",
            System.getenv().getOrDefault("UNIPASS_TEST_REDIS_EXECUTABLE", "redis-server"));
    Process cache =
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
    owned.add(cache);
    var redisConfig = new RedisStandaloneConfiguration("127.0.0.1", redisPort);
    redisConfig.setPassword(redisPassword);
    redis = new LettuceConnectionFactory(redisConfig);
    redis.afterPropertiesSet();
    redis.start();
    proxy = HttpServer.create(new InetSocketAddress("localhost", proxyPort), 0);
    proxyPool = Executors.newCachedThreadPool();
    proxy.setExecutor(proxyPool);
    proxy.createContext("/", this::forward);
    proxy.start();
    Map<String, String> env =
        new HashMap<>(
            Map.of(
                "UNIPASS_DB_URL",
                pg.getJdbcUrl("postgres", "postgres"),
                "UNIPASS_DB_USER",
                "postgres",
                "UNIPASS_DB_PASSWORD",
                "test",
                "UNIPASS_REDIS_PORT",
                Integer.toString(redisPort),
                "UNIPASS_REDIS_PASSWORD",
                redisPassword,
                "UNIPASS_ISSUER",
                issuer(),
                "UNIPASS_SIGNING_STORE",
                keys.toString(),
                "UNIPASS_SIGNING_PASSWORD",
                STORE_PASSWORD,
                "UNIPASS_SIGNING_ALIAS",
                "current",
                "UNIPASS_MFA_KEY",
                Base64.getEncoder().encodeToString(new byte[32])));
    env.putAll(
        Map.of(
            "UNIPASS_DIRECTORY_TYPE",
            "OPENLDAP",
            "UNIPASS_LDAP_URL",
            "ldaps://localhost:" + ldap.getListenPort(),
            "UNIPASS_LDAP_BASE_DN",
            "dc=example,dc=test",
            "UNIPASS_LDAP_READ_DN",
            "cn=reader",
            "UNIPASS_LDAP_READ_PASSWORD",
            "reader-test-only",
            "UNIPASS_LDAP_WRITE_DN",
            "cn=writer",
            "UNIPASS_LDAP_WRITE_PASSWORD",
            "writer-test-only",
            "UNIPASS_LDAP_WRITABLE_CONFIRMED",
            "true",
            "UNIPASS_PASSWORD_HISTORY_VERIFIED",
            "true"));
    Path server =
        Path.of(
                System.getProperty(
                    "test.iam.exec.jar", "../iam-server/target/iam-server-0.1.0-SNAPSHOT-exec.jar"))
            .toAbsolutePath();
    Process iam =
        launch(
            "iam",
            List.of(
                "-Djavax.net.ssl.trustStore=" + keys,
                "-Djavax.net.ssl.trustStorePassword=" + STORE_PASSWORD,
                "-Djavax.net.ssl.trustStoreType=PKCS12",
                "-jar",
                server.toString(),
                "--server.port=" + iamPort,
                "--server.address=127.0.0.1",
                "--unipass.local-http=true",
                "--unipass.jobs.enabled=false"),
            env);
    ready(iam, issuer() + "/.well-known/openid-configuration", "iam");
    jdbc =
        new JdbcTemplate(
            new DriverManagerDataSource(pg.getJdbcUrl("postgres", "postgres"), "postgres", "test"));
    user = UUID.randomUUID();
    jdbc.update("INSERT INTO import_source(source_id,cursor_value) VALUES ('rp-test','1')");
    jdbc.update(
        "INSERT INTO iam_user(id,employee_no,directory_id,directory_type,ldap_dn,display_name,status,source_id,source_version) VALUES (?,'E001',?,'OPENLDAP','uid=one,dc=example,dc=test','Test User','ACTIVE','rp-test',1)",
        user,
        anchor);
    var keyEnv =
        new org.springframework.mock.env.MockEnvironment()
            .withProperty("unipass.signing.store", keys.toString())
            .withProperty("unipass.signing.password", STORE_PASSWORD)
            .withProperty("unipass.signing.alias", "current")
            .withProperty("unipass.issuer", issuer());
    logoutWorker =
        new com.unipass.server.BackchannelLogoutWorker(
            jdbc,
            new org.springframework.transaction.support.TransactionTemplate(
                new org.springframework.jdbc.datasource.DataSourceTransactionManager(
                    jdbc.getDataSource())),
            signingKeys(),
            Clock.systemUTC(),
            keyEnv);
    var registrar = new ClientRegistrationService(new JdbcRegisteredClientRepository(jdbc), true);
    Path web =
        Path.of(System.getProperty("test.web.exec.jar", "target/iam-web-0.1.0-SNAPSHOT-exec.jar"))
            .toAbsolutePath();
    for (var app : rpPorts.entrySet()) {
      String name = app.getKey(),
          secret = UUID.randomUUID() + "+%:",
          sessionKey =
              Base64.getEncoder()
                  .encodeToString(
                      UUID.randomUUID()
                          .toString()
                          .substring(0, 32)
                          .getBytes(StandardCharsets.UTF_8));
      sessionKeys.put(name, sessionKey);
      registrar.register(
          new ClientRegistrationService.Spec(
              name,
              "Independent " + name,
              ClientRegistrationService.Kind.CONFIDENTIAL,
              List.of(rp(name) + "/login/oauth2/code/unipass"),
              List.of(rp(name) + "/"),
              Set.of("openid", "profile", "api.read"),
              rp(name) + "/logout/backchannel"),
          secret);
      Process process =
          launch(
              name,
              List.of(
                  "-jar",
                  web.toString(),
                  "--server.address=127.0.0.1",
                  "--unipass.rp.local-http=true"),
              Map.of(
                  "UNIPASS_RP_PORT",
                  Integer.toString(app.getValue()),
                  "UNIPASS_RP_ID",
                  name,
                  "UNIPASS_RP_ISSUER",
                  issuer(),
                  "UNIPASS_RP_ORIGIN",
                  rp(name),
                  "UNIPASS_RP_CLIENT_SECRET",
                  secret,
                  "UNIPASS_RP_SESSION_KEY",
                  sessionKey,
                  "UNIPASS_RP_REDIS_PORT",
                  Integer.toString(redisPort),
                  "UNIPASS_RP_REDIS_PASSWORD",
                  redisPassword));
      ready(process, rp(name) + "/health", name);
    }
  }

  private void forward(HttpExchange exchange) throws IOException {
    String path = exchange.getRequestURI().getPath();
    if (introspectionUnavailable.get() && path.equals("/oauth/introspect")) {
      exchange.sendResponseHeaders(503, -1);
      exchange.close();
      return;
    }
    byte[] body = exchange.getRequestBody().readAllBytes();
    boolean refresh =
        path.equals("/oauth/token")
            && new String(body, StandardCharsets.UTF_8).contains("grant_type=refresh_token");
    if (refresh) refreshCalls.incrementAndGet();
    try {
      var request =
          HttpRequest.newBuilder(
                  URI.create("http://localhost:" + iamPort + exchange.getRequestURI()))
              .timeout(Duration.ofSeconds(10))
              .method(
                  exchange.getRequestMethod(),
                  body.length == 0
                      ? HttpRequest.BodyPublishers.noBody()
                      : HttpRequest.BodyPublishers.ofByteArray(body));
      for (String header :
          List.of(
              "Authorization",
              "Cookie",
              "Content-Type",
              "Origin",
              "X-CSRF-TOKEN",
              "Idempotency-Key")) {
        String value = exchange.getRequestHeaders().getFirst(header);
        if (value != null) request.header(header, value);
      }
      var response =
          HttpClient.newBuilder()
              .connectTimeout(Duration.ofSeconds(2))
              .followRedirects(HttpClient.Redirect.NEVER)
              .build()
              .send(request.build(), HttpResponse.BodyHandlers.ofByteArray());
      if (refresh && dropRefreshResponse.getAndSet(false) && response.statusCode() == 200) {
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, response.body().length + 100);
        exchange.getResponseBody().write("{\"acc".getBytes(StandardCharsets.UTF_8));
        return;
      }
      response
          .headers()
          .map()
          .forEach(
              (key, values) -> {
                if (!Set.of("transfer-encoding", "content-length", "connection")
                    .contains(key.toLowerCase(Locale.ROOT)))
                  exchange.getResponseHeaders().put(key, new ArrayList<>(values));
              });
      exchange.sendResponseHeaders(
          response.statusCode(), response.body().length == 0 ? -1 : response.body().length);
      if (response.body().length > 0) exchange.getResponseBody().write(response.body());
    } catch (Exception failure) {
      try {
        exchange.sendResponseHeaders(502, -1);
      } catch (IOException ignored) {
      }
    } finally {
      exchange.close();
    }
  }

  @BeforeEach
  void reset() throws Exception {
    introspectionUnavailable.set(false);
    dropRefreshResponse.set(false);
    refreshCalls.set(0);
    jdbc.execute("TRUNCATE oidc_logout_task");
    jdbc.execute("TRUNCATE oauth2_authorization CASCADE");
    jdbc.execute("TRUNCATE auth_audit");
    jdbc.update(
        "UPDATE iam_user SET auth_epoch=auth_epoch+1,password_gate='OPEN',status='ACTIVE' WHERE id=?",
        user);
    ldap.modify(
        "uid=one,dc=example,dc=test",
        new Modification(ModificationType.REPLACE, "userPassword", PASSWORD));
  }

  private String callback(HttpClient client, String name, boolean credentials, String password)
      throws Exception {
    var start = get(client, rp(name) + "/oauth2/authorization/unipass");
    assertEquals(302, start.statusCode(), start.body());
    String authorization = start.headers().firstValue("Location").orElseThrow();
    assertTrue(authorization.contains("code_challenge_method=S256"), authorization);
    assertTrue(authorization.contains("nonce="));
    assertTrue(authorization.contains("state="));
    var response = get(client, authorization);
    String location = response.headers().firstValue("Location").orElse("");
    if (credentials) {
      assertTrue(location.contains("/login"), location);
      var page = get(client, issuer() + "/api/public/csrf");
      assertEquals(200, page.statusCode(), page.body());
      var csrf = json.readTree(page.body());
      assertEquals(
          302,
          form(
                  client,
                  issuer() + "/login",
                  Map.of(
                      "username",
                      "E001",
                      "password",
                      password,
                      csrf.get("parameter_name").asText(),
                      csrf.get("token").asText()))
              .statusCode());
      response = get(client, authorization);
      location = response.headers().firstValue("Location").orElse("");
    }
    assertEquals(302, response.statusCode(), response.body());
    assertTrue(location.startsWith(rp(name) + "/login/oauth2/code/unipass"), location);
    return location;
  }

  private void login(HttpClient client, String name, boolean credentials) throws Exception {
    assertEquals(302, get(client, callback(client, name, credentials, PASSWORD)).statusCode());
    assertEquals(200, get(client, rp(name) + "/bff/profile").statusCode());
  }

  private record Stored(
      String key, byte[] attribute, OAuth2AuthorizedClient client, OidcUser user) {}

  @SuppressWarnings("unchecked")
  private Stored stored(HttpClient browser, String app, boolean expire) {
    String cookie =
        ((CookieManager) browser.cookieHandler().orElseThrow())
            .getCookieStore().getCookies().stream()
                .filter(c -> c.getName().equals("UNIPASS_RP_" + app))
                .findFirst()
                .orElseThrow()
                .getValue();
    String session = new String(Base64.getDecoder().decode(cookie), StandardCharsets.UTF_8),
        key = "unipass:rp:" + app + ":sessions:" + session;
    var serializer = new EncryptedSessionSerializer(sessionKeys.get(app), "unipass:rp:" + app);
    try (var connection = redis.getConnection()) {
      Map<byte[], byte[]> entries =
          connection.hashCommands().hGetAll(key.getBytes(StandardCharsets.UTF_8));
      OAuth2AuthorizedClient client = null;
      OidcUser user = null;
      byte[] attribute = null;
      for (var entry : entries.entrySet()) {
        Object value = serializer.deserialize(entry.getValue());
        if (value instanceof Map<?, ?> map
            && map.get("unipass") instanceof OAuth2AuthorizedClient found) {
          client = found;
          attribute = entry.getKey();
          if (expire) {
            var expired =
                new OAuth2AccessToken(
                    found.getAccessToken().getTokenType(),
                    found.getAccessToken().getTokenValue(),
                    Instant.now().minusSeconds(3600),
                    Instant.now().minusSeconds(1),
                    found.getAccessToken().getScopes());
            var next = new HashMap<String, Object>((Map<String, Object>) map);
            next.put(
                "unipass",
                new OAuth2AuthorizedClient(
                    found.getClientRegistration(),
                    found.getPrincipalName(),
                    expired,
                    found.getRefreshToken()));
            connection
                .hashCommands()
                .hSet(
                    key.getBytes(StandardCharsets.UTF_8),
                    entry.getKey(),
                    serializer.serialize(next));
          }
        }
        if (value instanceof SecurityContext security)
          user = (OidcUser) security.getAuthentication().getPrincipal();
      }
      assertNotNull(client);
      assertNotNull(user);
      for (byte[] value : entries.values()) {
        String raw = new String(value, StandardCharsets.ISO_8859_1);
        assertFalse(raw.contains(client.getAccessToken().getTokenValue()));
        assertFalse(raw.contains(client.getRefreshToken().getTokenValue()));
      }
      return new Stored(key, attribute, client, user);
    }
  }

  private HttpResponse<String> api(String name, String token) throws Exception {
    return browser()
        .send(
            HttpRequest.newBuilder(URI.create(rp(name) + "/api/resource/data"))
                .timeout(Duration.ofSeconds(10))
                .header("Authorization", "Bearer " + token)
                .GET()
                .build(),
            HttpResponse.BodyHandlers.ofString());
  }

  @Test
  void independentRpProcessesUseSsoWithoutExposingCredentialsAndEnforceResourceContext()
      throws Exception {
    HttpClient browser = browser();
    login(browser, "crm", true);
    login(browser, "hrm", false);
    assertEquals(
        1,
        jdbc.queryForObject(
            "SELECT count(*) FROM auth_audit WHERE action='LOGIN_SUCCESS'", Integer.class));
    var crm = stored(browser, "crm", false);
    var hr = stored(browser, "hrm", false);
    assertNotEquals(
        crm.client.getAccessToken().getTokenValue(), hr.client.getAccessToken().getTokenValue());
    assertEquals(200, api("crm", crm.client.getAccessToken().getTokenValue()).statusCode());
    assertEquals(401, api("hrm", crm.client.getAccessToken().getTokenValue()).statusCode());
    assertEquals(401, api("crm", crm.user.getIdToken().getTokenValue()).statusCode());
    var data = get(browser, rp("crm") + "/bff/data");
    assertEquals(200, data.statusCode(), data.body());
    assertEquals(user.toString(), json.readTree(data.body()).get("sub").asText());
    assertFalse(data.body().contains("token"));
  }

  @Test
  void callbackStateCannotBeForgedMovedToAnotherRpOrReplayed() throws Exception {
    HttpClient browser = browser();
    String callback = callback(browser, "crm", true, PASSWORD);
    assertEquals(
        401, get(browser, callback.replaceAll("state=[^&]+", "state=forged-state")).statusCode());
    assertEquals(401, get(browser, callback.replace(rp("crm"), rp("hrm"))).statusCode());
    assertEquals(302, get(browser, callback).statusCode());
    assertEquals(401, get(browser, callback).statusCode());
  }

  @Test
  void liveStatusFailureDeniesBothCookieAndBearerRequestsAndRecoversWithoutStaleAcceptance()
      throws Exception {
    HttpClient browser = browser();
    login(browser, "crm", true);
    String token = stored(browser, "crm", false).client.getAccessToken().getTokenValue();
    assertEquals(200, api("crm", token).statusCode());
    introspectionUnavailable.set(true);
    try {
      assertEquals(503, get(browser, rp("crm") + "/bff/profile").statusCode());
      assertEquals(503, api("crm", token).statusCode());
    } finally {
      introspectionUnavailable.set(false);
    }
    assertEquals(200, get(browser, rp("crm") + "/bff/profile").statusCode());
  }

  @Test
  void concurrentRefreshIsSerializedBeforeSessionLoadAndCommitsOnlyOneRotation() throws Exception {
    HttpClient browser = browser();
    login(browser, "crm", true);
    String previous = stored(browser, "crm", true).client.getRefreshToken().getTokenValue();
    int baseline = refreshCalls.get();
    ExecutorService pool = Executors.newFixedThreadPool(6);
    CountDownLatch start = new CountDownLatch(1);
    List<Future<Integer>> requests = new ArrayList<>();
    try {
      for (int n = 0; n < 6; n++)
        requests.add(
            pool.submit(
                () -> {
                  start.await();
                  return get(browser, rp("crm") + "/bff/profile").statusCode();
                }));
      start.countDown();
      List<Integer> statuses = new ArrayList<>();
      for (var request : requests) statuses.add(request.get(15, TimeUnit.SECONDS));
      assertTrue(statuses.contains(200), statuses.toString());
      assertTrue(statuses.stream().allMatch(s -> s == 200 || s == 409), statuses.toString());
    } finally {
      pool.shutdownNow();
    }
    assertEquals(baseline + 1, refreshCalls.get());
    assertNotEquals(
        previous, stored(browser, "crm", false).client.getRefreshToken().getTokenValue());
    assertEquals(200, get(browser, rp("crm") + "/bff/profile").statusCode());
  }

  @Test
  void committedRefreshWithLostResponseClearsSessionAndNeverReplaysOldRefresh() throws Exception {
    HttpClient browser = browser();
    login(browser, "crm", true);
    stored(browser, "crm", true);
    int before = refreshCalls.get();
    dropRefreshResponse.set(true);
    assertEquals(401, get(browser, rp("crm") + "/bff/profile").statusCode());
    assertEquals(before + 1, refreshCalls.get());
    assertEquals(401, get(browser, rp("crm") + "/bff/profile").statusCode());
    assertEquals(before + 1, refreshCalls.get());
    assertEquals(
        0,
        jdbc.queryForObject(
            "SELECT count(*) FROM auth_audit WHERE action='TOKEN_REUSE_DETECTED'", Integer.class));
  }

  @Test
  void staleSessionSnapshotCannotReplayAnAlreadyAttemptedRefreshCredential() throws Exception {
    HttpClient browser = browser();
    login(browser, "crm", true);
    Stored stale = stored(browser, "crm", true);
    byte[] snapshot;
    try (var connection = redis.getConnection()) {
      snapshot =
          connection
              .hashCommands()
              .hGet(stale.key.getBytes(StandardCharsets.UTF_8), stale.attribute);
    }
    assertEquals(200, get(browser, rp("crm") + "/bff/profile").statusCode());
    int calls = refreshCalls.get();
    try (var connection = redis.getConnection()) {
      connection
          .hashCommands()
          .hSet(stale.key.getBytes(StandardCharsets.UTF_8), stale.attribute, snapshot);
    }
    assertEquals(401, get(browser, rp("crm") + "/bff/profile").statusCode());
    assertEquals(calls, refreshCalls.get());
    assertEquals(
        0,
        jdbc.queryForObject(
            "SELECT count(*) FROM auth_audit WHERE action='TOKEN_REUSE_DETECTED'", Integer.class));
  }

  @Test
  void directoryPasswordChangeInvalidatesBothIndependentRpsAndTheirApiTokens() throws Exception {
    HttpClient browser = browser();
    login(browser, "crm", true);
    login(browser, "hrm", false);
    String token = stored(browser, "hrm", false).client.getAccessToken().getTokenValue();
    var csrf = json.readTree(get(browser, issuer() + "/api/session/csrf").body());
    String body =
        json.writeValueAsString(
            Map.of("old_password", PASSWORD, "new_password", NEXT, "confirm_password", NEXT));
    long started = System.nanoTime();
    var changed =
        browser.send(
            HttpRequest.newBuilder(URI.create(issuer() + "/api/password/change"))
                .header("Content-Type", "application/json")
                .header("Origin", issuer())
                .header(csrf.get("header_name").asText(), csrf.get("token").asText())
                .header("Idempotency-Key", UUID.randomUUID().toString())
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build(),
            HttpResponse.BodyHandlers.ofString());
    assertEquals(200, changed.statusCode(), changed.body());
    assertEquals(401, get(browser, rp("crm") + "/bff/profile").statusCode());
    assertEquals(401, get(browser, rp("hrm") + "/bff/profile").statusCode());
    assertEquals(401, api("hrm", token).statusCode());
    revocationMillis.add(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started));
  }

  @Test
  void rpLogoutRequiresOriginAndCsrfAndInvalidatesTheOtherRpOnItsNextRequest() throws Exception {
    HttpClient browser = browser();
    login(browser, "crm", true);
    login(browser, "hrm", false);
    var csrf = json.readTree(get(browser, rp("crm") + "/csrf").body());
    assertEquals(
        403,
        form(browser, rp("crm") + "/logout", Map.of("_csrf", csrf.get("token").asText()))
            .statusCode());
    assertEquals(
        403,
        browser
            .send(
                HttpRequest.newBuilder(URI.create(rp("crm") + "/logout"))
                    .header("Origin", rp("crm"))
                    .POST(HttpRequest.BodyPublishers.noBody())
                    .build(),
                HttpResponse.BodyHandlers.ofString())
            .statusCode());
    var response =
        browser.send(
            HttpRequest.newBuilder(URI.create(rp("crm") + "/logout"))
                .header("Origin", rp("crm"))
                .header(csrf.get("header_name").asText(), csrf.get("token").asText())
                .POST(HttpRequest.BodyPublishers.noBody())
                .build(),
            HttpResponse.BodyHandlers.ofString());
    assertEquals(302, response.statusCode());
    String logout = response.headers().firstValue("Location").orElseThrow();
    assertTrue(logout.startsWith(issuer() + "/oauth/logout"), logout);
    var ended = get(browser, logout);
    assertEquals(302, ended.statusCode(), ended.body());
    assertEquals(rp("crm") + "/", ended.headers().firstValue("Location").orElseThrow());
    assertEquals(401, get(browser, rp("hrm") + "/bff/profile").statusCode());
  }

  private com.nimbusds.jose.jwk.source.JWKSource<com.nimbusds.jose.proc.SecurityContext>
      signingKeys() throws Exception {
    var store = java.security.KeyStore.getInstance("PKCS12");
    try (var input = Files.newInputStream(signingStore)) {
      store.load(input, STORE_PASSWORD.toCharArray());
    }
    var key =
        new com.nimbusds.jose.jwk.RSAKey.Builder(
                (java.security.interfaces.RSAPublicKey)
                    store.getCertificate("current").getPublicKey())
            .privateKey(
                (java.security.interfaces.RSAPrivateKey)
                    store.getKey("current", STORE_PASSWORD.toCharArray()))
            .keyID("current")
            .build();
    return new com.nimbusds.jose.jwk.source.ImmutableJWKSet<>(
        new com.nimbusds.jose.jwk.JWKSet(key));
  }

  private String logoutToken(String audience, String sid, String subject, Map<String, Object> extra)
      throws Exception {
    var claims =
        org.springframework.security.oauth2.jwt.JwtClaimsSet.builder()
            .issuer(issuer())
            .audience(List.of(audience))
            .issuedAt(Instant.now())
            .expiresAt(Instant.now().plusSeconds(120))
            .id(UUID.randomUUID().toString())
            .claim("sid", sid)
            .claim(
                "events", Map.of("http://schemas.openid.net/event/backchannel-logout", Map.of()));
    if (subject != null) claims.subject(subject);
    extra.forEach(
        (name, value) -> {
          if (value == null) claims.claims(values -> values.remove(name));
          else claims.claim(name, value);
        });
    return new org.springframework.security.oauth2.jwt.NimbusJwtEncoder(signingKeys())
        .encode(
            org.springframework.security.oauth2.jwt.JwtEncoderParameters.from(
                org.springframework.security.oauth2.jwt.JwsHeader.with(
                        org.springframework.security.oauth2.jose.jws.SignatureAlgorithm.RS256)
                    .keyId("current")
                    .type("logout+jwt")
                    .build(),
                claims.build()))
        .getTokenValue();
  }

  @Test
  void durableNotificationDeletesBothRpSessionsWithoutBrowserTrafficAndBlocksRestoredSnapshot()
      throws Exception {
    HttpClient browser = browser();
    login(browser, "crm", true);
    login(browser, "hrm", false);
    Stored crm = stored(browser, "crm", false), hr = stored(browser, "hrm", false);
    Map<byte[], byte[]> snapshot;
    try (var c = redis.getConnection()) {
      snapshot = c.hashCommands().hGetAll(hr.key.getBytes(StandardCharsets.UTF_8));
    }
    jdbc.update("UPDATE iam_user SET auth_epoch=auth_epoch+1 WHERE id=?", user);
    assertEquals(
        2,
        jdbc.queryForObject(
            "SELECT count(*) FROM oidc_logout_task WHERE state='PENDING'", Integer.class));
    assertTrue(logoutWorker.runOnce());
    assertTrue(logoutWorker.runOnce());
    assertFalse(logoutWorker.runOnce());
    assertEquals(
        2,
        jdbc.queryForObject(
            "SELECT count(*) FROM oidc_logout_task WHERE state='SENT'", Integer.class));
    try (var c = redis.getConnection()) {
      assertFalse(c.keyCommands().exists(crm.key.getBytes(StandardCharsets.UTF_8)));
      assertFalse(c.keyCommands().exists(hr.key.getBytes(StandardCharsets.UTF_8)));
      c.hashCommands().hMSet(hr.key.getBytes(StandardCharsets.UTF_8), snapshot);
      c.keyCommands().expire(hr.key.getBytes(StandardCharsets.UTF_8), 60);
    }
    var template = new org.springframework.data.redis.core.StringRedisTemplate(redis);
    var settings =
        new com.unipass.web.RpSettings(
            new org.springframework.mock.env.MockEnvironment()
                .withProperty("unipass.rp.id", "crm")
                .withProperty(
                    "unipass.rp.secret", crm.client.getClientRegistration().getClientSecret())
                .withProperty("unipass.rp.issuer", issuer())
                .withProperty("unipass.rp.origin", rp("crm"))
                .withProperty("unipass.rp.local-http", "true")
                .withProperty("server.address", "127.0.0.1"));
    assertFalse(
        new com.unipass.web.BackchannelSessions(template, settings)
            .bind(UUID.randomUUID().toString(), crm.user));
    assertEquals(401, get(browser, rp("hrm") + "/bff/profile").statusCode());
  }

  @Test
  void signedLogoutValidatesAudienceEventsNonceTimeSubjectAndJtiWithoutBrowserCredentials()
      throws Exception {
    HttpClient browser = browser();
    login(browser, "crm", true);
    Stored stored = stored(browser, "crm", false);
    String sid = stored.user.getIdToken().getClaimAsString("sid");
    String valid = logoutToken("crm", sid, user.toString(), Map.of());
    String[] parts = valid.split("\\.");
    byte[] signature = Base64.getUrlDecoder().decode(parts[2]);
    signature[0] ^= 1;
    String forged =
        parts[0]
            + "."
            + parts[1]
            + "."
            + Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
    for (String invalid :
        List.of(
            forged,
            logoutToken("crm", sid, user.toString(), Collections.singletonMap("aud", null)),
            logoutToken("crm", sid, user.toString(), Collections.singletonMap("sid", null)),
            logoutToken("crm", sid, user.toString(), Collections.singletonMap("jti", null)),
            logoutToken("hrm", sid, user.toString(), Map.of()),
            logoutToken("crm", sid, user.toString(), Map.of("nonce", "forbidden")),
            logoutToken("crm", sid, user.toString(), Map.of("events", Map.of())),
            logoutToken("crm", sid, UUID.randomUUID().toString(), Map.of()),
            logoutToken(
                "crm", sid, user.toString(), Map.of("iat", Instant.now().minusSeconds(600))),
            logoutToken("crm", sid, user.toString(), Map.of("iat", Instant.now().plusSeconds(90))),
            logoutToken(
                "crm",
                sid,
                user.toString(),
                Map.of(
                    "iat", Instant.now().minusSeconds(120), "exp", Instant.now().minusSeconds(1))),
            logoutToken(
                "crm", sid, user.toString(), Map.of("iss", "https://wrong.example.test")))) {
      assertEquals(
          400,
          form(browser(), rp("crm") + "/logout/backchannel", Map.of("logout_token", invalid))
              .statusCode());
      assertEquals(200, get(browser, rp("crm") + "/bff/profile").statusCode());
    }
    assertEquals(
        400,
        form(
                browser(),
                rp("crm") + "/logout/backchannel",
                Map.of("logout_token", stored.user.getIdToken().getTokenValue()))
            .statusCode());
    assertEquals(400, form(browser(), rp("crm") + "/logout/backchannel", Map.of()).statusCode());
    assertEquals(
        400,
        form(browser(), rp("crm") + "/logout/backchannel?logout_token=" + encode(valid), Map.of())
            .statusCode());
    var request =
        HttpRequest.newBuilder(URI.create(rp("crm") + "/logout/backchannel"))
            .timeout(Duration.ofSeconds(10))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString("logout_token=" + encode(valid)))
            .build();
    var first = browser().sendAsync(request, HttpResponse.BodyHandlers.ofString());
    var second = browser().sendAsync(request, HttpResponse.BodyHandlers.ofString());
    assertEquals(
        List.of(200, 400),
        java.util.stream.Stream.of(first.get(), second.get())
            .map(HttpResponse::statusCode)
            .sorted()
            .toList());
    assertEquals(
        400,
        form(browser(), rp("crm") + "/logout/backchannel", Map.of("logout_token", valid))
            .statusCode());
    assertEquals(401, get(browser, rp("crm") + "/bff/profile").statusCode());
  }

  @Test
  void failedDeliveryRetriesAndExhaustedLeaseBecomesDead() throws Exception {
    HttpClient browser = browser();
    login(browser, "crm", true);
    jdbc.update("UPDATE iam_user SET auth_epoch=auth_epoch+1 WHERE id=?", user);
    // Fault injection changes only this test's persisted delivery destination to a closed port.
    String target = jdbc.queryForObject("SELECT target_uri FROM oidc_logout_task", String.class);
    jdbc.update(
        "UPDATE oidc_logout_task SET target_uri=?",
        "http://localhost:" + port() + "/logout/backchannel");
    assertTrue(logoutWorker.runOnce());
    assertEquals(
        "PENDING", jdbc.queryForObject("SELECT state FROM oidc_logout_task", String.class));
    jdbc.update(
        "UPDATE oidc_logout_task SET target_uri=?,next_attempt_at=now()-interval '1 second'",
        target);
    assertTrue(logoutWorker.runOnce());
    assertEquals("SENT", jdbc.queryForObject("SELECT state FROM oidc_logout_task", String.class));
    jdbc.execute(
        "UPDATE oidc_logout_task SET state='RUNNING',attempts=5,lease_until=now()-interval '1 second'");
    assertFalse(logoutWorker.runOnce());
    assertEquals("DEAD", jdbc.queryForObject("SELECT state FROM oidc_logout_task", String.class));
  }

  @Test
  void staleWorkerCannotFinishAnotherLeaseAndReclaimedDeliveryUsesFreshJti() throws Exception {
    HttpClient browser = browser();
    login(browser, "crm", true);
    jdbc.update("UPDATE iam_user SET auth_epoch=auth_epoch+1 WHERE id=?", user);
    var received = new CopyOnWriteArrayList<String>();
    HttpServer receiver = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
    receiver.createContext(
        "/logout/backchannel",
        exchange -> {
          try {
            String body =
                new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String token =
                URLDecoder.decode(body.substring("logout_token=".length()), StandardCharsets.UTF_8);
            received.add(com.nimbusds.jwt.SignedJWT.parse(token).getJWTClaimsSet().getJWTID());
            if (received.size() == 1)
              jdbc.update("UPDATE oidc_logout_task SET lease_token=?", UUID.randomUUID());
            exchange.sendResponseHeaders(200, -1);
          } catch (Exception failure) {
            exchange.sendResponseHeaders(500, -1);
          } finally {
            exchange.close();
          }
        });
    receiver.start();
    try {
      jdbc.update(
          "UPDATE oidc_logout_task SET target_uri=?",
          "http://localhost:" + receiver.getAddress().getPort() + "/logout/backchannel");
      assertTrue(logoutWorker.runOnce());
      assertEquals(
          "RUNNING", jdbc.queryForObject("SELECT state FROM oidc_logout_task", String.class));
      jdbc.execute("UPDATE oidc_logout_task SET lease_until=now()-interval '1 second'");
      assertTrue(logoutWorker.runOnce());
      assertEquals("SENT", jdbc.queryForObject("SELECT state FROM oidc_logout_task", String.class));
      assertEquals(2, received.size());
      assertNotEquals(received.get(0), received.get(1));
      assertEquals(2, jdbc.queryForObject("SELECT attempts FROM oidc_logout_task", Integer.class));
    } finally {
      receiver.stop(0);
    }
  }

  @Test
  void partialHttp200BodyCannotHoldWorkerOrConfirmLogout() throws Exception {
    HttpClient browser = browser();
    login(browser, "crm", true);
    jdbc.update("UPDATE iam_user SET auth_epoch=auth_epoch+1 WHERE id=?", user);
    var release = new CountDownLatch(1);
    var entered = new CountDownLatch(1);
    HttpServer receiver = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
    receiver.createContext(
        "/logout/backchannel",
        exchange -> {
          try {
            exchange.getRequestBody().readAllBytes();
            exchange.sendResponseHeaders(200, 1000);
            exchange.getResponseBody().write(0);
            exchange.getResponseBody().flush();
            entered.countDown();
            release.await(10, TimeUnit.SECONDS);
          } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
          } finally {
            exchange.close();
          }
        });
    receiver.start();
    try {
      jdbc.update(
          "UPDATE oidc_logout_task SET target_uri=?",
          "http://localhost:" + receiver.getAddress().getPort() + "/logout/backchannel");
      long start = System.nanoTime();
      assertTrue(logoutWorker.runOnce());
      assertTrue(System.nanoTime() - start < Duration.ofSeconds(7).toNanos());
      assertEquals(0L, entered.getCount());
      assertEquals(
          "PENDING", jdbc.queryForObject("SELECT state FROM oidc_logout_task", String.class));
    } finally {
      release.countDown();
      receiver.stop(0);
    }
  }

  @Test
  void rolledBackRevocationCannotPublishNotificationOrInvalidateTheRp() throws Exception {
    HttpClient browser = browser();
    login(browser, "crm", true);
    var tx =
        new org.springframework.transaction.support.TransactionTemplate(
            new org.springframework.jdbc.datasource.DataSourceTransactionManager(
                jdbc.getDataSource()));
    tx.executeWithoutResult(
        status -> {
          jdbc.update("UPDATE iam_user SET auth_epoch=auth_epoch+1 WHERE id=?", user);
          assertEquals(
              1, jdbc.queryForObject("SELECT count(*) FROM oidc_logout_task", Integer.class));
          status.setRollbackOnly();
        });
    assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM oidc_logout_task", Integer.class));
    assertFalse(logoutWorker.runOnce());
    assertEquals(200, get(browser, rp("crm") + "/bff/profile").statusCode());
  }

  @Test
  void familyLogoutRequiresFreshLoginForThatRpAndLateNotificationCannotDeleteNewSession()
      throws Exception {
    HttpClient browser = browser();
    login(browser, "crm", true);
    login(browser, "hrm", false);
    Stored previous = stored(browser, "crm", false);
    jdbc.execute(
        "UPDATE oauth2_authorization SET revoked=true WHERE id IN (SELECT authorization_id FROM oidc_rp_session WHERE client_id='crm')");
    assertTrue(logoutWorker.runOnce());
    assertEquals(401, get(browser, rp("crm") + "/bff/profile").statusCode());
    assertEquals(200, get(browser, rp("hrm") + "/bff/profile").statusCode());
    login(browser, "crm", true);
    Stored current = stored(browser, "crm", false);
    assertNotEquals(
        previous.user.getIdToken().getClaimAsString("sid"),
        current.user.getIdToken().getClaimAsString("sid"));
    jdbc.execute(
        "UPDATE oidc_logout_task SET state='PENDING',attempts=0,next_attempt_at=now()-interval '1 second'");
    assertTrue(logoutWorker.runOnce());
    assertEquals(200, get(browser, rp("crm") + "/bff/profile").statusCode());
    assertEquals(200, get(browser, rp("hrm") + "/bff/profile").statusCode());
  }

  @AfterAll
  void close() throws Exception {
    Files.writeString(
        root.resolve("revocation-observations.md"),
        "# Local independent RP observations\n\n"
            + revocationMillis
            + " milliseconds from password request start through both RP/API rejection. Small local samples; not a percentile/SLA report.\n");
    Collections.reverse(owned);
    for (Process process : owned) {
      if (process.isAlive()) {
        process.destroy();
        if (!process.waitFor(5, TimeUnit.SECONDS)) process.destroyForcibly();
      }
    }
    if (proxy != null) proxy.stop(0);
    if (proxyPool != null) proxyPool.shutdownNow();
    if (redis != null) redis.destroy();
    if (ldap != null) ldap.shutDown(true);
    if (pg != null) pg.close();
  }
}
