package com.unipass.server;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import java.net.URI;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class FeishuIdentityIT {
  private EmbeddedPostgres pg;
  private JdbcTemplate jdbc;
  private TransactionTemplate tx;
  private AccountState accounts;
  private FeishuService service;
  private FeishuAdmin admin;
  private FeishuFixture remote;
  private static final UUID USER = new UUID(0, 101), OTHER = new UUID(0, 102);

  @BeforeAll
  void start() throws Exception {
    System.setProperty(
        "ot.epg.working-dir",
        Files.createDirectories(Path.of("target", "feishu-test", "postgres"))
            .toAbsolutePath()
            .toString());
    pg =
        EmbeddedPostgres.builder()
            .setPort(0)
            .setServerConfig("listen_addresses", "127.0.0.1")
            .start();
    jdbc = new JdbcTemplate(pg.getPostgresDatabase());
    tx = new TransactionTemplate(new DataSourceTransactionManager(jdbc.getDataSource()));
    tx.setTimeout(10);
    remote = new FeishuFixture();
  }

  @AfterAll
  void stop() throws Exception {
    remote.close();
    pg.close();
  }

  @BeforeEach
  void seed() {
    Flyway.configure().dataSource(jdbc.getDataSource()).cleanDisabled(false).load().clean();
    Flyway.configure().dataSource(jdbc.getDataSource()).target("10").load().migrate();
    jdbc.update("INSERT INTO import_source(source_id,cursor_value) VALUES ('feishu-test','1')");
    user(USER);
    user(OTHER);
    Flyway.configure().dataSource(jdbc.getDataSource()).load().migrate();
    var generation = UUID.randomUUID();
    jdbc.update(
        "UPDATE auth_runtime_state SET redis_generation=?,redis_run_id='fixture-run-identity'",
        generation);
    var redis = mock(RedisSecurityState.class);
    when(redis.current())
        .thenReturn(new RedisSecurityState.Observed(generation.toString(), "fixture-run-identity"));
    accounts = new AccountState(jdbc, redis);
    ReflectionTestUtils.setField(accounts, "feishuEnabled", true);
    remote.reset();
    service =
        new FeishuService(
            jdbc, tx, accounts, mock(MfaService.class), Clock.systemUTC(), remote.client());
    admin = new FeishuAdmin(jdbc, tx);
    admin.configure(
        FeishuFixture.APP, FeishuFixture.TENANT, "operator:fixture", "ticket:fixture-config");
    admin.recordLoginVerification("operator:fixture", "ticket:fixture-contract");
  }

  private void user(UUID id) {
    jdbc.update(
        "INSERT INTO iam_user(id,employee_no,directory_id,directory_type,ldap_dn,display_name,status,source_id,source_version) VALUES (?,?,?,'OPENLDAP','uid=test','Test','ACTIVE','feishu-test',1)",
        id,
        id.toString(),
        id);
  }

  private IdentityPrincipal principal(UUID user) {
    return accounts.registerLogin(
        new IdentityPrincipal(
            user,
            jdbc.queryForObject("SELECT auth_epoch FROM iam_user WHERE id=?", Long.class, user),
            Instant.now(),
            List.of("ROLE_USER")));
  }

  private String state(boolean binding, IdentityPrincipal principal, String session) {
    return FeishuFixture.parameters(
            URI.create(service.start(binding, principal, session, "fixture-ip").authorizationUrl())
                .getRawQuery())
        .get("state");
  }

  private void bind(UUID user, String code) {
    String session = "binding-" + UUID.randomUUID();
    var actor = principal(user);
    assertNull(service.callback(state(true, actor, session), code, null, actor, session));
  }

  @Test
  void upgradeDefaultsAndCapabilityEvidenceRemainFailClosed() {
    var disabled =
        new FeishuService(
            jdbc,
            tx,
            accounts,
            mock(MfaService.class),
            Clock.systemUTC(),
            new org.springframework.mock.env.MockEnvironment());
    assertEquals(
        503,
        assertThrows(
                ResponseStatusException.class, () -> disabled.start(false, null, "default", "ip"))
            .getStatusCode()
            .value());
    assertEquals(
        "UNVERIFIED",
        jdbc.queryForObject(
            "SELECT state FROM feishu_capability WHERE capability='CONTACT_READ'", String.class));
    assertEquals(
        2,
        jdbc.queryForObject(
            "SELECT count(*) FROM feishu_capability WHERE state='UNAVAILABLE'", Integer.class));
    admin.disable("operator:fixture", "ticket:disable");
    assertEquals(
        503,
        assertThrows(ResponseStatusException.class, () -> state(false, null, "anonymous"))
            .getStatusCode()
            .value());
    assertThrows(
        IllegalArgumentException.class,
        () -> admin.recordLoginVerification("operator:fixture", " "));
    assertThrows(
        org.springframework.dao.DataAccessException.class,
        () ->
            jdbc.execute(
                "UPDATE feishu_capability SET state='VERIFIED',evidence_ref=NULL WHERE capability='LOGIN'"));
    assertThrows(
        org.springframework.dao.DataAccessException.class,
        () -> jdbc.execute("UPDATE feishu_connector SET app_id='another_app'"));
    assertThrows(
        org.springframework.dao.DataAccessException.class,
        () -> jdbc.execute("DELETE FROM feishu_connector"));
    admin.recordLoginVerification("operator:fixture", "ticket:real-evidence-required");
    assertNotNull(state(false, null, "anonymous"));
  }

  @Test
  void onlyExplicitBindingAllowsLoginAndNeverCreatesPasswordProof() {
    String before = state(false, null, "unknown");
    assertEquals(
        401,
        assertThrows(
                ResponseStatusException.class,
                () -> service.callback(before, "unknown_code", null, null, "unknown"))
            .getStatusCode()
            .value());
    bind(USER, "binding_code");
    String state = state(false, null, "login");
    var principal = service.callback(state, "login_code", null, null, "login");
    assertEquals(USER, principal.getUserId());
    assertEquals(IdentityPrincipal.Method.FEISHU, principal.getAuthenticationMethod());
    assertNull(principal.getPasswordAuthenticatedAt());
    assertEquals(List.of("feishu"), principal.getAuthenticationMethods());
    assertTrue(accounts.allowed(principal));
    assertFalse(principal.hasRecentPassword(Instant.now()));
    assertEquals(
        403,
        assertThrows(ResponseStatusException.class, () -> state(true, principal, "weak-binding"))
            .getStatusCode()
            .value());
    assertEquals(
        0,
        jdbc.queryForObject(
            "SELECT count(*) FROM feishu_flow WHERE state_digest=?", Integer.class, state));
    assertEquals(
        0,
        jdbc.queryForObject(
            "SELECT count(*) FROM feishu_code_use WHERE code_digest='login_code'", Integer.class));
    ReflectionTestUtils.setField(accounts, "feishuEnabled", false);
    assertFalse(accounts.allowed(principal));
  }

  @Test
  void browserStateAndCodeAreConsumedOnceEvenAfterUnknownExternalOutcome() {
    String state = state(false, null, "owner");
    assertThrows(
        ResponseStatusException.class,
        () -> service.callback(state, "code", null, null, "stranger"));
    assertEquals(0, remote.calls.get());
    remote.tokenStatus = 500;
    assertEquals(
        503,
        assertThrows(
                ResponseStatusException.class,
                () -> service.callback(state, "burned_code", null, null, "owner"))
            .getStatusCode()
            .value());
    assertThrows(
        ResponseStatusException.class,
        () -> service.callback(state, "burned_code", null, null, "owner"));
    String next = state(false, null, "other-browser");
    assertThrows(
        ResponseStatusException.class,
        () -> service.callback(next, "burned_code", null, null, "other-browser"));
    assertEquals(1, remote.calls.get());
    String cancel = state(false, null, "cancel");
    assertThrows(
        ResponseStatusException.class,
        () -> service.callback(cancel, null, "access_denied", null, "cancel"));
    assertThrows(
        ResponseStatusException.class,
        () -> service.callback(cancel, "after_cancel", null, null, "cancel"));
    String expired = state(false, null, "expired");
    jdbc.execute("UPDATE feishu_flow SET expires_at=now()-interval '1 second'");
    assertThrows(
        ResponseStatusException.class,
        () -> service.callback(expired, "expired_code", null, null, "expired"));
    assertEquals(1, remote.calls.get());
  }

  @Test
  void simultaneousCallbacksCommitOneIdentityAndMakeOneExternalExchange() throws Exception {
    bind(USER, "bind");
    remote.calls.set(0);
    String state = state(false, null, "concurrent");
    var pool = Executors.newFixedThreadPool(2);
    var barrier = new CyclicBarrier(2);
    Callable<Boolean> run =
        () -> {
          barrier.await(5, TimeUnit.SECONDS);
          try {
            return service.callback(state, "concurrent_code", null, null, "concurrent") != null;
          } catch (ResponseStatusException rejected) {
            return false;
          }
        };
    try {
      var first = pool.submit(run);
      var second = pool.submit(run);
      assertNotEquals(first.get(10, TimeUnit.SECONDS), second.get(10, TimeUnit.SECONDS));
    } finally {
      pool.shutdownNow();
    }
    assertEquals(1, remote.calls.get());
  }

  @Test
  void simultaneousBindingsCannotStealAnExternalIdentity() throws Exception {
    var pool = Executors.newFixedThreadPool(2);
    var barrier = new CyclicBarrier(2);
    Callable<Boolean> first =
        () -> {
          barrier.await(5, TimeUnit.SECONDS);
          try {
            bind(USER, "first_bind");
            return true;
          } catch (ResponseStatusException rejected) {
            return false;
          }
        };
    Callable<Boolean> second =
        () -> {
          barrier.await(5, TimeUnit.SECONDS);
          try {
            bind(OTHER, "second_bind");
            return true;
          } catch (ResponseStatusException rejected) {
            return false;
          }
        };
    try {
      var left = pool.submit(first);
      var right = pool.submit(second);
      assertNotEquals(left.get(10, TimeUnit.SECONDS), right.get(10, TimeUnit.SECONDS));
    } finally {
      pool.shutdownNow();
    }
    assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM feishu_binding", Integer.class));
  }

  @Test
  void epochChangesDuringExchangeAndPermissionExpiryRequireNewBinding() {
    bind(USER, "bind");
    String pending = state(false, null, "pending");
    remote.afterToken =
        () -> jdbc.update("UPDATE iam_user SET auth_epoch=auth_epoch+1 WHERE id=?", USER);
    assertEquals(
        401,
        assertThrows(
                ResponseStatusException.class,
                () -> service.callback(pending, "epoch_race", null, null, "pending"))
            .getStatusCode()
            .value());
    remote.afterToken = () -> {};
    bind(USER, "renew");
    var login = service.callback(state(false, null, "login"), "new_login", null, null, "login");
    assertTrue(accounts.allowed(login));
    jdbc.execute(
        "UPDATE feishu_capability SET verified_at=now()-interval '8 days',valid_until=now()-interval '1 day' WHERE capability='LOGIN'");
    assertFalse(accounts.allowed(login));
    admin.recordLoginVerification("operator:fixture", "ticket:reverified");
    assertFalse(accounts.federatedAllowed(USER, principal(USER).getEpoch()));
    bind(USER, "fresh_binding");
    assertTrue(accounts.federatedAllowed(USER, principal(USER).getEpoch()));
    service.unlink(principal(USER));
    assertFalse(accounts.federatedAllowed(USER, principal(USER).getEpoch()));
  }

  @Test
  void failedFinalTransactionCannotPersistBindingOrMakeCodeReusable() {
    var actor = principal(USER);
    String state = state(true, actor, "binding");
    jdbc.execute(
        "CREATE FUNCTION reject_binding_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='FEISHU_BINDING_CONFIRMED' THEN RAISE EXCEPTION 'fixture commit failure'; END IF; RETURN NEW; END $$");
    jdbc.execute(
        "CREATE TRIGGER reject_binding_audit BEFORE INSERT ON feishu_audit FOR EACH ROW EXECUTE FUNCTION reject_binding_audit()");
    assertThrows(
        org.springframework.dao.DataAccessException.class,
        () -> service.callback(state, "binding_failure", null, actor, "binding"));
    assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM feishu_binding", Integer.class));
    assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM feishu_code_use", Integer.class));
    assertThrows(
        ResponseStatusException.class,
        () -> service.callback(state, "binding_failure", null, actor, "binding"));
    assertEquals(1, remote.calls.get());
  }

  @Test
  void flowRateLimitIsPerBrowserAndExpiredRowsAreCleanedInBoundedBatches() {
    for (int count = 0; count < 5; count++) state(false, null, "browser");
    assertEquals(
        429,
        assertThrows(ResponseStatusException.class, () -> state(false, null, "browser"))
            .getStatusCode()
            .value());
    jdbc.execute("UPDATE feishu_flow SET created_at=now()-interval '2 days'");
    assertEquals(5, service.cleanup());
    assertNotNull(state(false, null, "browser"));
  }

  @Test
  void packagedAdminRequiresEvidenceAndDoesNotContactRemoteTenant() throws Exception {
    Path log = Path.of("target", "feishu-admin-cli.log").toAbsolutePath();
    assertEquals(0, cli(log, true, "report"));
    String report = Files.readString(log);
    assertTrue(report.contains("CONTACT_READ"));
    assertTrue(report.contains("UNAVAILABLE"));
    assertFalse(report.contains(FeishuFixture.SECRET));
    assertEquals(1, cli(log, false, "record-login-verification"));
    assertEquals(0, cli(log, true, "disable"));
    assertFalse(jdbc.queryForObject("SELECT enabled FROM feishu_connector", Boolean.class));
    assertEquals(0, cli(log, true, "record-login-verification"));
    assertTrue(jdbc.queryForObject("SELECT enabled FROM feishu_connector", Boolean.class));
    assertEquals(0, remote.calls.get());
  }

  private int cli(Path log, boolean evidence, String command) throws Exception {
    var builder =
        new ProcessBuilder(
            Path.of(
                    System.getProperty("java.home"),
                    "bin",
                    System.getProperty("os.name").startsWith("Windows") ? "java.exe" : "java")
                .toString(),
            "-Dloader.main=com.unipass.server.FeishuAdminCli",
            "-cp",
            Path.of(
                    System.getProperty(
                        "test.server.exec.jar", "target/iam-server-0.1.0-SNAPSHOT-exec.jar"))
                .toAbsolutePath()
                .toString(),
            "org.springframework.boot.loader.launch.PropertiesLauncher",
            command);
    builder.environment().put("UNIPASS_DB_URL", pg.getJdbcUrl("postgres", "postgres"));
    builder.environment().put("UNIPASS_DB_USER", "postgres");
    builder.environment().put("UNIPASS_DB_PASSWORD", "test");
    builder.environment().put("UNIPASS_OPERATOR_REF", "operator:packaged-cli");
    if (evidence)
      builder.environment().put("UNIPASS_EVIDENCE_REF", "ticket:fixture-not-real-tenant");
    else builder.environment().remove("UNIPASS_EVIDENCE_REF");
    var process = builder.redirectErrorStream(true).redirectOutput(log.toFile()).start();
    try {
      assertTrue(process.waitFor(30, TimeUnit.SECONDS));
      return process.exitValue();
    } finally {
      if (process.isAlive()) process.destroyForcibly();
    }
  }
}
