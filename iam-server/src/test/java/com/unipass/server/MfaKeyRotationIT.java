package com.unipass.server;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.transaction.support.TransactionTemplate;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class MfaKeyRotationIT {
  private static final String ACTOR = "operator:test", EVIDENCE = "ticket:key-rotation";
  private static final UUID USER = new UUID(0, 1), OTHER = new UUID(0, 2);
  private EmbeddedPostgres pg;
  private JdbcTemplate jdbc;
  private TransactionTemplate tx;
  private MfaKeyService legacy, keys;
  private byte[] secret, pending;
  private UUID change;

  private static String key(int value) {
    byte[] raw = new byte[32];
    Arrays.fill(raw, (byte) value);
    return Base64.getEncoder().encodeToString(raw);
  }

  private MfaKeyService service(boolean legacyKey, Map<String, String> ring) throws Exception {
    return new MfaKeyService(
        jdbc,
        tx,
        new MockEnvironment()
            .withProperty("unipass.mfa.key", legacyKey ? key(0) : "")
            .withProperty("unipass.mfa.keys-json", new ObjectMapper().writeValueAsString(ring)));
  }

  @BeforeAll
  void start() throws Exception {
    System.setProperty(
        "ot.epg.working-dir",
        Files.createDirectories(Path.of("target", "mfa-key-rotation", "postgres"))
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
  }

  private void user(UUID id) {
    jdbc.update(
        "INSERT INTO iam_user(id,employee_no,directory_id,directory_type,ldap_dn,display_name,status,source_id,source_version,auth_epoch) VALUES (?,?,?,'OPENLDAP','uid=test','Test','ACTIVE','key-test',1,5)",
        id,
        id.toString(),
        UUID.randomUUID());
  }

  @BeforeEach
  void seed() throws Exception {
    Flyway.configure().dataSource(jdbc.getDataSource()).cleanDisabled(false).load().clean();
    Flyway.configure().dataSource(jdbc.getDataSource()).target("8").load().migrate();
    jdbc.update("INSERT INTO import_source(source_id,cursor_value) VALUES ('key-test','1')");
    user(USER);
    secret = new byte[20];
    pending = new byte[20];
    Arrays.fill(secret, (byte) 3);
    Arrays.fill(pending, (byte) 4);
    change = UUID.randomUUID();
    var old = new MfaSecretCipher(key(0));
    jdbc.update(
        "INSERT INTO mfa_totp(user_id,secret_cipher,enabled,last_used_step,failed_attempts,locked_until) VALUES (?,?,true,123,3,now()+interval '10 minutes')",
        USER,
        old.encrypt(USER, secret));
    jdbc.update(
        "INSERT INTO mfa_factor_change(id,user_id,auth_epoch,session_digest,secret_cipher,mode,state,expires_at,created_at) VALUES (?,?,5,'session-digest',?,'ROTATE','PENDING',now()+interval '5 minutes',now())",
        change,
        USER,
        old.encrypt(USER, pending));
    Flyway.configure().dataSource(jdbc.getDataSource()).target("9").load().migrate();
    assertEquals(
        5L, jdbc.queryForObject("SELECT auth_epoch FROM iam_user WHERE id=?", Long.class, USER));
    Flyway.configure().dataSource(jdbc.getDataSource()).load().migrate();
    legacy = service(true, Map.of());
    keys = service(true, Map.of("next", key(1)));
  }

  private byte[] factor(UUID user) {
    return jdbc.queryForObject(
        "SELECT secret_cipher FROM mfa_totp WHERE user_id=?", byte[].class, user);
  }

  private void activate() {
    assertTrue(keys.introduce("next", ACTOR, EVIDENCE));
    assertFalse(keys.introduce("next", ACTOR, EVIDENCE));
    assertTrue(keys.activate("next", ACTOR, EVIDENCE));
  }

  @Test
  void firstBootstrapCannotPinWrongLegacyMaterial() throws Exception {
    // Recreate V9's pre-bootstrap metadata while retaining the V8 ciphertext.
    jdbc.execute("UPDATE mfa_encryption_control SET active_key=NULL");
    jdbc.execute("DELETE FROM mfa_encryption_key");
    jdbc.execute("DELETE FROM mfa_key_audit");
    var wrong = new MockEnvironment().withProperty("unipass.mfa.key", key(2));
    assertThrows(IllegalStateException.class, () -> new MfaKeyService(jdbc, tx, wrong));
    assertNull(jdbc.queryForObject("SELECT active_key FROM mfa_encryption_control", String.class));
    assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM mfa_encryption_key", Integer.class));
    assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM mfa_key_audit", Integer.class));
    assertEquals(2, service(true, Map.of()).verify());
    assertArrayEquals(secret, service(true, Map.of()).decrypt(USER, factor(USER)));
  }

  @Test
  void stagedUpgradeRekeysActiveAndPendingWithoutChangingSecurityState() throws Exception {
    long epochBefore =
        jdbc.queryForObject("SELECT auth_epoch FROM iam_user WHERE id=?", Long.class, USER);
    var before =
        jdbc.queryForMap(
            "SELECT enabled,last_used_step,failed_attempts,locked_until,pending_expires_at,created_at FROM mfa_totp WHERE user_id=?",
            USER);
    var pendingBefore =
        jdbc.queryForMap(
            "SELECT state,auth_epoch,session_digest,expires_at,created_at FROM mfa_factor_change WHERE id=?",
            change);
    assertEquals("legacy", keys.status().active());
    assertEquals(2, keys.verify());
    activate();
    assertThrows(IllegalStateException.class, () -> legacy.encrypt(USER, secret));
    assertThrows(IllegalStateException.class, () -> keys.retire("legacy", ACTOR, EVIDENCE));
    byte[] stale = new MfaSecretCipher(key(0)).encrypt(USER, secret);
    assertThrows(
        org.springframework.dao.DataAccessException.class,
        () -> jdbc.update("UPDATE mfa_totp SET secret_cipher=? WHERE user_id=?", stale, USER));
    assertEquals(2, keys.rekey(1, ACTOR, EVIDENCE));
    assertEquals(0, keys.rekey(1, ACTOR, EVIDENCE));
    assertEquals(
        before,
        jdbc.queryForMap(
            "SELECT enabled,last_used_step,failed_attempts,locked_until,pending_expires_at,created_at FROM mfa_totp WHERE user_id=?",
            USER));
    assertEquals(
        pendingBefore,
        jdbc.queryForMap(
            "SELECT state,auth_epoch,session_digest,expires_at,created_at FROM mfa_factor_change WHERE id=?",
            change));
    assertEquals(
        epochBefore,
        jdbc.queryForObject("SELECT auth_epoch FROM iam_user WHERE id=?", Long.class, USER));
    assertArrayEquals(secret, keys.decrypt(USER, factor(USER)));
    assertArrayEquals(
        pending,
        keys.decrypt(
            USER,
            jdbc.queryForObject(
                "SELECT secret_cipher FROM mfa_factor_change WHERE id=?", byte[].class, change)));
    assertEquals(2, keys.verify());
    assertTrue(keys.retire("legacy", ACTOR, EVIDENCE));
    assertFalse(keys.retire("legacy", ACTOR, EVIDENCE));
    assertThrows(IllegalStateException.class, () -> keys.decrypt(USER, stale));
    assertArrayEquals(secret, service(false, Map.of("next", key(1))).decrypt(USER, factor(USER)));
    assertThrows(IllegalStateException.class, () -> keys.activate("legacy", ACTOR, EVIDENCE));
    assertThrows(IllegalStateException.class, () -> keys.introduce("legacy", ACTOR, EVIDENCE));
    assertThrows(IllegalStateException.class, () -> service(true, Map.of("next", key(2))));
    assertThrows(IllegalStateException.class, () -> service(true, Map.of()));
  }

  @Test
  void corruptedCiphertextRollsBackBatchAndPreventsRetirement() throws Exception {
    user(OTHER);
    byte[] valid = new MfaSecretCipher(key(0)).encrypt(OTHER, secret), bad = valid.clone();
    bad[bad.length - 1] ^= 1;
    jdbc.update(
        "INSERT INTO mfa_totp(user_id,secret_cipher,enabled) VALUES (?,?,true)", OTHER, bad);
    byte[] original = factor(USER);
    activate();
    assertThrows(IllegalStateException.class, () -> keys.rekey(100, ACTOR, EVIDENCE));
    assertArrayEquals(original, factor(USER));
    assertEquals(
        0,
        jdbc.queryForObject(
            "SELECT count(*) FROM mfa_key_audit WHERE action='REKEYED'", Integer.class));
    // Restore the authenticated old snapshot while the new writer is active through
    // the service, rather than disabling the database writer fence.
    jdbc.update(
        "UPDATE mfa_totp SET secret_cipher=? WHERE user_id=?", keys.reencrypt(OTHER, valid), OTHER);
    assertEquals(2, keys.rekey(100, ACTOR, EVIDENCE));
    byte[] current = factor(USER), tampered = current.clone();
    tampered[tampered.length - 1] ^= 1;
    jdbc.update("UPDATE mfa_totp SET secret_cipher=? WHERE user_id=?", tampered, USER);
    assertThrows(IllegalStateException.class, keys::verify);
    assertThrows(IllegalStateException.class, () -> keys.retire("legacy", ACTOR, EVIDENCE));
    assertEquals(
        "AVAILABLE",
        jdbc.queryForObject(
            "SELECT state FROM mfa_encryption_key WHERE key_id='legacy'", String.class));
    jdbc.update("UPDATE mfa_totp SET secret_cipher=? WHERE user_id=?", current, USER);
    assertTrue(keys.retire("legacy", ACTOR, EVIDENCE));
  }

  @Test
  void lockedIdentityIsSkippedAndLaterBatchResumes() throws Exception {
    user(OTHER);
    jdbc.update(
        "INSERT INTO mfa_totp(user_id,secret_cipher,enabled) VALUES (?,?,true)",
        OTHER,
        legacy.encrypt(OTHER, secret));
    activate();
    try (var connection = jdbc.getDataSource().getConnection()) {
      connection.setAutoCommit(false);
      try (var statement =
          connection.prepareStatement("SELECT id FROM iam_user WHERE id=? FOR UPDATE")) {
        statement.setObject(1, USER);
        statement.executeQuery().close();
      }
      assertEquals(1, keys.rekey(1, ACTOR, EVIDENCE));
      assertEquals("legacy", MfaSecretCipher.keyId(factor(USER)));
      connection.rollback();
    }
    assertEquals(2, keys.rekey(1, ACTOR, EVIDENCE));
    assertEquals(0, keys.rekey(100, ACTOR, EVIDENCE));
    assertEquals(3, keys.verify());
  }

  @Test
  void parallelRekeyWorkersDoNotOverwriteOrDuplicateFactorWork() throws Exception {
    user(OTHER);
    jdbc.update(
        "INSERT INTO mfa_totp(user_id,secret_cipher,enabled) VALUES (?,?,true)",
        OTHER,
        legacy.encrypt(OTHER, secret));
    activate();
    var pool = Executors.newFixedThreadPool(2);
    var barrier = new CyclicBarrier(2);
    try {
      Callable<Integer> run =
          () -> {
            barrier.await(5, TimeUnit.SECONDS);
            return keys.rekey(1, ACTOR, EVIDENCE);
          };
      var first = pool.submit(run);
      var second = pool.submit(run);
      assertEquals(3, first.get(10, TimeUnit.SECONDS) + second.get(10, TimeUnit.SECONDS));
      assertEquals(
          3,
          jdbc.queryForObject(
              "SELECT sum(changed_rows) FROM mfa_key_audit WHERE action='REKEYED'", Integer.class));
      assertEquals(0, keys.rekey(100, ACTOR, EVIDENCE));
    } finally {
      pool.shutdownNow();
    }
  }

  @Test
  void activationWaitsForInFlightWriterAndThenRejectsItsStaleKey() throws Exception {
    keys.introduce("next", ACTOR, EVIDENCE);
    var entered = new CountDownLatch(1);
    var release = new CountDownLatch(1);
    var activating = new CountDownLatch(1);
    var pool = Executors.newFixedThreadPool(2);
    try {
      var write =
          pool.submit(
              () ->
                  tx.executeWithoutResult(
                      status -> {
                        byte[] encrypted = legacy.encrypt(USER, secret);
                        entered.countDown();
                        try {
                          assertTrue(release.await(5, TimeUnit.SECONDS));
                        } catch (InterruptedException interrupted) {
                          Thread.currentThread().interrupt();
                          throw new IllegalStateException();
                        }
                        jdbc.update(
                            "UPDATE mfa_totp SET secret_cipher=? WHERE user_id=?", encrypted, USER);
                      }));
      assertTrue(entered.await(5, TimeUnit.SECONDS));
      var activate =
          pool.submit(
              () -> {
                activating.countDown();
                return keys.activate("next", ACTOR, EVIDENCE);
              });
      assertTrue(activating.await(5, TimeUnit.SECONDS));
      assertThrows(TimeoutException.class, () -> activate.get(200, TimeUnit.MILLISECONDS));
      release.countDown();
      write.get(5, TimeUnit.SECONDS);
      assertTrue(activate.get(5, TimeUnit.SECONDS));
      assertThrows(IllegalStateException.class, () -> legacy.encrypt(USER, secret));
      assertEquals(2, keys.rekey(100, ACTOR, EVIDENCE));
    } finally {
      release.countDown();
      pool.shutdownNow();
    }
  }

  @Test
  void deferredCommitFailureCannotSwitchWriterOrLeavePartiallyRekeyedRows() {
    keys.introduce("next", ACTOR, EVIDENCE);
    jdbc.execute(
        "CREATE FUNCTION reject_key_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action IN ('ACTIVATED','REKEYED') THEN RAISE EXCEPTION 'test key commit failure'; END IF; RETURN NEW; END $$");
    String install =
        "CREATE CONSTRAINT TRIGGER reject_key_commit AFTER INSERT ON mfa_key_audit DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_key_commit()";
    jdbc.execute(install);
    assertThrows(RuntimeException.class, () -> keys.activate("next", ACTOR, EVIDENCE));
    assertEquals("legacy", keys.status().active());
    jdbc.execute("DROP TRIGGER reject_key_commit ON mfa_key_audit");
    keys.activate("next", ACTOR, EVIDENCE);
    byte[] before = factor(USER);
    jdbc.execute(install);
    assertThrows(RuntimeException.class, () -> keys.rekey(100, ACTOR, EVIDENCE));
    assertArrayEquals(before, factor(USER));
    assertEquals(
        0,
        jdbc.queryForObject(
            "SELECT count(*) FROM mfa_key_audit WHERE action='REKEYED'", Integer.class));
    jdbc.execute("DROP TRIGGER reject_key_commit ON mfa_key_audit");
    assertEquals(2, keys.rekey(100, ACTOR, EVIDENCE));
  }

  private String cli(String... args) throws Exception {
    List<String> command =
        new ArrayList<>(
            List.of(
                Path.of(
                        System.getProperty("java.home"),
                        "bin",
                        System.getProperty("os.name").startsWith("Windows") ? "java.exe" : "java")
                    .toString(),
                "-Dloader.main=com.unipass.server.MfaKeyAdminCli",
                "-cp",
                Path.of(
                        System.getProperty(
                            "test.server.exec.jar", "target/iam-server-0.1.0-SNAPSHOT-exec.jar"))
                    .toAbsolutePath()
                    .toString(),
                "org.springframework.boot.loader.launch.PropertiesLauncher"));
    command.addAll(List.of(args));
    Path log =
        Path.of("target", "mfa-key-rotation", "cli-" + args[0] + "-" + UUID.randomUUID() + ".log");
    var builder = new ProcessBuilder(command);
    builder.environment().keySet().removeIf(name -> name.startsWith("UNIPASS_"));
    builder
        .environment()
        .putAll(
            Map.of(
                "UNIPASS_DB_URL",
                pg.getJdbcUrl("postgres", "postgres"),
                "UNIPASS_DB_USER",
                "postgres",
                "UNIPASS_DB_PASSWORD",
                "test",
                "UNIPASS_MFA_KEY",
                key(0),
                "UNIPASS_MFA_KEYS_JSON",
                new ObjectMapper().writeValueAsString(Map.of("next", key(1))),
                "UNIPASS_OPERATOR_REF",
                ACTOR,
                "UNIPASS_EVIDENCE_REF",
                EVIDENCE));
    Process process = builder.redirectErrorStream(true).redirectOutput(log.toFile()).start();
    try {
      assertTrue(process.waitFor(20, TimeUnit.SECONDS));
      String output = Files.readString(log);
      assertEquals(0, process.exitValue(), output);
      assertFalse(output.contains(key(0)));
      assertFalse(output.contains(key(1)));
      return output;
    } finally {
      if (process.isAlive()) process.destroyForcibly();
    }
  }

  @Test
  void packagedCliRunsCompleteLifecycleWithoutPrintingKeys() throws Exception {
    assertTrue(cli("status").contains("legacy"));
    assertTrue(cli("introduce", "next").contains("true"));
    assertTrue(cli("activate", "next").contains("true"));
    assertTrue(cli("rekey", "1").contains("\"changed_rows\":2"));
    assertTrue(cli("verify").contains("\"verified_rows\":2"));
    assertTrue(cli("retire", "legacy").contains("true"));
    assertTrue(cli("status").contains("RETIRED"));
  }

  @AfterAll
  void close() throws Exception {
    if (pg != null) pg.close();
  }
}
