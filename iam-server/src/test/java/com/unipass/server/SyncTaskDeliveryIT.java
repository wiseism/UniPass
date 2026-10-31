package com.unipass.server;

import static com.unipass.server.SyncTaskDelivery.*;
import static org.junit.jupiter.api.Assertions.*;

import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SyncTaskDeliveryIT {
  private static final UUID USER = new UUID(0, 1);
  private EmbeddedPostgres pg;
  private JdbcTemplate jdbc;
  private TransactionTemplate tx;
  private final List<SyncTaskWorker> workers = new ArrayList<>();

  @BeforeAll
  void start() throws Exception {
    System.setProperty(
        "ot.epg.working-dir",
        Files.createDirectories(Path.of("target", "sync-delivery", "postgres"))
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

  @BeforeEach
  void seed() {
    Flyway.configure().dataSource(jdbc.getDataSource()).cleanDisabled(false).load().clean();
    Flyway.configure().dataSource(jdbc.getDataSource()).load().migrate();
    jdbc.update("INSERT INTO import_source(source_id,cursor_value) VALUES ('sync-test','1')");
    jdbc.update(
        """
                INSERT INTO iam_user(id,employee_no,directory_id,directory_type,ldap_dn,display_name,status,source_id,source_version,auth_epoch)
                VALUES (?,'sync-test',?,'OPENLDAP','uid=test','Test','ACTIVE','sync-test',1,5)
                """,
        USER,
        UUID.randomUUID());
  }

  @AfterEach
  void closeWorkers() {
    workers.forEach(SyncTaskWorker::close);
    workers.clear();
  }

  @AfterAll
  void stop() throws Exception {
    if (pg != null) pg.close();
  }

  private UUID event() {
    UUID id = UUID.randomUUID();
    jdbc.update(
        """
                INSERT INTO outbox_event(event_id,aggregate_id,event_type,auth_epoch,payload,created_at)
                VALUES (?,?,'unipass.password.changed',5,'{"unexpected_password":"never-forward-this"}',clock_timestamp())
                """,
        id,
        USER);
    return id;
  }

  private UUID task(UUID event) {
    // Tests focus on one target; the other durable task is left for its adapter.
    jdbc.update(
        "UPDATE sync_task SET next_retry_at=clock_timestamp()+interval '1 day' WHERE target='FEISHU_APP_REAUTH'");
    return jdbc.queryForObject(
        "SELECT id FROM sync_task WHERE event_id=? AND target='APP_PUSH'", UUID.class, event);
  }

  private String state(UUID id) {
    return jdbc.queryForObject("SELECT state FROM sync_task WHERE id=?", String.class, id);
  }

  private void due(UUID id) {
    jdbc.update(
        "UPDATE sync_task SET next_retry_at=clock_timestamp()-interval '1 second' WHERE id=?", id);
  }

  private SyncTaskWorker worker(SyncTaskDelivery adapter) {
    return worker(adapter, Duration.ofSeconds(5));
  }

  private SyncTaskWorker worker(SyncTaskDelivery adapter, Duration timeout) {
    var worker =
        new SyncTaskWorker(jdbc, tx, adapter == null ? List.of() : List.of(adapter), timeout);
    workers.add(worker);
    return worker;
  }

  private static SyncTaskDelivery adapter(java.util.function.Function<Event, Result> call) {
    return new SyncTaskDelivery() {
      @Override
      public String target() {
        return "APP_PUSH";
      }

      @Override
      public Result deliver(Event event) {
        return call.apply(event);
      }
    };
  }

  private static Result delivered() {
    return new Result(Outcome.SUCCESS, Code.DELIVERY_CONFIRMED, null);
  }

  @Test
  void fanoutAndDisableAreAtomicIdempotentAndNeverContainPasswords() {
    UUID event = event();
    assertEquals(
        2,
        jdbc.queryForObject(
            "SELECT count(*) FROM sync_task WHERE event_id=?", Integer.class, event));
    assertNotNull(
        jdbc.queryForObject(
            "SELECT published_at FROM outbox_event WHERE event_id=?",
            java.sql.Timestamp.class,
            event));
    jdbc.update(
        """
                INSERT INTO sync_task(id,event_id,target,state,next_retry_at) VALUES (?,?,'APP_PUSH','PENDING',now())
                ON CONFLICT(event_id,target) DO NOTHING
                """,
        UUID.randomUUID(),
        event);
    assertEquals(2, jdbc.queryForObject("SELECT count(*) FROM sync_task", Integer.class));
    tx.executeWithoutResult(
        status -> {
          jdbc.update(
              "UPDATE iam_user SET status='DISABLED',auth_epoch=auth_epoch+1,password_gate='BLOCKED' WHERE id=?",
              USER);
          assertEquals(
              1,
              jdbc.queryForObject(
                  "SELECT count(*) FROM outbox_event WHERE event_type='unipass.user.disabled'",
                  Integer.class));
          status.setRollbackOnly();
        });
    assertEquals(
        0,
        jdbc.queryForObject(
            "SELECT count(*) FROM outbox_event WHERE event_type='unipass.user.disabled'",
            Integer.class));
    jdbc.update(
        "UPDATE iam_user SET status='DISABLED',auth_epoch=auth_epoch+1,password_gate='BLOCKED' WHERE id=?",
        USER);
    jdbc.update("UPDATE iam_user SET status='DISABLED' WHERE id=?", USER);
    assertEquals(
        1,
        jdbc.queryForObject(
            "SELECT count(*) FROM outbox_event WHERE event_type='unipass.user.disabled'",
            Integer.class));
    assertEquals(
        Set.of("user_id", "auth_epoch"),
        jdbc
            .queryForList(
                "SELECT jsonb_object_keys(payload) FROM outbox_event WHERE event_type='unipass.user.disabled'",
                String.class)
            .stream()
            .collect(java.util.stream.Collectors.toSet()));
    jdbc.execute(
        "ALTER TABLE sync_task ADD CONSTRAINT reject_disable_target CHECK(false) NOT VALID");
    assertThrows(
        org.springframework.dao.DataAccessException.class,
        () ->
            jdbc.update(
                """
                INSERT INTO outbox_event(event_id,aggregate_id,event_type,auth_epoch,payload,created_at)
                VALUES (?,?,'unipass.password.changed',5,'{}',now())
                """,
                UUID.randomUUID(),
                USER));
    assertEquals(2, jdbc.queryForObject("SELECT count(*) FROM outbox_event", Integer.class));
  }

  @Test
  void successfulAdapterReceivesOnlyTypedMetadataAndNoTransactionLocks() throws Exception {
    UUID event = event(), id = task(event);
    var worker =
        worker(
            adapter(
                value -> {
                  assertEquals(event, value.eventId());
                  assertEquals(USER, value.userId());
                  assertEquals(5, value.authEpoch());
                  assertFalse(value.toString().contains("never-forward-this"));
                  // Claim committed before the external call; another connection can lock the row.
                  tx.executeWithoutResult(
                      ignored ->
                          jdbc.queryForList(
                              "SELECT id FROM sync_task WHERE id=? FOR UPDATE NOWAIT", id));
                  return delivered();
                }));
    assertTrue(worker.runOnce());
    assertFalse(worker.runOnce());
    assertEquals("SUCCESS", state(id));
    assertEquals(
        2,
        jdbc.queryForObject(
            "SELECT count(*) FROM sync_task_audit WHERE task_id=?", Integer.class, id));
    assertNull(jdbc.queryForObject("SELECT lease_owner FROM sync_task WHERE id=?", UUID.class, id));
  }

  @Test
  void unavailableAndPermissionDeniedCapabilitiesBlockWithoutClaimingSuccess() {
    UUID first = task(event());
    worker(null).runOnce();
    assertEquals("BLOCKED", state(first));
    assertEquals(
        "CAPABILITY_MISSING",
        jdbc.queryForObject("SELECT last_error FROM sync_task WHERE id=?", String.class, first));
    UUID second = task(event());
    worker(adapter(event -> Result.blocked(Code.PERMISSION_DENIED))).runOnce();
    assertEquals("BLOCKED", state(second));
    assertThrows(
        IllegalArgumentException.class,
        () -> new Result(Outcome.SUCCESS, Code.CAPABILITY_MISSING, null));
    assertThrows(
        IllegalArgumentException.class,
        () -> new Result(Outcome.SUCCESS_DEGRADED, Code.PERMISSION_DENIED, null));
  }

  @Test
  void rateLimitAndTransientErrorsUseOneFiveFifteenMinutesThenDeadLetter() {
    UUID id = task(event());
    var limited =
        worker(
            adapter(event -> new Result(Outcome.RETRY, Code.RATE_LIMITED, Duration.ofMinutes(10))));
    limited.runOnce();
    assertEquals("PENDING", state(id));
    assertTrue(
        jdbc.queryForObject(
            "SELECT extract(epoch FROM next_retry_at-updated_at)>=600 FROM sync_task WHERE id=?",
            Boolean.class,
            id));
    var temporary = worker(adapter(event -> Result.retry(Code.TEMPORARY_FAILURE)));
    due(id);
    temporary.runOnce();
    assertTrue(
        jdbc.queryForObject(
            "SELECT extract(epoch FROM next_retry_at-updated_at) BETWEEN 299 AND 311 FROM sync_task WHERE id=?",
            Boolean.class,
            id));
    due(id);
    temporary.runOnce();
    assertTrue(
        jdbc.queryForObject(
            "SELECT extract(epoch FROM next_retry_at-updated_at) BETWEEN 899 AND 911 FROM sync_task WHERE id=?",
            Boolean.class,
            id));
    due(id);
    temporary.runOnce();
    assertEquals("DEAD", state(id));
    assertFalse(temporary.runOnce());
    assertEquals(
        4,
        jdbc.queryForObject("SELECT attempt_count FROM sync_task WHERE id=?", Integer.class, id));
    UUID normal = task(event());
    temporary.runOnce();
    assertTrue(
        jdbc.queryForObject(
            "SELECT extract(epoch FROM next_retry_at-updated_at) BETWEEN 59 AND 71 FROM sync_task WHERE id=?",
            Boolean.class,
            normal));
  }

  @Test
  void timedOutOrThrowingAdapterRecordsUnknownOutcomeWithoutRemoteMessage() {
    UUID id = task(event());
    var worker =
        worker(
            adapter(
                event -> {
                  try {
                    new CountDownLatch(1).await();
                  } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                  }
                  return delivered();
                }),
            Duration.ofMillis(100));
    assertTimeoutPreemptively(Duration.ofSeconds(3), () -> assertTrue(worker.runOnce()));
    assertEquals("PENDING", state(id));
    assertEquals(
        "OUTCOME_UNKNOWN",
        jdbc.queryForObject("SELECT last_error FROM sync_task WHERE id=?", String.class, id));
    due(id);
    worker(
            adapter(
                event -> {
                  throw new IllegalStateException("secret-token-never-persist");
                }))
        .runOnce();
    assertEquals(
        0,
        jdbc.queryForObject(
            "SELECT count(*) FROM sync_task_audit WHERE result_code LIKE '%secret%'",
            Integer.class));
    assertEquals(
        "OUTCOME_UNKNOWN",
        jdbc.queryForObject("SELECT last_error FROM sync_task WHERE id=?", String.class, id));
  }

  @Test
  void expiredLeaseCanBeReclaimedAndLateOwnerCannotOverwriteNewResult() throws Exception {
    UUID event = event(), id = task(event);
    CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
    var oldWorker =
        worker(
            adapter(
                value -> {
                  entered.countDown();
                  try {
                    assertTrue(release.await(3, TimeUnit.SECONDS));
                  } catch (InterruptedException interrupted) {
                    throw new IllegalStateException(interrupted);
                  }
                  return delivered();
                }));
    ExecutorService executor = Executors.newSingleThreadExecutor();
    try {
      Future<Boolean> pending = executor.submit(oldWorker::runOnce);
      assertTrue(entered.await(3, TimeUnit.SECONDS));
      jdbc.update(
          "UPDATE sync_task SET lease_until=clock_timestamp()-interval '1 second' WHERE id=?", id);
      AtomicReference<UUID> replayed = new AtomicReference<>();
      worker(
              adapter(
                  value -> {
                    replayed.set(value.eventId());
                    return Result.blocked(Code.PERMISSION_DENIED);
                  }))
          .runOnce();
      release.countDown();
      assertTrue(pending.get(3, TimeUnit.SECONDS));
      assertEquals(event, replayed.get());
      assertEquals("BLOCKED", state(id));
      assertEquals(
          2,
          jdbc.queryForObject("SELECT attempt_count FROM sync_task WHERE id=?", Integer.class, id));
      assertEquals(
          1,
          jdbc.queryForObject(
              "SELECT count(*) FROM sync_task_audit WHERE task_id=? AND action='FINISHED'",
              Integer.class,
              id));
    } finally {
      release.countDown();
      executor.shutdownNow();
    }
  }

  @Test
  void twoWorkersSkipBusyTaskInsteadOfDuplicatingDelivery() throws Exception {
    UUID id = task(event());
    AtomicInteger calls = new AtomicInteger();
    CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
    var slow =
        worker(
            adapter(
                event -> {
                  calls.incrementAndGet();
                  entered.countDown();
                  try {
                    assertTrue(release.await(3, TimeUnit.SECONDS));
                  } catch (InterruptedException interrupted) {
                    throw new IllegalStateException(interrupted);
                  }
                  return delivered();
                }));
    var other =
        worker(
            adapter(
                event -> {
                  calls.incrementAndGet();
                  return delivered();
                }));
    ExecutorService executor = Executors.newSingleThreadExecutor();
    try {
      Future<Boolean> pending = executor.submit(slow::runOnce);
      assertTrue(entered.await(3, TimeUnit.SECONDS));
      assertFalse(other.runOnce());
      release.countDown();
      assertTrue(pending.get(3, TimeUnit.SECONDS));
      assertEquals(1, calls.get());
      assertEquals("SUCCESS", state(id));
    } finally {
      release.countDown();
      executor.shutdownNow();
    }
  }

  @Test
  void crashedLastAttemptDiesWithoutMakingFifthExternalCall() {
    UUID id = task(event());
    jdbc.update(
        """
                UPDATE sync_task SET state='RUNNING',attempt_count=4,lease_version=4,lease_owner=?,lease_token=?,
                lease_until=clock_timestamp()-interval '1 second' WHERE id=?
                """,
        UUID.randomUUID(),
        UUID.randomUUID(),
        id);
    var worker =
        worker(
            adapter(
                event -> {
                  fail("A fifth delivery is forbidden");
                  return delivered();
                }));
    assertTrue(worker.runOnce());
    assertEquals("DEAD", state(id));
    assertFalse(worker.runOnce());
    assertEquals(
        "LEASE_EXPIRED",
        jdbc.queryForObject("SELECT last_error FROM sync_task WHERE id=?", String.class, id));
  }

  @Test
  void lockedPendingTaskIsSkippedAndProcessedAfterRelease() throws Exception {
    UUID first = task(event()), second = task(event());
    var worker = worker(adapter(event -> delivered()));
    try (var connection = jdbc.getDataSource().getConnection()) {
      connection.setAutoCommit(false);
      try (var statement =
          connection.prepareStatement("SELECT id FROM sync_task WHERE id=? FOR UPDATE")) {
        statement.setObject(1, first);
        statement.executeQuery().close();
      }
      assertTrue(worker.runOnce());
      assertEquals("SUCCESS", state(second));
      assertEquals("PENDING", state(first));
      connection.rollback();
    }
    assertTrue(worker.runOnce());
    assertEquals("SUCCESS", state(first));
  }

  @Test
  void interruptIgnoringAdapterHasBoundedCapacityAndNoUnboundedQueue() {
    CountDownLatch release = new CountDownLatch(1);
    AtomicInteger calls = new AtomicInteger();
    var worker =
        worker(
            adapter(
                event -> {
                  calls.incrementAndGet();
                  boolean done = false;
                  while (!done) {
                    try {
                      done = release.await(1, TimeUnit.SECONDS);
                    } catch (InterruptedException ignored) {
                      /* fault injection */
                    }
                  }
                  return delivered();
                }),
            Duration.ofMillis(100));
    try {
      UUID first = task(event());
      worker.runOnce();
      assertEquals("PENDING", state(first));
      UUID second = task(event());
      worker.runOnce();
      assertEquals("PENDING", state(second));
      UUID third = task(event());
      worker.runOnce();
      assertEquals(
          "LOCAL_CAPACITY",
          jdbc.queryForObject("SELECT last_error FROM sync_task WHERE id=?", String.class, third));
      assertEquals(2, calls.get());
      assertEquals("PENDING", state(third));
    } finally {
      release.countDown();
    }
  }

  @Test
  void unknownEventVersionDiesBeforeCallingAdapter() {
    UUID event = event(), id = task(event);
    jdbc.update("UPDATE outbox_event SET schema_version=2 WHERE event_id=?", event);
    worker(
            adapter(
                value -> {
                  fail("Unknown event schema must not be delivered");
                  return delivered();
                }))
        .runOnce();
    assertEquals("DEAD", state(id));
    assertEquals(
        "UNSUPPORTED_EVENT",
        jdbc.queryForObject("SELECT last_error FROM sync_task WHERE id=?", String.class, id));
  }

  @Test
  void operatorRequeueAndWorkerCompletionRollbackTogetherWithTheirAudit() {
    UUID id = task(event());
    var worker = worker(null);
    worker.runOnce();
    var admin = new SyncTaskAdmin(jdbc, tx);
    assertEquals(1, admin.tasks(100).size());
    assertEquals(0, admin.report().missingTasks());
    assertEquals(0, admin.report().unroutedEvents());
    assertThrows(IllegalArgumentException.class, () -> admin.retry(id, "operator:test", ""));
    jdbc.execute(
        "ALTER TABLE sync_task_audit ADD CONSTRAINT reject_requeue CHECK(action<>'REQUEUED')");
    assertThrows(
        org.springframework.dao.DataAccessException.class,
        () -> admin.retry(id, "operator:test", "ticket:123"));
    assertEquals("BLOCKED", state(id));
    jdbc.execute("ALTER TABLE sync_task_audit DROP CONSTRAINT reject_requeue");
    assertTrue(admin.retry(id, "operator:test", "ticket:123"));
    assertFalse(admin.retry(id, "operator:test", "ticket:123"));
    assertEquals(
        1,
        jdbc.queryForObject(
            "SELECT previous_attempt_count FROM sync_task_audit WHERE action='REQUEUED'",
            Integer.class));
    jdbc.execute(
        "ALTER TABLE sync_task_audit ADD CONSTRAINT reject_finish CHECK(action<>'FINISHED') NOT VALID");
    assertThrows(org.springframework.dao.DataAccessException.class, worker::runOnce);
    assertEquals("RUNNING", state(id));
    jdbc.execute("ALTER TABLE sync_task_audit DROP CONSTRAINT reject_finish");
    jdbc.update(
        "UPDATE sync_task SET lease_until=clock_timestamp()-interval '1 second' WHERE id=?", id);
    worker(adapter(event -> delivered())).runOnce();
    assertEquals("SUCCESS", state(id));
    assertFalse(admin.retry(id, "operator:test", "ticket:123"));
  }

  @Test
  void deferredCommitFailureCannotLoseClaimOrHideRepeatedExternalDelivery() {
    UUID event = event(), id = task(event);
    AtomicInteger calls = new AtomicInteger();
    var worker =
        worker(
            adapter(
                value -> {
                  assertEquals(event, value.eventId());
                  calls.incrementAndGet();
                  return delivered();
                }));
    jdbc.execute(
        """
                CREATE FUNCTION reject_sync_commit() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN IF NEW.action='CLAIMED' THEN RAISE EXCEPTION 'injected commit failure'; END IF; RETURN NEW; END $$
                """);
    jdbc.execute(
        """
                CREATE CONSTRAINT TRIGGER reject_sync_commit AFTER INSERT ON sync_task_audit
                DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_sync_commit()
                """);
    assertThrows(RuntimeException.class, worker::runOnce);
    assertEquals("PENDING", state(id));
    assertEquals(0, calls.get());
    assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM sync_task_audit", Integer.class));
    jdbc.execute(
        """
                CREATE OR REPLACE FUNCTION reject_sync_commit() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN IF NEW.action='FINISHED' THEN RAISE EXCEPTION 'injected commit failure'; END IF; RETURN NEW; END $$
                """);
    assertThrows(RuntimeException.class, worker::runOnce);
    assertEquals("RUNNING", state(id));
    assertEquals(1, calls.get());
    assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM sync_task_audit", Integer.class));
    jdbc.execute("DROP TRIGGER reject_sync_commit ON sync_task_audit");
    jdbc.update(
        "UPDATE sync_task SET lease_until=clock_timestamp()-interval '1 second' WHERE id=?", id);
    worker.runOnce();
    assertEquals("SUCCESS", state(id));
    assertEquals(2, calls.get());
    assertEquals(3, jdbc.queryForObject("SELECT count(*) FROM sync_task_audit", Integer.class));
  }

  @Test
  void expiredOwnerCannotConfirmEvenBeforeAnotherWorkerClaims() {
    UUID id = task(event());
    worker(
            adapter(
                value -> {
                  jdbc.update(
                      "UPDATE sync_task SET lease_until=clock_timestamp()-interval '1 second' WHERE id=?",
                      id);
                  return delivered();
                }))
        .runOnce();
    assertEquals("RUNNING", state(id));
    assertEquals(
        0,
        jdbc.queryForObject(
            "SELECT count(*) FROM sync_task_audit WHERE action='FINISHED'", Integer.class));
    worker(adapter(value -> delivered())).runOnce();
    assertEquals("SUCCESS", state(id));
  }

  @Test
  void packagedOperatorCliReportsAndAuditsRequeue() throws Exception {
    UUID id = task(event());
    worker(null).runOnce();
    String report = cli("report");
    assertTrue(report.contains("BLOCKED"));
    assertTrue(report.contains("missingTasks"));
    assertFalse(report.contains("never-forward-this"));
    assertTrue(cli("tasks").contains(id.toString()));
    assertTrue(cli("retry", id.toString()).contains("true"));
    assertEquals("PENDING", state(id));
    assertEquals(
        "ticket:cli-sync",
        jdbc.queryForObject(
            "SELECT evidence_ref FROM sync_task_audit WHERE action='REQUEUED'", String.class));
  }

  @Test
  void upgradingV9PreservesExistingTasksRecoversClaimsAndBackfillsDisabledUsers() {
    Flyway.configure().dataSource(jdbc.getDataSource()).cleanDisabled(false).load().clean();
    Flyway.configure().dataSource(jdbc.getDataSource()).target("9").load().migrate();
    jdbc.update("INSERT INTO import_source(source_id,cursor_value) VALUES ('sync-test','1')");
    jdbc.update(
        """
                INSERT INTO iam_user(id,employee_no,directory_id,directory_type,ldap_dn,display_name,status,source_id,source_version,auth_epoch,password_gate)
                VALUES (?,'sync-test',?,'OPENLDAP','uid=test','Test','DISABLED','sync-test',1,5,'BLOCKED')
                """,
        USER,
        UUID.randomUUID());
    UUID event = UUID.randomUUID(), task = UUID.randomUUID();
    jdbc.update(
        """
                INSERT INTO outbox_event(event_id,aggregate_id,event_type,auth_epoch,payload,created_at)
                VALUES (?,?,'unipass.password.changed',4,'{}',now())
                """,
        event,
        USER);
    jdbc.update(
        """
                INSERT INTO sync_task(id,event_id,target,state,attempt_count,next_retry_at,lease_token,lease_until)
                VALUES (?,?,'APP_PUSH','RUNNING',2,now(),?,now()+interval '1 minute')
                """,
        task,
        event,
        UUID.randomUUID());
    Flyway.configure().dataSource(jdbc.getDataSource()).load().migrate();
    assertEquals("PENDING", state(task));
    assertEquals(
        2,
        jdbc.queryForObject("SELECT attempt_count FROM sync_task WHERE id=?", Integer.class, task));
    assertEquals(
        2,
        jdbc.queryForObject(
            "SELECT count(*) FROM sync_task WHERE event_id=?", Integer.class, event));
    assertEquals(
        1,
        jdbc.queryForObject(
            "SELECT count(*) FROM outbox_event WHERE event_type='unipass.user.disabled' AND auth_epoch=5",
            Integer.class));
    assertEquals(4, jdbc.queryForObject("SELECT count(*) FROM sync_task", Integer.class));
    assertEquals(0, new SyncTaskAdmin(jdbc, tx).report().missingTasks());
    Flyway.configure().dataSource(jdbc.getDataSource()).load().migrate();
    assertEquals(4, jdbc.queryForObject("SELECT count(*) FROM sync_task", Integer.class));
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
                "-Dloader.main=com.unipass.server.SyncTaskAdminCli",
                "-cp",
                Path.of(
                        System.getProperty(
                            "test.server.exec.jar", "target/iam-server-0.1.0-SNAPSHOT-exec.jar"))
                    .toAbsolutePath()
                    .toString(),
                "org.springframework.boot.loader.launch.PropertiesLauncher"));
    command.addAll(List.of(args));
    Path log = Path.of("target", "sync-delivery", "cli-" + UUID.randomUUID() + ".log");
    var process =
        new ProcessBuilder(command).redirectErrorStream(true).redirectOutput(log.toFile());
    process.environment().keySet().removeIf(name -> name.startsWith("UNIPASS_"));
    process
        .environment()
        .putAll(
            Map.of(
                "UNIPASS_DB_URL",
                pg.getJdbcUrl("postgres", "postgres"),
                "UNIPASS_DB_USER",
                "postgres",
                "UNIPASS_DB_PASSWORD",
                "postgres",
                "UNIPASS_OPERATOR_REF",
                "operator:cli-sync",
                "UNIPASS_EVIDENCE_REF",
                "ticket:cli-sync"));
    Process running = process.start();
    try {
      assertTrue(running.waitFor(20, TimeUnit.SECONDS));
      assertEquals(0, running.exitValue(), () -> read(log));
      return read(log);
    } finally {
      if (running.isAlive()) running.destroyForcibly();
    }
  }

  private static String read(Path path) {
    try {
      return Files.readString(path);
    } catch (Exception failure) {
      return "Cannot read CLI output";
    }
  }
}
