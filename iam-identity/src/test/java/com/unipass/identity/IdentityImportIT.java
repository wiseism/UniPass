package com.unipass.identity;

import static org.junit.jupiter.api.Assertions.*;

import com.unipass.directory.*;
import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import java.sql.*;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.*;

/** Real PostgreSQL integration suite, selected by the integration Maven profile. */
class IdentityImportIT {
  private static EmbeddedPostgres postgres;
  private static Database testDatabase;
  private Database db;
  private FakeDirectory directory;
  private IdentityImportService imports;
  private IdentityLifecycleService lifecycle;
  private String first, second;

  @BeforeAll
  static void database() throws Exception {
    String url = System.getProperty("test.db.url");
    if (url == null) {
      System.setProperty(
          "ot.epg.working-dir",
          java.nio.file.Files.createDirectories(java.nio.file.Path.of("target", "embedded-pg"))
              .toAbsolutePath()
              .toString());
      postgres =
          EmbeddedPostgres.builder()
              .setPort(0)
              .setServerConfig("listen_addresses", "127.0.0.1")
              .start();
      testDatabase = new Database(postgres.getJdbcUrl("postgres", "postgres"), "postgres", "");
    } else {
      testDatabase =
          new Database(
              url,
              System.getProperty("test.db.user", "unipass_test"),
              System.getProperty("test.db.password", "unipass_test_only"));
    }
    testDatabase.migrate();
  }

  @AfterAll
  static void stopDatabase() throws Exception {
    if (postgres != null) postgres.close();
  }

  @BeforeEach
  void setup() throws Exception {
    db = testDatabase;
    try (Connection c = db.open();
        Statement s = c.createStatement()) {
      s.execute("TRUNCATE import_source CASCADE");
    }
    directory = new FakeDirectory();
    first = directory.add("E001");
    second = directory.add("E002");
    imports = new IdentityImportService(db, directory, DirectoryConfig.Type.OPENLDAP);
    lifecycle = new IdentityLifecycleService(db, directory);
  }

  private HrRow row(String employee, String id, String status, long version) {
    return new HrRow(employee, id, "Employee", status, version);
  }

  private UUID initial() throws Exception {
    var preview = imports.preview("hr", "", "1", List.of(row("E001", first, "ACTIVE", 1)));
    imports.apply(preview.batchId());
    return userId(first);
  }

  private UUID userId(String directoryId) throws Exception {
    try (Connection c = db.open();
        PreparedStatement s = c.prepareStatement("SELECT id FROM iam_user WHERE directory_id=?")) {
      s.setObject(1, UUID.fromString(directoryId));
      try (ResultSet r = s.executeQuery()) {
        assertTrue(r.next());
        return r.getObject(1, UUID.class);
      }
    }
  }

  private String scalar(String sql) throws Exception {
    try (Connection c = db.open();
        Statement s = c.createStatement();
        ResultSet r = s.executeQuery(sql)) {
      assertTrue(r.next());
      return r.getString(1);
    }
  }

  @Test
  void previewDoesNotMutateIdentitiesAndRepeatedApplyIsIdempotent() throws Exception {
    var rows = List.of(row("E001", first, "ACTIVE", 1));
    var p = imports.preview("hr", "", "1", rows);
    assertEquals("CREATE", p.rows().get(0).action());
    assertEquals("0", scalar("SELECT count(*) FROM iam_user"));
    assertEquals(p.batchId(), imports.preview("hr", "", "1", rows).batchId());
    assertEquals(1, imports.apply(p.batchId()).appliedRows());
    assertTrue(imports.apply(p.batchId()).alreadyApplied());
    assertEquals("1", scalar("SELECT count(*) FROM iam_user"));
    assertEquals("1", scalar("SELECT cursor_value FROM import_source WHERE source_id='hr'"));
    assertEquals(
        "1", scalar("SELECT count(*) FROM identity_audit WHERE action='IDENTITY_IMPORTED'"));
  }

  @Test
  void quarantinesAllDuplicateRowsAndAppliesUnrelatedValidRow() throws Exception {
    var p =
        imports.preview(
            "hr",
            "",
            "1",
            List.of(
                row("E001", first, "ACTIVE", 1),
                row("E001", first.toUpperCase(Locale.ROOT), "ACTIVE", 1),
                row("E002", second, "ACTIVE", 1)));
    assertEquals(1, p.validCount());
    assertEquals("DUPLICATE_INPUT", p.rows().get(0).errorCode());
    assertEquals("DUPLICATE_INPUT", p.rows().get(1).errorCode());
    assertEquals(1, imports.apply(p.batchId()).appliedRows());
    assertEquals("E002", scalar("SELECT employee_no FROM iam_user"));
  }

  @Test
  void dnMovePreservesInternalIdAndMissingRowsNeverDeleteUsers() throws Exception {
    UUID original = initial();
    directory.move(first, "uid=moved,dc=example,dc=test");
    var p = imports.preview("hr", "1", "2", List.of(row("E001", first, "ACTIVE", 2)));
    imports.apply(p.batchId());
    assertEquals(original, userId(first));
    assertEquals("uid=moved,dc=example,dc=test", scalar("SELECT ldap_dn FROM iam_user"));
    imports.apply(
        imports.preview("hr", "2", "3", List.of(row("E002", second, "ACTIVE", 1))).batchId());
    assertEquals("2", scalar("SELECT count(*) FROM iam_user"));
  }

  @Test
  void accountCannotReactivateFromStalePreviewAfterManualDisable() throws Exception {
    UUID id = initial();
    var update = imports.preview("hr", "1", "2", List.of(row("E001", first, "ACTIVE", 2)));
    lifecycle.disable(id, UUID.randomUUID());
    assertFalse(lifecycle.canAuthenticate(id, 0));
    assertFalse(lifecycle.canAuthenticate(id, 1));
    assertThrows(IllegalStateException.class, () -> imports.apply(update.batchId()));
    assertEquals("1", scalar("SELECT cursor_value FROM import_source WHERE source_id='hr'"));
    assertEquals("PREVIEW", imports.report(update.batchId()).state());
  }

  @Test
  void failedDirectoryDisableKeepsLocalGateClosedAndRetryIsDurable() throws Exception {
    UUID id = initial();
    lifecycle.disable(id, UUID.randomUUID());
    lifecycle.disable(id, UUID.randomUUID());
    assertEquals("1", scalar("SELECT auth_epoch FROM iam_user"));
    directory.failWrite = true;
    assertTrue(lifecycle.reconcileOne());
    assertEquals("PENDING", scalar("SELECT state FROM directory_disable_task"));
    assertEquals("UNKNOWN_WRITE", scalar("SELECT last_error FROM directory_disable_task"));
    assertFalse(lifecycle.canAuthenticate(id, 0));
    directory.failWrite = false;
    try (Connection c = db.open();
        Statement s = c.createStatement()) {
      s.executeUpdate(
          "UPDATE directory_disable_task SET next_attempt_at=now()-interval '1 second'");
    }
    assertTrue(lifecycle.reconcileOne());
    assertEquals("DONE", scalar("SELECT state FROM directory_disable_task"));
    assertTrue(directory.users.get(first).disabled());
  }

  @Test
  void sourceCursorConflictDoesNotPartiallyCommit() throws Exception {
    var a = imports.preview("hr", "", "1", List.of(row("E001", first, "ACTIVE", 1)));
    var b = imports.preview("hr", "", "2", List.of(row("E002", second, "ACTIVE", 1)));
    imports.apply(a.batchId());
    assertThrows(IllegalStateException.class, () -> imports.apply(b.batchId()));
    assertEquals("1", scalar("SELECT count(*) FROM iam_user"));
  }

  @Test
  void allInvalidBatchDoesNotAdvanceCursorAndDoesNotCallDirectory() throws Exception {
    var p =
        imports.preview(
            "hr", "", "1", List.of(row("", "bad", "INVALID_STATUS_LONGER_THAN_SIXTEEN", -1)));
    assertEquals(0, p.validCount());
    assertThrows(IllegalStateException.class, () -> imports.apply(p.batchId()));
    assertEquals("", scalar("SELECT cursor_value FROM import_source WHERE source_id='hr'"));
    assertEquals(0, directory.lookups);
  }

  @Test
  void rejectsStaleVersionsAndDirectoryIdentityMismatchWithoutSilentMerge() throws Exception {
    initial();
    var stale = imports.preview("hr", "1", "2", List.of(row("E001", first, "ACTIVE", 1)));
    assertEquals("STALE_SOURCE_VERSION", stale.rows().get(0).errorCode());
    var mismatch = imports.preview("hr", "1", "2", List.of(row("E003", second, "ACTIVE", 1)));
    assertEquals("DIRECTORY_IDENTITY_MISMATCH", mismatch.rows().get(0).errorCode());
  }

  @Test
  void concurrentApplyOnlyCreatesOneIdentity() throws Exception {
    var p = imports.preview("hr", "", "1", List.of(row("E001", first, "ACTIVE", 1)));
    ExecutorService pool = Executors.newFixedThreadPool(2);
    try {
      var a = pool.submit(() -> imports.apply(p.batchId()));
      var b = pool.submit(() -> imports.apply(p.batchId()));
      assertNotEquals(
          a.get(10, TimeUnit.SECONDS).alreadyApplied(),
          b.get(10, TimeUnit.SECONDS).alreadyApplied());
      assertEquals("1", scalar("SELECT count(*) FROM iam_user"));
    } finally {
      pool.shutdownNow();
    }
  }

  @Test
  void lateConflictRollsBackEarlierRowsAndKeepsCursor() throws Exception {
    var p =
        imports.preview(
            "hr",
            "",
            "1",
            List.of(row("E001", first, "ACTIVE", 1), row("E002", second, "ACTIVE", 1)));
    imports.apply(
        imports.preview("other_hr", "", "1", List.of(row("E002", second, "ACTIVE", 1))).batchId());
    assertThrows(IllegalStateException.class, () -> imports.apply(p.batchId()));
    assertEquals("1", scalar("SELECT count(*) FROM iam_user"));
    assertEquals("E002", scalar("SELECT employee_no FROM iam_user"));
    assertEquals("", scalar("SELECT cursor_value FROM import_source WHERE source_id='hr'"));
    assertEquals("PREVIEW", imports.report(p.batchId()).state());
  }

  @Test
  void staleWorkerCannotCompleteNewlyEnqueuedDisable() throws Exception {
    UUID id = initial();
    lifecycle.disable(id, UUID.randomUUID());
    directory.duringDisable =
        () -> {
          try {
            lifecycle.disable(id, UUID.randomUUID());
          } catch (SQLException e) {
            throw new RuntimeException(e);
          }
        };
    assertTrue(lifecycle.reconcileOne());
    assertEquals("PENDING", scalar("SELECT state FROM directory_disable_task"));
    directory.duringDisable = null;
    assertTrue(lifecycle.reconcileOne());
    assertEquals("DONE", scalar("SELECT state FROM directory_disable_task"));
  }

  @Test
  void packagedCliCanMigrateAndReportWithoutDirectoryCredentials() throws Exception {
    var p = imports.preview("hr", "", "1", List.of(row("E001", first, "ACTIVE", 1)));
    String javaCommand =
        java.nio.file.Path.of(
                System.getProperty("java.home"),
                "bin",
                System.getProperty("os.name").startsWith("Windows") ? "java.exe" : "java")
            .toString();
    for (List<String> args :
        List.of(List.of("migrate"), List.of("report", p.batchId().toString()))) {
      List<String> command =
          new ArrayList<>(
              List.of(
                  javaCommand,
                  "-jar",
                  System.getProperty(
                      "test.identity.cli.jar", "target/iam-identity-0.1.0-SNAPSHOT-cli.jar")));
      command.addAll(args);
      ProcessBuilder pb = new ProcessBuilder(command).redirectErrorStream(true);
      pb.environment().keySet().removeIf(key -> key.startsWith("UNIPASS_"));
      pb.environment().put("UNIPASS_DB_URL", db.url());
      pb.environment().put("UNIPASS_DB_USER", db.username());
      pb.environment()
          .put("UNIPASS_DB_PASSWORD", db.password().isEmpty() ? "unused-test-only" : db.password());
      Process process = pb.start();
      assertTrue(process.waitFor(20, TimeUnit.SECONDS));
      String output =
          new String(
              process.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
      assertEquals(0, process.exitValue(), output);
      if (args.get(0).equals("report")) {
        assertTrue(output.contains("action=CREATE"));
        assertTrue(output.contains("valid=1"));
      }
    }
  }

  @Test
  void directoryOutageRollsBackPreviewAndDatabaseOutageDoesNotAllowAuthentication()
      throws Exception {
    directory.failRead = true;
    assertThrows(
        DirectoryFailure.class,
        () -> imports.preview("hr", "", "1", List.of(row("E001", first, "ACTIVE", 1))));
    assertEquals("0", scalar("SELECT count(*) FROM import_batch"));
    Database down = new Database("jdbc:postgresql://127.0.0.1:1/absent", "absent", "absent");
    assertThrows(
        SQLException.class,
        () -> new IdentityLifecycleService(down, directory).canAuthenticate(UUID.randomUUID(), 0));
  }

  private static final class FakeDirectory implements DirectoryGateway {
    @Override
    public DirectoryConfig.Type type() {
      return DirectoryConfig.Type.OPENLDAP;
    }

    final Map<String, DirectoryUser> users = new HashMap<>();
    boolean failWrite, failRead;
    int lookups;
    Runnable duringDisable;

    String add(String employee) {
      String id = UUID.randomUUID().toString();
      users.put(
          id, new DirectoryUser(id, employee, "uid=" + employee + ",dc=example,dc=test", false));
      return id;
    }

    void move(String id, String dn) {
      var u = users.get(id);
      users.put(id, new DirectoryUser(id, u.employeeNo(), dn, u.disabled()));
    }

    @Override
    public Optional<DirectoryUser> findByStableId(String id) {
      lookups++;
      if (failRead) throw new DirectoryFailure(DirectoryFailure.Kind.UNAVAILABLE);
      return Optional.ofNullable(users.get(id));
    }

    @Override
    public boolean verifyCredential(String id, char[] p) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void changePassword(String id, char[] a, char[] b) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void disableUser(String id) {
      if (failWrite) throw new DirectoryFailure(DirectoryFailure.Kind.UNKNOWN_WRITE);
      if (duringDisable != null) duringDisable.run();
      var u = users.get(id);
      users.put(id, new DirectoryUser(id, u.employeeNo(), u.dn(), true));
    }
  }
}
