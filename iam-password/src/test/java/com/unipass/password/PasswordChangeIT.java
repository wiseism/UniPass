package com.unipass.password;

import static com.unipass.password.PasswordFailure.Code.*;
import static com.unipass.password.PasswordOperation.State.*;
import static org.junit.jupiter.api.Assertions.*;

import com.unipass.directory.*;
import com.unipass.identity.*;
import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import java.nio.file.*;
import java.sql.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.*;

class PasswordChangeIT {
  private static EmbeddedPostgres postgres;
  private static Database db;
  private MutableClock clock;
  private FakeDirectory directory;
  private PasswordChangeService passwords;
  private UUID user, admin;
  private static final String OLD = "Qx!7vN2$pk", NEW = "Rz@8mP4#st", THIRD = "Hz@9kM5!qp";

  @BeforeAll
  static void startDatabase() throws Exception {
    System.setProperty(
        "ot.epg.working-dir",
        Files.createDirectories(Path.of("target", "embedded-pg")).toAbsolutePath().toString());
    postgres =
        EmbeddedPostgres.builder()
            .setPort(0)
            .setServerConfig("listen_addresses", "127.0.0.1")
            .start();
    db = new Database(postgres.getJdbcUrl("postgres", "postgres"), "postgres", "");
    db.migrate();
  }

  @AfterAll
  static void stopDatabase() throws Exception {
    if (postgres != null) postgres.close();
  }

  @BeforeEach
  void setup() throws Exception {
    try (Connection c = db.open();
        Statement s = c.createStatement()) {
      s.execute("ALTER TABLE outbox_event DROP CONSTRAINT IF EXISTS reject_events");
      s.execute("TRUNCATE import_source CASCADE");
    }
    clock = new MutableClock(Instant.now().truncatedTo(java.time.temporal.ChronoUnit.MICROS));
    directory = new FakeDirectory();
    user = seed("E001");
    admin = seed("ADMIN9");
    passwords = service(point -> {});
  }

  private UUID seed(String employee) throws Exception {
    UUID id = UUID.randomUUID();
    try (Connection c = db.open()) {
      sql(
          c,
          "INSERT INTO import_source(source_id,cursor_value) VALUES ('hr','1') ON CONFLICT DO NOTHING");
      sql(
          c,
          "INSERT INTO iam_user(id,employee_no,directory_id,directory_type,ldap_dn,display_name,status,source_id,source_version) VALUES (?,?,?,'OPENLDAP',?,'员工','ACTIVE','hr',1)",
          id,
          employee,
          id,
          "uid=" + employee + ",dc=example");
    }
    directory.passwords.put(id.toString(), OLD);
    return id;
  }

  private PasswordChangeService service(PasswordChangeService.Hook hook) {
    return new PasswordChangeService(db, directory, PasswordPolicy.defaults(), clock, true, hook);
  }

  private AuthenticatedActor actor(long epoch) {
    return AuthenticatedActor.user(user, epoch, clock.instant());
  }

  private AuthenticatedActor recoveryAdmin() {
    return new AuthenticatedActor(
        admin, 0, clock.instant(), Set.of("PASSWORD_RECOVERY"), clock.instant());
  }

  private static String key() {
    return UUID.randomUUID().toString();
  }

  private PasswordOperation change(String key) {
    return passwords.change(actor(0), key, OLD.toCharArray(), NEW.toCharArray(), NEW.toCharArray());
  }

  private String scalar(String query) throws Exception {
    try (Connection c = db.open();
        Statement s = c.createStatement();
        ResultSet r = s.executeQuery(query)) {
      assertTrue(r.next());
      return r.getString(1);
    }
  }

  private boolean allowed(long epoch) throws Exception {
    return new IdentityLifecycleService(db, directory).canAuthenticate(user, epoch);
  }

  @Test
  void successfulChangeFencesOldSessionsAndAtomicallyCreatesOutboxTasksAndAudit() throws Exception {
    directory.beforeWrite =
        () -> {
          try {
            assertFalse(allowed(0));
            assertFalse(allowed(1));
          } catch (Exception e) {
            throw new RuntimeException(e);
          }
        };
    char[] old = OLD.toCharArray(), next = NEW.toCharArray(), confirm = NEW.toCharArray();
    PasswordOperation op = passwords.change(actor(0), key(), old, next, confirm);
    assertEquals(COMMITTED, op.state());
    assertEquals(1, op.fencedEpoch());
    assertTrue(Arrays.equals(old, new char[old.length]));
    assertTrue(Arrays.equals(next, new char[next.length]));
    assertTrue(Arrays.equals(confirm, new char[confirm.length]));
    assertFalse(allowed(0));
    assertTrue(allowed(1));
    assertEquals(NEW, directory.passwords.get(user.toString()));
    assertEquals("1", scalar("SELECT count(*) FROM outbox_event"));
    assertEquals("2", scalar("SELECT count(*) FROM sync_task"));
    assertEquals(
        "1", scalar("SELECT count(*) FROM password_audit WHERE action='PASSWORD_CHANGED'"));
    String payload = scalar("SELECT payload::text FROM outbox_event");
    assertFalse(payload.contains(NEW));
    assertFalse(payload.contains(OLD));
  }

  @Test
  void sameIdempotencyKeyNeverRepeatsDirectoryWriteEvenWithOldEpoch() {
    String key = key();
    PasswordOperation first = change(key);
    assertEquals(first.id(), change(key).id());
    assertEquals(1, directory.writes);
  }

  @Test
  void badOldPasswordOrWeakNewPasswordDoesNotFenceAccount() throws Exception {
    assertEquals(
        OLD_PASSWORD_INCORRECT,
        assertThrows(
                PasswordFailure.class,
                () ->
                    passwords.change(
                        actor(0),
                        key(),
                        "wrong".toCharArray(),
                        NEW.toCharArray(),
                        NEW.toCharArray()))
            .code());
    clock.advance(61);
    assertEquals(
        POLICY_REJECTED,
        assertThrows(
                PasswordFailure.class,
                () ->
                    passwords.change(
                        actor(0),
                        key(),
                        OLD.toCharArray(),
                        "weak".toCharArray(),
                        "weak".toCharArray()))
            .code());
    assertTrue(allowed(0));
    assertEquals("0", scalar("SELECT count(*) FROM password_operation"));
    assertEquals(0, directory.writes);
  }

  @Test
  void unverifiedDirectoryPolicyFailsClosed() {
    var unverified =
        new PasswordChangeService(db, directory, PasswordPolicy.defaults(), clock, false);
    assertEquals(
        DIRECTORY_POLICY_NOT_VERIFIED,
        assertThrows(
                PasswordFailure.class,
                () ->
                    unverified.change(
                        actor(0), key(), OLD.toCharArray(), NEW.toCharArray(), NEW.toCharArray()))
            .code());
    assertEquals(0, directory.writes);
  }

  @Test
  void explicitDirectoryRejectionReopensGateButNeverRestoresOldEpoch() throws Exception {
    directory.mode = Mode.REJECT;
    PasswordOperation op = change(key());
    assertEquals(REJECTED, op.state());
    assertFalse(allowed(0));
    assertTrue(allowed(1));
    assertEquals("0", scalar("SELECT count(*) FROM outbox_event"));
  }

  @Test
  void timeoutBeforeOrAfterActualDirectoryWriteAlwaysStaysBlocked() throws Exception {
    directory.mode = Mode.TIMEOUT_AFTER;
    String key = key();
    PasswordOperation op = change(key);
    assertEquals(UNKNOWN, op.state());
    assertEquals(NEW, directory.passwords.get(user.toString()));
    assertFalse(allowed(0));
    assertFalse(allowed(1));
    assertEquals(op.id(), change(key).id());
    assertEquals(1, directory.writes);
    assertEquals("0", scalar("SELECT count(*) FROM outbox_event"));
  }

  @Test
  void postgresFinalizationFailurePreservesGateAndDoesNotLeakPartialEvents() throws Exception {
    try (Connection c = db.open()) {
      sql(c, "ALTER TABLE outbox_event ADD CONSTRAINT reject_events CHECK(false)");
    }
    var op = change(key());
    assertEquals(UNKNOWN, op.state());
    assertEquals("FINALIZATION_UNAVAILABLE", op.errorCode());
    assertFalse(allowed(1));
    assertEquals("0", scalar("SELECT count(*) FROM outbox_event"));
    assertEquals("0", scalar("SELECT count(*) FROM sync_task"));
    assertEquals(NEW, directory.passwords.get(user.toString()));
  }

  @Test
  void crashAfterPrepareIsRecoveredToUnknownWithoutReplayingWrite() throws Exception {
    passwords =
        service(
            point -> {
              if (point == PasswordChangeService.Point.AFTER_PREPARE) throw new Crash();
            });
    assertThrows(Crash.class, () -> change(key()));
    assertEquals(0, directory.writes);
    assertFalse(allowed(0));
    clock.advance(31);
    assertEquals(1, passwords.markAbandonedUnknown());
    assertEquals(0, passwords.markAbandonedUnknown());
    assertEquals("UNKNOWN", scalar("SELECT state FROM password_operation"));
    assertFalse(allowed(1));
  }

  @Test
  void crashAfterDirectoryWriteCannotBeAssumedFailedAndConfirmedRecoveryIsAudited()
      throws Exception {
    String key = key();
    passwords =
        service(
            point -> {
              if (point == PasswordChangeService.Point.AFTER_DIRECTORY_WRITE) throw new Crash();
            });
    assertThrows(Crash.class, () -> change(key));
    assertEquals(NEW, directory.passwords.get(user.toString()));
    clock.advance(31);
    passwords.markAbandonedUnknown();
    UUID id = UUID.fromString(scalar("SELECT id FROM password_operation"));
    assertEquals(
        COMMITTED,
        passwords.recover(recoveryAdmin(), id, true, "ticket:SEC-100/evidence-1").state());
    assertTrue(allowed(1));
    assertFalse(allowed(0));
    assertEquals(1, directory.writes);
    assertEquals("1", scalar("SELECT count(*) FROM outbox_event"));
    assertEquals(
        "ticket:SEC-100/evidence-1",
        scalar("SELECT recovery_evidence_ref FROM password_operation"));
  }

  @Test
  void crashBeforeCommitRollsBackAllMetadataAndCrashAfterCommitIsReplaySafe() throws Exception {
    passwords =
        service(
            point -> {
              if (point == PasswordChangeService.Point.BEFORE_COMMIT) throw new Crash();
            });
    assertThrows(Crash.class, () -> change(key()));
    assertEquals("PREPARED", scalar("SELECT state FROM password_operation"));
    assertEquals("0", scalar("SELECT count(*) FROM outbox_event"));
    assertFalse(allowed(1));
    // A separate user demonstrates response loss after the durable commit.
    UUID another = seed("E009");
    String idem = key();
    passwords =
        service(
            point -> {
              if (point == PasswordChangeService.Point.AFTER_COMMIT) throw new Crash();
            });
    var actor = AuthenticatedActor.user(another, 0, clock.instant());
    assertThrows(
        Crash.class,
        () ->
            passwords.change(actor, idem, OLD.toCharArray(), NEW.toCharArray(), NEW.toCharArray()));
    assertEquals(
        COMMITTED,
        passwords
            .change(actor, idem, OLD.toCharArray(), NEW.toCharArray(), NEW.toCharArray())
            .state());
    assertEquals(2, directory.writes);
  }

  @Test
  void concurrentDisableDuringDirectoryWriteCannotBeUndoneBySuccessfulFinalization()
      throws Exception {
    directory.beforeWrite =
        () -> {
          try {
            new IdentityLifecycleService(db, directory).disable(user, UUID.randomUUID());
          } catch (SQLException e) {
            throw new RuntimeException(e);
          }
        };
    assertEquals(COMMITTED, change(key()).state());
    assertFalse(allowed(0));
    assertFalse(allowed(1));
    assertFalse(allowed(2));
    assertEquals("DISABLED", scalar("SELECT status FROM iam_user WHERE id='" + user + "'"));
    assertEquals("BLOCKED", scalar("SELECT password_gate FROM iam_user WHERE id='" + user + "'"));
  }

  @Test
  void rejectsStaleFutureAndNonRecentAuthenticationAndEnforcesRequestThrottle() {
    assertEquals(
        STALE_SESSION,
        assertThrows(
                PasswordFailure.class,
                () ->
                    passwords.change(
                        actor(9), key(), OLD.toCharArray(), NEW.toCharArray(), NEW.toCharArray()))
            .code());
    var stale = AuthenticatedActor.user(user, 0, clock.instant().minusSeconds(301));
    assertEquals(
        RECENT_AUTH_REQUIRED,
        assertThrows(
                PasswordFailure.class,
                () ->
                    passwords.change(
                        stale, key(), OLD.toCharArray(), NEW.toCharArray(), NEW.toCharArray()))
            .code());
    assertThrows(
        PasswordFailure.class,
        () ->
            passwords.change(
                actor(0), key(), "bad".toCharArray(), NEW.toCharArray(), NEW.toCharArray()));
    assertEquals(RATE_LIMITED, assertThrows(PasswordFailure.class, () -> change(key())).code());
  }

  @Test
  void epochIsMonotonicIndependentOfSecondResolution() throws Exception {
    change(key());
    clock.advance(61);
    assertEquals(
        2,
        passwords
            .change(actor(1), key(), NEW.toCharArray(), THIRD.toCharArray(), THIRD.toCharArray())
            .fencedEpoch());
    assertFalse(allowed(0));
    assertFalse(allowed(1));
    assertTrue(allowed(2));
  }

  @Test
  void recoveryNeedsSeparateActiveAdminRecentMfaEvidenceAndExpiredLease() {
    directory.mode = Mode.TIMEOUT_BEFORE;
    var op = change(key());
    assertEquals(
        RECOVERY_NOT_PERMITTED,
        assertThrows(
                PasswordFailure.class,
                () -> passwords.recover(recoveryAdmin(), op.id(), false, "ticket:SEC-1/evidence"))
            .code());
    clock.advance(31);
    assertEquals(
        RECOVERY_NOT_PERMITTED,
        assertThrows(
                PasswordFailure.class,
                () ->
                    passwords.recover(
                        AuthenticatedActor.user(admin, 0, clock.instant()),
                        op.id(),
                        false,
                        "ticket:SEC-1/evidence"))
            .code());
    assertEquals(
        RECOVERY_EVIDENCE_REQUIRED,
        assertThrows(
                PasswordFailure.class, () -> passwords.recover(recoveryAdmin(), op.id(), false, ""))
            .code());
    assertEquals(
        REJECTED,
        passwords.recover(recoveryAdmin(), op.id(), false, "ticket:SEC-1/evidence").state());
    assertEquals(
        REJECTED,
        passwords.recover(recoveryAdmin(), op.id(), false, "ticket:SEC-1/evidence").state());
    assertEquals(
        RECOVERY_NOT_PERMITTED,
        assertThrows(
                PasswordFailure.class,
                () -> passwords.recover(recoveryAdmin(), op.id(), true, "ticket:SEC-1/evidence"))
            .code());
  }

  @Test
  void statusDoesNotAllowCrossUserDisclosure() {
    var op = change(key());
    assertEquals(
        NOT_FOUND, assertThrows(PasswordFailure.class, () -> passwords.get(op.id(), admin)).code());
  }

  private ResetGrantService.Grant grant(UUID id) throws Exception {
    UUID verification = UUID.randomUUID();
    try (Connection c = db.open()) {
      sql(
          c,
          "INSERT INTO identity_verification(id,user_id,auth_epoch,factor,verified_at,expires_at) VALUES (?,?,0,'EMAIL_LINK',?,?)",
          verification,
          id,
          Timestamp.from(clock.instant()),
          Timestamp.from(clock.instant().plusSeconds(300)));
    }
    return new ResetGrantService(db, clock).issueFromVerification(verification);
  }

  @Test
  void oneTimeResetGrantIsHashedEpochBoundAndReplayDoesNotRewritePassword() throws Exception {
    var grant = grant(user);
    assertFalse(grant.toString().contains(grant.token()));
    assertNotEquals(grant.token(), scalar("SELECT token_digest FROM password_reset_grant"));
    passwords =
        new PasswordChangeService(db, directory, PasswordPolicy.defaults(), clock, true, true);
    String key = key();
    var op = passwords.reset(grant.token(), key, NEW.toCharArray(), NEW.toCharArray());
    assertEquals(COMMITTED, op.state());
    assertEquals(
        op.id(), passwords.reset(grant.token(), key, NEW.toCharArray(), NEW.toCharArray()).id());
    assertEquals(1, directory.writes);
    assertEquals(
        INVALID_REQUEST,
        assertThrows(
                PasswordFailure.class,
                () -> passwords.reset(grant.token(), key(), NEW.toCharArray(), NEW.toCharArray()))
            .code());
    assertEquals("RESET", scalar("SELECT operation_type FROM password_operation"));
  }

  @Test
  void expiredOrOldEpochResetGrantCannotBeConsumed() throws Exception {
    var expired = grant(user);
    clock.advance(601);
    passwords =
        new PasswordChangeService(db, directory, PasswordPolicy.defaults(), clock, true, true);
    assertEquals(
        INVALID_REQUEST,
        assertThrows(
                PasswordFailure.class,
                () -> passwords.reset(expired.token(), key(), NEW.toCharArray(), NEW.toCharArray()))
            .code());
    var stale = grant(admin);
    try (Connection c = db.open()) {
      sql(c, "UPDATE iam_user SET auth_epoch=1 WHERE id=?", admin);
    }
    assertEquals(
        STALE_SESSION,
        assertThrows(
                PasswordFailure.class,
                () -> passwords.reset(stale.token(), key(), NEW.toCharArray(), NEW.toCharArray()))
            .code());
  }

  @Test
  void adminResetRequiresAuthorityAndRecentMfaAndForcesNextPasswordChange() throws Exception {
    passwords =
        new PasswordChangeService(db, directory, PasswordPolicy.defaults(), clock, true, true);
    assertEquals(
        RECOVERY_NOT_PERMITTED,
        assertThrows(
                PasswordFailure.class,
                () ->
                    passwords.adminReset(
                        recoveryAdmin(), user, key(), NEW.toCharArray(), NEW.toCharArray()))
            .code());
    var privileged =
        new AuthenticatedActor(
            admin, 0, clock.instant(), Set.of("PASSWORD_RESET"), clock.instant());
    String key = key();
    var op = passwords.adminReset(privileged, user, key, NEW.toCharArray(), NEW.toCharArray());
    assertEquals(COMMITTED, op.state());
    assertEquals("t", scalar("SELECT must_change_password FROM iam_user WHERE id='" + user + "'"));
    assertEquals(
        op.id(),
        passwords.adminReset(privileged, user, key, NEW.toCharArray(), NEW.toCharArray()).id());
    assertEquals(1, directory.writes);
    passwords.change(actor(1), key(), NEW.toCharArray(), THIRD.toCharArray(), THIRD.toCharArray());
    assertEquals("f", scalar("SELECT must_change_password FROM iam_user WHERE id='" + user + "'"));
  }

  @Test
  void concurrentRequestsNeverPerformTwoDirectoryWrites() throws Exception {
    ExecutorService pool = Executors.newFixedThreadPool(2);
    try {
      Callable<Object> task =
          () -> {
            try {
              return change(key());
            } catch (PasswordFailure e) {
              return e.code();
            }
          };
      var a = pool.submit(task);
      var b = pool.submit(task);
      var results = List.of(a.get(15, TimeUnit.SECONDS), b.get(15, TimeUnit.SECONDS));
      assertEquals(1, results.stream().filter(r -> r instanceof PasswordOperation).count());
      assertEquals(1, directory.writes);
    } finally {
      pool.shutdownNow();
    }
  }

  private static void sql(Connection c, String query, Object... args) throws SQLException {
    try (PreparedStatement s = c.prepareStatement(query)) {
      for (int i = 0; i < args.length; i++) s.setObject(i + 1, args[i]);
      s.executeUpdate();
    }
  }

  private static final class Crash extends Error {}

  private enum Mode {
    NORMAL,
    REJECT,
    TIMEOUT_BEFORE,
    TIMEOUT_AFTER
  }

  private static final class FakeDirectory implements DirectoryGateway {
    final Map<String, String> passwords = new ConcurrentHashMap<>();
    volatile Mode mode = Mode.NORMAL;
    volatile int writes;
    Runnable beforeWrite;

    @Override
    public DirectoryConfig.Type type() {
      return DirectoryConfig.Type.OPENLDAP;
    }

    @Override
    public Optional<DirectoryUser> findByStableId(String id) {
      return Optional.of(new DirectoryUser(id, "E001", "uid=one,dc=example", false));
    }

    @Override
    public boolean verifyCredential(String id, char[] password) {
      return Objects.equals(passwords.get(id), new String(password));
    }

    @Override
    public Optional<String> passwordVersion(String id) {
      return Optional.of("version-" + writes);
    }

    @Override
    public void changePassword(String id, char[] old, char[] next) {
      if (!verifyCredential(id, old)) throw new DirectoryFailure(DirectoryFailure.Kind.REJECTED);
      write(id, next);
    }

    @Override
    public void disableUser(String id) {}

    @Override
    public boolean supportsPasswordReset() {
      return true;
    }

    @Override
    public void resetPassword(String id, char[] next) {
      write(id, next);
    }

    private void write(String id, char[] next) {
      writes++;
      if (beforeWrite != null) beforeWrite.run();
      if (mode == Mode.REJECT) throw new DirectoryFailure(DirectoryFailure.Kind.REJECTED);
      if (mode == Mode.TIMEOUT_BEFORE)
        throw new DirectoryFailure(DirectoryFailure.Kind.UNKNOWN_WRITE);
      passwords.put(id, new String(next));
      if (mode == Mode.TIMEOUT_AFTER)
        throw new DirectoryFailure(DirectoryFailure.Kind.UNKNOWN_WRITE);
    }
  }

  private static final class MutableClock extends Clock {
    private Instant instant;

    MutableClock(Instant instant) {
      this.instant = instant;
    }

    void advance(long seconds) {
      instant = instant.plusSeconds(seconds);
    }

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return instant;
    }
  }
}
