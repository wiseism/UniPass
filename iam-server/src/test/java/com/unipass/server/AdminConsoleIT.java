package com.unipass.server;

import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;
import org.mockito.Mockito;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AdminConsoleIT {
    private static final UUID OPERATOR = new UUID(0, 1);
    private static final UUID NON_ADMIN = new UUID(0, 4);
    private static final UUID TARGET = new UUID(0, 2);
    private static final List<String> SYSTEM = List.of("ROLE_SYSTEM_ADMIN");
    private EmbeddedPostgres pg;
    private JdbcTemplate jdbc;
    private TransactionTemplate tx;
    private AdminAuditService audit;
    private AdminConsoleService console;
    private AccountState accounts;
    private final AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2026-10-23T00:00:00Z"));

    @BeforeAll void start() throws Exception {
        System.setProperty("ot.epg.working-dir",
                Files.createDirectories(Path.of("target", "admin-console", "postgres")).toAbsolutePath().toString());
        pg = EmbeddedPostgres.builder().setPort(0).setServerConfig("listen_addresses", "127.0.0.1").start();
        jdbc = new JdbcTemplate(pg.getPostgresDatabase());
        tx = new TransactionTemplate(new DataSourceTransactionManager(jdbc.getDataSource()));
        tx.setTimeout(10);
        Clock clock = new Clock() {
            @Override public ZoneId getZone() { return ZoneId.of("UTC"); }
            @Override public Clock withZone(ZoneId zone) { return this; }
            @Override public Instant instant() { return now.get(); }
        };
        audit = new AdminAuditService(jdbc, clock);
        accounts = Mockito.mock(AccountState.class);
        Mockito.when(accounts.roles(OPERATOR)).thenReturn(List.of("ROLE_SYSTEM_ADMIN"));
        Mockito.when(accounts.roles(NON_ADMIN)).thenReturn(List.of("ROLE_USER"));
        MfaService mfa = Mockito.mock(MfaService.class);
        Mockito.when(mfa.recent(Mockito.any())).thenReturn(true);
        console = new AdminConsoleService(jdbc, tx, accounts, audit, mfa, clock);
    }
    @BeforeEach void seed() {
        Flyway.configure().dataSource(jdbc.getDataSource()).cleanDisabled(false).load().clean();
        Flyway.configure().dataSource(jdbc.getDataSource()).load().migrate();
        jdbc.update("INSERT INTO import_source(source_id,cursor_value) VALUES ('admin-test','1')");
        jdbc.update("""
                INSERT INTO iam_user(id,employee_no,directory_id,directory_type,ldap_dn,display_name,status,source_id,source_version,auth_epoch)
                VALUES (?,'admin-test',?,'OPENLDAP','uid=test','Test','ACTIVE','admin-test',1,5)
                """, OPERATOR, UUID.randomUUID());
        // The operator holds their console role durably, as in production.
        jdbc.update("INSERT INTO iam_user_role(user_id,role) VALUES (?,'ROLE_SYSTEM_ADMIN') ON CONFLICT DO NOTHING", OPERATOR);
        jdbc.update("""
                INSERT INTO iam_user(id,employee_no,directory_id,directory_type,ldap_dn,display_name,status,source_id,source_version,auth_epoch)
                VALUES (?,'admin-target',?,'OPENLDAP','uid=target','Target','ACTIVE','admin-test',1,5)
                """, TARGET, UUID.randomUUID());
    }

    private IdentityPrincipal operator() {
        // Password proof is anchored to the injected test clock so the 300s "recent" window holds.
        return new IdentityPrincipal(OPERATOR, 5, now.get(), SYSTEM, now.get(),
                IdentityPrincipal.Method.PASSWORD, now.get(), UUID.randomUUID());
    }
    private int roles(UUID user, String role) {
        return jdbc.queryForObject("SELECT count(*) FROM iam_user_role WHERE user_id=? AND role=?", Integer.class, user, role);
    }
    private int actions(String action) {
        return jdbc.queryForObject("SELECT count(*) FROM admin_console_action WHERE action=?", Integer.class, action);
    }
    private List<String> auditActions() {
        return jdbc.queryForList("SELECT action FROM auth_audit ORDER BY created_at,id", String.class);
    }
    private ResponseStatusException rejected(Runnable call) {
        try { call.run(); throw new AssertionError("Expected rejection"); }
        catch (ResponseStatusException e) { return e; }
    }

    @Test void nonAdministratorIsRejectedBeforeAnyWrite() {
        IdentityPrincipal plain = new IdentityPrincipal(NON_ADMIN, 5, Instant.now(), List.of("ROLE_USER"), null,
                IdentityPrincipal.Method.PASSWORD, Instant.now(), UUID.randomUUID());
        assertEquals(403, rejected(() -> console.requireConsole(plain)).getStatusCode().value());
        assertTrue(auditActions().isEmpty());
    }

    @Test void grantWritesRoleActionAndAuditTogetherWithAllowlistedDetail() {
        console.change(operator(), TARGET, "GRANT", "ROLE_ADMIN_PASSWORD_RESET", "客服工单确认", "grant-unit-key-0001");
        assertEquals(1, roles(TARGET, "ROLE_ADMIN_PASSWORD_RESET"));
        assertEquals(1, actions("GRANT"));
        Map<String, Object> audit = jdbc.queryForMap(
                "SELECT user_id,(operation_id IS NOT NULL) AS has_op,detail->>'role' AS role,detail->>'reason' AS reason,detail->>'operator' AS actor FROM auth_audit WHERE action='ROLE_GRANTED'");
        assertEquals(TARGET, audit.get("user_id"));
        assertEquals("ROLE_ADMIN_PASSWORD_RESET", audit.get("role"));
        assertEquals("客服工单确认", audit.get("reason"));
        assertEquals(OPERATOR.toString(), audit.get("actor"));
        assertEquals(true, audit.get("has_op"));
        // Unknown detail keys never reach the store.
        assertEquals(Set.of("role", "reason", "login", "target_action", "replay", "operator"),
                new HashSet<>(List.of(AdminAuditService.DETAIL_KEYS.toArray(new String[0]))));
    }

    @Test void sameKeyWithContextReplayDoesNotDuplicateAuditOrRoles() {
        console.change(operator(), TARGET, "GRANT", "ROLE_ADMIN_PASSWORD_RESET", "同一原因重放", "replay-unit-key-01");
        console.change(operator(), TARGET, "GRANT", "ROLE_ADMIN_PASSWORD_RESET", "同一原因重放", "replay-unit-key-01");
        assertEquals(1, roles(TARGET, "ROLE_ADMIN_PASSWORD_RESET"));
        assertEquals(1, actions("GRANT"));
        assertEquals(1, auditActions().size());
    }

    @Test void sameKeyWithChangedContextIsRejected() {
        console.change(operator(), TARGET, "GRANT", "ROLE_ADMIN_PASSWORD_RESET", "第一次原因", "context-unit-key1");
        assertEquals(409, rejected(() -> console.change(operator(), TARGET, "GRANT", "ROLE_ADMIN_PASSWORD_RESET", "第二次原因", "context-unit-key1")).getStatusCode().value());
        assertEquals(1, actions("GRANT"));
        assertEquals(1, auditActions().size());
    }

    @Test void contractViolationsNeverReachTheDatabase() {
        IdentityPrincipal admin = operator();
        assertEquals(400, rejected(() -> console.change(admin, TARGET, "PROMOTE", "ROLE_SYSTEM_ADMIN", "r", "contract-key-01")).getStatusCode().value());
        assertEquals(400, rejected(() -> console.change(admin, TARGET, "GRANT", "ROLE_SUPER_ADMIN", "r", "contract-key-02")).getStatusCode().value());
        assertEquals(400, rejected(() -> console.change(admin, TARGET, "GRANT", "ROLE_SYSTEM_ADMIN", " ", "contract-key-03")).getStatusCode().value());
        assertEquals(400, rejected(() -> console.change(admin, TARGET, "GRANT", "ROLE_SYSTEM_ADMIN", "bad\nreason", "contract-key-04")).getStatusCode().value());
        assertEquals(404, rejected(() -> console.change(admin, new UUID(9, 9), "GRANT", "ROLE_SYSTEM_ADMIN", "ok reason", "contract-key-05")).getStatusCode().value());
        assertEquals(0, actions("GRANT") + actions("REVOKE"));
        assertTrue(auditActions().isEmpty());
    }

    @Test void auditFailureRollsBackRoleChangeTogether() {
        jdbc.execute("CREATE FUNCTION audit_barrier() RETURNS trigger AS $b$ BEGIN RAISE EXCEPTION 'audit blocked'; END $b$ LANGUAGE plpgsql");
        jdbc.execute("CREATE TRIGGER audit_barrier BEFORE INSERT ON auth_audit FOR EACH ROW EXECUTE FUNCTION audit_barrier()");
        assertThrows(org.springframework.dao.DataAccessException.class, () ->
                console.change(operator(), TARGET, "GRANT", "ROLE_ADMIN_PASSWORD_RESET", "审计失败也回滚", "atomic-unit-key-01"));
        assertEquals(0, roles(TARGET, "ROLE_ADMIN_PASSWORD_RESET"));
        assertEquals(0, actions("GRANT"));
    }

    @Test void operatorKeepsTheirLastConsoleRole() {
        IdentityPrincipal admin = operator();
        // No other console administrator exists yet: the removal is refused and access stays.
        assertEquals(409, rejected(() -> console.change(admin, OPERATOR, "REVOKE", "ROLE_SYSTEM_ADMIN", "自撤测试", "self-unit-key-001")).getStatusCode().value());
        assertEquals(1, roles(OPERATOR, "ROLE_SYSTEM_ADMIN"));
        // After a second console administrator exists, the operator may step down.
        console.change(admin, TARGET, "GRANT", "ROLE_SYSTEM_ADMIN", "第二名管理员交接", "self-unit-key-002");
        console.change(admin, OPERATOR, "REVOKE", "ROLE_SYSTEM_ADMIN", "主动交接退出", "self-unit-key-003");
        assertEquals(0, roles(OPERATOR, "ROLE_SYSTEM_ADMIN"));
        assertEquals(1, roles(TARGET, "ROLE_SYSTEM_ADMIN"));
    }

    @Test void auditPageIsNewestFirstWithValidatedCursorAndContract() {
        for (int i = 0; i < 7; i++) {
            audit.record("ROLE_GRANTED", "SUCCESS", OPERATOR, TARGET, UUID.randomUUID(), null, UUID.randomUUID(),
                    Map.of("role", "ROLE_ADMIN_PASSWORD_RESET"));
            now.updateAndGet(value -> value.plusSeconds(1));
        }
        AdminAuditService.Page first = audit.page(null, 3);
        assertEquals(3, first.entries().size());
        assertNotNull(first.nextCursor());
        assertTrue(first.nextCursor().matches("[A-Za-z0-9_-]{16,512}"));
        AdminAuditService.Page second = audit.page(first.nextCursor(), 3);
        assertEquals(3, second.entries().size());
        assertTrue(second.entries().get(0).createdAt().isBefore(first.entries().get(2).createdAt()));
        Set<UUID> seenIds = new HashSet<>(first.entries().stream().map(AdminAuditService.Entry::id).toList());
        second.entries().forEach(entry -> assertFalse(seenIds.contains(entry.id())));
        AdminAuditService.Page tail = audit.page(second.nextCursor(), 3);
        assertEquals(1, tail.entries().size());
        assertNull(tail.nextCursor());
        assertEquals("ROLE_ADMIN_PASSWORD_RESET", first.entries().get(0).detail().get("role"));
        assertEquals("cursor", assertThrows(IllegalArgumentException.class, () -> audit.page("aGVsbG8", 3)).getMessage());
        assertEquals("cursor", assertThrows(IllegalArgumentException.class,
                () -> audit.page(java.util.Base64.getUrlEncoder().encodeToString("bad|shape".getBytes()), 3)).getMessage());
        AdminAuditService strict = new AdminAuditService(jdbc, Clock.fixed(Instant.now(), ZoneId.of("UTC")));
        assertEquals("detail value", assertThrows(IllegalArgumentException.class, () -> strict.record(
                "ROLE_GRANTED", "SUCCESS", OPERATOR, TARGET, UUID.randomUUID(), null, UUID.randomUUID(),
                Map.of("role", "x".repeat(501)))).getMessage());
        assertEquals("detail key", assertThrows(IllegalArgumentException.class, () -> strict.record(
                "ROLE_GRANTED", "SUCCESS", OPERATOR, TARGET, UUID.randomUUID(), null, UUID.randomUUID(),
                Map.of("password", "secret"))).getMessage());
    }

    @Test void exportStaysWithinTheRowCapAndKeepsTheHeader() {
        for (int i = 0; i < 12; i++)
            audit.record("ROLE_GRANTED", "SUCCESS", OPERATOR, TARGET, UUID.randomUUID(), null, UUID.randomUUID(),
                    Map.of("role", (i % 2 == 0) ? "ROLE_ADMIN_PASSWORD_RESET" : "ROLE_ADMIN_PASSWORD_RECOVERY"));
        List<String> lines = audit.export(10);
        assertEquals(11, lines.size());
        assertEquals("created_at,user_id,action,result,client_id,operation_id,trace_id", lines.get(0));
        assertTrue(lines.get(1).contains("ROLE_GRANTED"));
    }

    @Test void replayOfPastGrantMustNotResurrectRevokedRole() {
        String key = "sequence-unit-key1";
        console.change(operator(), TARGET, "GRANT", "ROLE_ADMIN_MFA_RECOVERY", "第一次授权", key);
        console.change(operator(), TARGET, "REVOKE", "ROLE_ADMIN_MFA_RECOVERY", "随即撤销", "revoke-unit-key1");
        assertEquals(0, roles(TARGET, "ROLE_ADMIN_MFA_RECOVERY"));
        // Replaying the old grant key stays idempotent; it must not resurrect a later-revoked role.
        console.change(operator(), TARGET, "GRANT", "ROLE_ADMIN_MFA_RECOVERY", "第一次授权", key);
        assertEquals(0, roles(TARGET, "ROLE_ADMIN_MFA_RECOVERY"));
        assertEquals(2, actions("GRANT") + actions("REVOKE"));
    }

    @AfterAll void stop() throws Exception { if (pg != null) pg.close(); }
}
