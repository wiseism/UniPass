package com.unipass.server;

import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;
import java.sql.Timestamp;
import java.time.Clock;
import java.util.*;

/**
 * Role management for the T8 console. Only the allowlisted roles are
 * assignable, changes and their audit land in the same transaction, the same
 * idempotency key must replay to the same outcome, and an operator cannot
 * remove their own last SYSTEM_ADMIN role.
 */
@Service
public final class AdminConsoleService {
    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final AccountState accounts;
    private final AdminAuditService audit;
    private final MfaService mfa;
    private final Clock clock;

    public AdminConsoleService(JdbcTemplate jdbc, TransactionTemplate tx, AccountState accounts, AdminAuditService audit, MfaService mfa, Clock clock) {
        this.jdbc = jdbc; this.tx = tx; this.accounts = accounts; this.audit = audit; this.mfa = mfa; this.clock = clock;
    }

    public void requireConsole(IdentityPrincipal principal) {
        if (!accounts.roles(principal.getUserId()).contains("ROLE_SYSTEM_ADMIN"))
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Console authority required");
    }

    public List<String> roles(UUID target) {
        return jdbc.queryForList("SELECT role FROM iam_user_role WHERE user_id=? ORDER BY role", String.class, target);
    }

    public void change(IdentityPrincipal principal, UUID target, String action, String role, String reason, String key) {
        requireConsole(principal);
        if (!principal.hasRecentPassword(clock.instant()) || !mfa.recent(principal))
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Administrative authority and recent password/MFA required");
        if (!Set.of("GRANT", "REVOKE").contains(action)) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Role action required");
        if (!ASSIGNABLE.contains(role)) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Role not assignable");
        if (reason == null || reason.isBlank() || reason.length() > 500 || reason.codePoints().anyMatch(Character::isISOControl))
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Reason required");
        tx.executeWithoutResult(status -> {
            accounts.lockAndRequire(principal);
            if (!Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS(SELECT 1 FROM iam_user WHERE id=?)", Boolean.class, target)))
                throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Identity unavailable");
            UUID actionId = UUID.randomUUID();
            boolean fresh = jdbc.update("""
                    INSERT INTO admin_console_action(id,actor_id,target_id,action,detail,idempotency_key,reason,created_at)
                    VALUES (?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING
                    """, actionId, principal.getUserId(), target, action, role, key, reason, Timestamp.from(clock.instant())) == 1;
            if (fresh) {
                if (action.equals("GRANT")) {
                    jdbc.update("INSERT INTO iam_user_role(user_id,role) VALUES (?,?) ON CONFLICT DO NOTHING", target, role);
                } else {
                    jdbc.update("DELETE FROM iam_user_role WHERE user_id=? AND role=?", target, role);
                    if (role.equals("ROLE_SYSTEM_ADMIN") && target.equals(principal.getUserId())
                            && !Boolean.TRUE.equals(jdbc.queryForObject(
                                    "SELECT EXISTS(SELECT 1 FROM iam_user_role WHERE role='ROLE_SYSTEM_ADMIN' AND user_id<>?)", Boolean.class, target)))
                        throw new ResponseStatusException(HttpStatus.CONFLICT, "Last console administrator");
                }
                audit.record(action.equals("GRANT") ? "ROLE_GRANTED" : "ROLE_REVOKED", "SUCCESS", principal.getUserId(), target,
                        principal.getLoginId(), null, actionId, Map.of("role", role, "reason", reason.trim()));
            } else {
                // A key reuse with identical context stays idempotent without a second audit row;
                // different context is rejected so a replay can never silently change the outcome.
                String stored = jdbc.query("""
                        SELECT reason FROM admin_console_action
                        WHERE actor_id=? AND target_id=? AND action=? AND detail=? AND idempotency_key=?
                        """, (org.springframework.jdbc.core.ResultSetExtractor<String>) r -> {
                    if (!r.next()) throw new ResponseStatusException(HttpStatus.CONFLICT, "Idempotency context changed");
                    return r.getString(1);
                }, principal.getUserId(), target, action, role, key);
                if (!reason.equals(stored)) throw new ResponseStatusException(HttpStatus.CONFLICT, "Idempotency context changed");
            }
        });
    }

    static final Set<String> ASSIGNABLE = Set.of("ROLE_SYSTEM_ADMIN", "ROLE_ADMIN_PASSWORD_RESET",
            "ROLE_ADMIN_PASSWORD_RECOVERY", "ROLE_ADMIN_MFA_RECOVERY");
}
