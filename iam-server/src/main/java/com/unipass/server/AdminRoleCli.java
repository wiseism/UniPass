package com.unipass.server;

import com.unipass.identity.Database;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.Set;
import java.util.UUID;

/**
 * Offline operator tool that bootstraps console roles by employee number.
 * No HTTP management endpoint exists for first-time role provisioning.
 */
public final class AdminRoleCli {
    private AdminRoleCli() { }

    public static void main(String[] args) {
        try {
            Database db = new Database(env("UNIPASS_DB_URL"), env("UNIPASS_DB_USER"), env("UNIPASS_DB_PASSWORD"));
            if (args.length == 1 && args[0].equals("migrate")) { db.migrate(); return; }
            if (args.length != 3 || !Set.of("grant", "revoke").contains(args[0]))
                throw new IllegalArgumentException("migrate | grant|revoke <employee_no> <ROLE_...>");
            String verb = args[0];
            String role = args[2];
            if (!AdminConsoleService.ASSIGNABLE.contains(role)) throw new IllegalArgumentException("Role not assignable");
            var jdbc = new JdbcTemplate(new org.springframework.jdbc.datasource.AbstractDataSource() {
                @Override public java.sql.Connection getConnection() throws java.sql.SQLException { return db.open(); }
                @Override public java.sql.Connection getConnection(String u, String p) throws java.sql.SQLException { throw new UnsupportedOperationException(); }
            });
            var tx = new TransactionTemplate(new DataSourceTransactionManager(jdbc.getDataSource()));
            String employee = args[1];
            tx.executeWithoutResult(status -> {
                var ids = jdbc.queryForList("SELECT id FROM iam_user WHERE employee_no=?", UUID.class, employee);
                if (ids.size() != 1) throw new IllegalStateException("Identity not unique");
                UUID id = ids.get(0);
                if (verb.equals("grant")) {
                    jdbc.update("INSERT INTO iam_user_role(user_id,role) VALUES (?,?) ON CONFLICT DO NOTHING", id, role);
                } else {
                    jdbc.update("DELETE FROM iam_user_role WHERE user_id=? AND role=?", id, role);
                }
                String action = verb.equals("grant") ? "ROLE_GRANTED" : "ROLE_REVOKED";
                jdbc.update("""
                        INSERT INTO auth_audit(id,user_id,action,trace_id,detail,created_at)
                        VALUES (?,?,?,?,?::jsonb,now())
                        """, UUID.randomUUID(), id, action,
                        UUID.randomUUID(), "{\"operator\":\"admin-role-cli\",\"role\":\"" + role + "\"}");
            });
            System.out.println("role=" + role);
        } catch (Exception e) {
            System.err.println("Role operation failed (" + e.getClass().getSimpleName() + ").");
            System.exit(1);
        }
    }

    private static String env(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) throw new IllegalArgumentException("Missing configuration");
        return value;
    }
}
