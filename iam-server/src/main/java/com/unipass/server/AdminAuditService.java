package com.unipass.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;
import org.springframework.jdbc.core.JdbcTemplate;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.*;

/**
 * Console audit recorder and reader. Writers must call this inside their own
 * transaction so an audit failure blocks the privileged change (T8: audit
 * failures do not allow the change to proceed silently).
 */
@Service
public final class AdminAuditService {
    /** Detail keys never leave this allowlist; unknown keys are rejected, not silently stored. */
    static final Set<String> DETAIL_KEYS = Set.of("role", "reason", "login", "target_action", "replay", "operator");
    private static final int DETAIL_MAX = 500;
    private final JdbcTemplate jdbc;
    private final Clock clock;
    private final ObjectMapper mapper = new ObjectMapper();
    public AdminAuditService(JdbcTemplate jdbc, Clock clock) { this.jdbc = jdbc; this.clock = clock; }

    public enum Result { SUCCESS, REJECTED, UNAVAILABLE }

    /** Throws IllegalArgumentException on contract violations (detail contract errors are operator mistakes, not user errors). */
    public UUID record(String action, String result, UUID actor, UUID subject, UUID login, String clientId,
            UUID operationId, Map<String, String> detail) {
        Objects.requireNonNull(action);
        if (!action.matches("[A-Z_]{1,64}")) throw new IllegalArgumentException("action");
        if (result == null || !Set.of("SUCCESS", "REJECTED", "UNAVAILABLE").contains(result)) throw new IllegalArgumentException("result");
        Map<String, String> safe = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : Objects.requireNonNull(detail).entrySet()) {
            if (!DETAIL_KEYS.contains(entry.getKey())) throw new IllegalArgumentException("detail key");
            String value = entry.getValue() == null ? "" : entry.getValue();
            if (value.length() > DETAIL_MAX || value.codePoints().anyMatch(Character::isISOControl))
                throw new IllegalArgumentException("detail value");
            safe.put(entry.getKey(), value);
        }
        UUID id = UUID.randomUUID();
        // user_id stores the audit subject; the acting operator travels inside the
        // allowlisted detail object so console writes stay attributable (T8 actor field).
        safe.put("operator", Objects.requireNonNull(actor).toString());
        jdbc.update("INSERT INTO auth_audit(id,user_id,action,trace_id,login_id,result,client_id,source_ip,operation_id,detail,created_at) VALUES (?,?,?,?,?,?,?,?,?,?::jsonb,?)",
                id, subject, action, UUID.randomUUID(), login, result, trimmed(clientId, 100), null, operationId,
                json(safe), Timestamp.from(clock.instant()));
        return id;
    }

    public record Entry(UUID id, Instant createdAt, UUID subject, String action, String result, String clientId,
            String operationId, Map<String, Object> detail) { }

    public record Page(List<Entry> entries, String nextCursor) { }

    /** Newest first, stable ties broken by id, opaque validated cursor. */
    public Page page(String cursor, int limit) {
        DecodedCursor decoded = DecodedCursor.parse(cursor);
        List<Entry> rows = jdbc.query(
                "SELECT id,created_at,user_id,action,result,client_id,operation_id,detail FROM auth_audit "
                        + "WHERE (?::timestamptz IS NULL OR (created_at,id) < (?::timestamptz,?::uuid)) "
                        + "ORDER BY created_at DESC, id DESC LIMIT ?",
                (r, n) -> new Entry(r.getObject("id", UUID.class), r.getTimestamp("created_at").toInstant(),
                        r.getObject("user_id", UUID.class), r.getString("action"), r.getString("result"),
                        r.getString("client_id"), r.getString("operation_id"),
                        readDetail(r.getString("detail"))),
                decoded.createdAt, decoded.createdAt, decoded.id, limit);
        if (rows.size() == limit && !rows.isEmpty()) {
            Entry last = rows.get(rows.size() - 1);
            return new Page(rows, DecodedCursor.encode(new DecodedCursor(last.createdAt().toString(), last.id().toString())));
        }
        return new Page(rows, null);
    }

    /** Export is a separate permissionless-by-role read with a hard row cap and CSV formula-injection defense. */
    public List<String> export(int cap) {
        List<String> lines = new ArrayList<>();
        lines.add("created_at,user_id,action,result,client_id,operation_id,trace_id");
        org.springframework.jdbc.core.RowCallbackHandler writer =
                r -> lines.add(String.join(",",
                        r.getString("created_at").replace(",", " "),
                        String.valueOf(r.getObject("user_id", UUID.class)),
                        cell(r.getString("action")), cell(r.getString("result")), cell(r.getString("client_id")),
                        cell(r.getString("operation_id")), cell(r.getString("trace_id"))));
        jdbc.query("SELECT id,created_at,user_id,action,result,client_id,operation_id,trace_id FROM (SELECT id,created_at,user_id,action,result,client_id,operation_id,trace_id FROM auth_audit ORDER BY created_at DESC, id DESC LIMIT ?) e ORDER BY created_at, id",
                writer, cap);
        return lines;
    }

    private static String cell(String value) {
        if (value == null) return "";
        if (!value.matches("^[A-Za-z0-9@./_ -]*$")) throw new IllegalStateException("Unsafe audit cell");
        return value.replace(" ", "");
    }

    private Map<String, Object> readDetail(String raw) {
        try { return mapper.readValue(raw == null ? "{}" : raw, Map.class); }
        catch (java.io.IOException e) { throw new IllegalStateException("Stored detail is not valid JSON"); }
    }

    private String json(Map<String, String> detail) {
        try { return mapper.writeValueAsString(detail); }
        catch (java.io.IOException e) { throw new IllegalStateException("Detail serialization failed"); }
    }

    private static String trimmed(String value, int max) {
        if (value == null) return null;
        if (value.length() > max) throw new IllegalArgumentException("client id");
        return value;
    }

    record DecodedCursor(String createdAt, String id) {
        static DecodedCursor parse(String raw) {
            if (raw == null || raw.isBlank()) return new DecodedCursor(null, null);
            if (!raw.matches("[A-Za-z0-9_-]{16,512}")) throw new IllegalArgumentException("cursor");
            try {
                String[] parts = new String(Base64.getUrlDecoder().decode(raw), StandardCharsets.UTF_8).split("\\|", -1);
                if (parts.length != 2) throw new IllegalArgumentException("cursor");
                Instant.parse(parts[0]); UUID.fromString(parts[1]);
                return new DecodedCursor(parts[0], parts[1]);
            } catch (IllegalArgumentException e) { throw new IllegalArgumentException("cursor"); }
        }
        static String encode(DecodedCursor cursor) {
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString((cursor.createdAt() + "|" + cursor.id()).getBytes(StandardCharsets.UTF_8));
        }
    }
}
