package com.unipass.identity;

import com.unipass.directory.DirectoryConfig.Type;
import com.unipass.directory.DirectoryGateway;
import java.io.*;
import java.security.*;
import java.sql.*;
import java.util.*;

/** Preview is durable and immutable. Apply is serialized with lifecycle changes in PostgreSQL. */
public final class IdentityImportService {
  private final Database db;
  private final DirectoryGateway directory;
  private final Type type;

  public IdentityImportService(Database db, DirectoryGateway directory, Type type) {
    if (directory != null && directory.type() != type)
      throw new IllegalArgumentException("Directory type mismatch");
    this.db = db;
    this.directory = directory;
    this.type = type;
  }

  public record RowResult(int rowNo, String action, String errorCode) {}

  public record Preview(UUID batchId, String state, List<RowResult> rows) {
    public long validCount() {
      return rows.stream().filter(r -> r.errorCode() == null).count();
    }
  }

  public record ApplyResult(UUID batchId, int appliedRows, boolean alreadyApplied) {}

  private record Existing(
      UUID id,
      String employee,
      UUID directoryId,
      String source,
      long version,
      String status,
      String type) {}

  private record Resolved(
      HrRow row, UUID directoryId, String dn, Long observedVersion, String error) {}

  public Preview preview(String source, String expectedCursor, String nextCursor, List<HrRow> rows)
      throws SQLException {
    if (source == null
        || !source.matches("[a-zA-Z0-9_-]{1,100}")
        || expectedCursor == null
        || nextCursor == null
        || nextCursor.isBlank()
        || nextCursor.length() > 500
        || expectedCursor.length() > 500
        || expectedCursor.equals(nextCursor)
        || rows.isEmpty()
        || rows.size() > 50000) throw new IllegalArgumentException("Invalid import envelope");
    String checksum = checksum(source, expectedCursor, nextCursor, rows, type);
    try (Connection c = db.open()) {
      UUID found = batchByChecksum(c, source, checksum);
      if (found != null) return report(c, found);
    }
    Map<String, Integer> employees = new HashMap<>(), ids = new HashMap<>();
    for (HrRow row : rows) {
      employees.merge(String.valueOf(row.employeeNo()), 1, Integer::sum);
      ids.merge(normalizeId(row.directoryId()), 1, Integer::sum);
    }
    // Resolve directory snapshots before opening the database write transaction.
    List<Resolved> snapshots = new ArrayList<>();
    for (HrRow row : rows) {
      String error = validate(row);
      UUID id = error == null ? UUID.fromString(row.directoryId()) : null;
      if (error == null
          && (employees.get(row.employeeNo()) > 1 || ids.get(normalizeId(row.directoryId())) > 1))
        error = "DUPLICATE_INPUT";
      String dn = null;
      if (error == null) {
        var user = directory.findByStableId(id.toString()).orElse(null);
        if (user == null) error = "DIRECTORY_NOT_FOUND";
        else if (!row.employeeNo().equals(user.employeeNo())
            || !id.toString().equals(user.stableId())) error = "DIRECTORY_IDENTITY_MISMATCH";
        else if (user.disabled() && row.status().equals("ACTIVE")) error = "DIRECTORY_DISABLED";
        else dn = user.dn();
      }
      snapshots.add(new Resolved(row, id, dn, null, error));
    }
    try (Connection c = db.open()) {
      c.setAutoCommit(false);
      try {
        lock(c);
        execute(
            c,
            "INSERT INTO import_source(source_id,cursor_value) VALUES (?,?) ON CONFLICT DO NOTHING",
            source,
            "");
        UUID found = batchByChecksum(c, source, checksum);
        if (found != null) {
          Preview result = report(c, found);
          c.commit();
          return result;
        }
        if (!cursor(c, source).equals(expectedCursor))
          throw new IllegalStateException("Source cursor conflict");
        List<Resolved> resolved = new ArrayList<>();
        for (Resolved snapshot : snapshots) {
          HrRow row = snapshot.row();
          String error = snapshot.error();
          UUID id = snapshot.directoryId();
          Long observed = null;
          if (error == null) {
            Existing existing = existingByDirectory(c, id);
            error = conflict(c, row, id, source, existing);
            observed = existing == null ? null : existing.version();
          }
          resolved.add(new Resolved(row, id, snapshot.dn(), observed, error));
        }
        UUID batch = UUID.randomUUID();
        execute(
            c,
            "INSERT INTO import_batch(id,source_id,expected_cursor,next_cursor,checksum,directory_type,status) VALUES (?,?,?,?,?,?,'PREVIEW')",
            batch,
            source,
            expectedCursor,
            nextCursor,
            checksum,
            type.name());
        for (int i = 0; i < resolved.size(); i++) {
          Resolved r = resolved.get(i);
          HrRow h = r.row();
          String action =
              r.error() != null
                  ? "REJECTED"
                  : h.status().equals("DISABLED")
                      ? "DISABLE"
                      : r.observedVersion() == null ? "CREATE" : "UPDATE";
          execute(
              c,
              "INSERT INTO import_row(batch_id,row_no,employee_no,directory_id,ldap_dn,display_name,desired_status,source_version,observed_version,error_code,planned_action) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
              batch,
              i + 1,
              h.employeeNo(),
              r.directoryId(),
              r.dn(),
              h.displayName(),
              h.status(),
              h.sourceVersion(),
              r.observedVersion(),
              r.error(),
              action);
        }
        execute(
            c,
            "INSERT INTO identity_audit(id,batch_id,action,trace_id) VALUES (?,?,'IMPORT_PREVIEW',?)",
            UUID.randomUUID(),
            batch,
            batch);
        Preview result = report(c, batch);
        c.commit();
        return result;
      } catch (SQLException | RuntimeException e) {
        c.rollback();
        throw e;
      }
    }
  }

  public ApplyResult apply(UUID batchId) throws SQLException {
    try (Connection c = db.open()) {
      c.setAutoCommit(false);
      try {
        lock(c);
        String source, expected, next;
        try (PreparedStatement s =
            c.prepareStatement(
                "SELECT source_id,expected_cursor,next_cursor,status,directory_type FROM import_batch WHERE id=? FOR UPDATE")) {
          s.setObject(1, batchId);
          try (ResultSet r = s.executeQuery()) {
            if (!r.next()) throw new IllegalArgumentException("Unknown batch");
            if (!type.name().equals(r.getString(5)))
              throw new IllegalStateException("Directory type differs from preview");
            if (r.getString(4).equals("APPLIED")) {
              c.commit();
              return new ApplyResult(batchId, 0, true);
            }
            source = r.getString(1);
            expected = r.getString(2);
            next = r.getString(3);
          }
        }
        if (!cursor(c, source).equals(expected))
          throw new IllegalStateException("Source cursor conflict; create a new preview");
        int count = 0;
        try (PreparedStatement s =
            c.prepareStatement(
                "SELECT * FROM import_row WHERE batch_id=? AND error_code IS NULL ORDER BY row_no")) {
          s.setObject(1, batchId);
          try (ResultSet r = s.executeQuery()) {
            while (r.next()) {
              UUID dirId = r.getObject("directory_id", UUID.class);
              HrRow row =
                  new HrRow(
                      r.getString("employee_no"),
                      dirId.toString(),
                      r.getString("display_name"),
                      r.getString("desired_status"),
                      r.getLong("source_version"));
              Existing existing = existingByDirectory(c, dirId);
              Long observed = r.getObject("observed_version", Long.class);
              if (!Objects.equals(observed, existing == null ? null : existing.version())
                  || conflict(c, row, dirId, source, existing) != null)
                throw new IllegalStateException("Preview stale at row " + r.getInt("row_no"));
              UUID userId = existing == null ? UUID.randomUUID() : existing.id();
              boolean disabled = row.status().equals("DISABLED");
              if (existing == null) {
                execute(
                    c,
                    "INSERT INTO iam_user(id,employee_no,directory_id,directory_type,ldap_dn,display_name,status,source_id,source_version,auth_epoch,password_gate) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    userId,
                    row.employeeNo(),
                    dirId,
                    type.name(),
                    r.getString("ldap_dn"),
                    row.displayName(),
                    row.status(),
                    source,
                    row.sourceVersion(),
                    disabled ? 1L : 0L,
                    disabled ? "BLOCKED" : "OPEN");
              } else {
                // Do not clear a password gate held by another operation.
                execute(
                    c,
                    "UPDATE iam_user SET ldap_dn=?,display_name=?,source_version=?,directory_etl_at=now(),status=?,auth_epoch=auth_epoch+?,password_gate=CASE WHEN ? THEN 'BLOCKED' ELSE password_gate END WHERE id=?",
                    r.getString("ldap_dn"),
                    row.displayName(),
                    row.sourceVersion(),
                    row.status(),
                    disabled && !existing.status().equals("DISABLED") ? 1L : 0L,
                    disabled,
                    userId);
              }
              if (disabled) enqueueDisable(c, userId);
              execute(
                  c,
                  "INSERT INTO identity_audit(id,user_id,batch_id,action,trace_id) VALUES (?,?,?,?,?)",
                  UUID.randomUUID(),
                  userId,
                  batchId,
                  disabled ? "USER_DISABLED" : "IDENTITY_IMPORTED",
                  batchId);
              count++;
            }
          }
        }
        if (count == 0)
          throw new IllegalStateException("Batch has no valid rows; cursor was not advanced");
        execute(c, "UPDATE import_source SET cursor_value=? WHERE source_id=?", next, source);
        execute(c, "UPDATE import_batch SET status='APPLIED',applied_at=now() WHERE id=?", batchId);
        c.commit();
        return new ApplyResult(batchId, count, false);
      } catch (SQLException | RuntimeException e) {
        c.rollback();
        throw e;
      }
    }
  }

  public Preview report(UUID batch) throws SQLException {
    try (Connection c = db.open()) {
      return report(c, batch);
    }
  }

  private static Preview report(Connection c, UUID batch) throws SQLException {
    String state;
    try (PreparedStatement s = c.prepareStatement("SELECT status FROM import_batch WHERE id=?")) {
      s.setObject(1, batch);
      try (ResultSet r = s.executeQuery()) {
        if (!r.next()) throw new IllegalArgumentException("Unknown batch");
        state = r.getString(1);
      }
    }
    List<RowResult> rows = new ArrayList<>();
    try (PreparedStatement s =
        c.prepareStatement(
            "SELECT row_no,planned_action,error_code FROM import_row WHERE batch_id=? ORDER BY row_no")) {
      s.setObject(1, batch);
      try (ResultSet r = s.executeQuery()) {
        while (r.next()) rows.add(new RowResult(r.getInt(1), r.getString(2), r.getString(3)));
      }
    }
    return new Preview(batch, state, List.copyOf(rows));
  }

  private static String validate(HrRow r) {
    if (r.employeeNo() == null || !r.employeeNo().matches("[a-zA-Z0-9_.-]{1,100}"))
      return "INVALID_EMPLOYEE_NO";
    try {
      if (!UUID.fromString(r.directoryId()).toString().equalsIgnoreCase(r.directoryId()))
        return "INVALID_DIRECTORY_ID";
    } catch (RuntimeException e) {
      return "INVALID_DIRECTORY_ID";
    }
    if (r.displayName() == null || r.displayName().isBlank() || r.displayName().length() > 200)
      return "INVALID_DISPLAY_NAME";
    if (!Set.of("ACTIVE", "DISABLED").contains(String.valueOf(r.status()))) return "INVALID_STATUS";
    if (r.sourceVersion() < 0) return "INVALID_SOURCE_VERSION";
    return null;
  }

  private static String normalizeId(String value) {
    try {
      return UUID.fromString(value).toString();
    } catch (RuntimeException e) {
      return String.valueOf(value);
    }
  }

  private String conflict(Connection c, HrRow row, UUID id, String source, Existing current)
      throws SQLException {
    try (PreparedStatement s =
        c.prepareStatement("SELECT directory_id FROM iam_user WHERE employee_no=?")) {
      s.setString(1, row.employeeNo());
      try (ResultSet r = s.executeQuery()) {
        if (r.next() && !id.equals(r.getObject(1, UUID.class))) return "EMPLOYEE_ALREADY_BOUND";
      }
    }
    if (current == null) return null;
    if (!current.type().equals(type.name())) return "DIRECTORY_TYPE_CONFLICT";
    if (!current.source().equals(source)) return "SOURCE_OWNERSHIP_CONFLICT";
    if (!current.employee().equals(row.employeeNo())) return "EMPLOYEE_RENAME_REQUIRES_REVIEW";
    if (row.sourceVersion() <= current.version()) return "STALE_SOURCE_VERSION";
    if (current.status().equals("DISABLED") && row.status().equals("ACTIVE"))
      return "REACTIVATION_REQUIRES_REVIEW";
    return null;
  }

  private static Existing existingByDirectory(Connection c, UUID id) throws SQLException {
    try (PreparedStatement s =
        c.prepareStatement(
            "SELECT id,employee_no,source_id,source_version,status,directory_type FROM iam_user WHERE directory_id=?")) {
      s.setObject(1, id);
      try (ResultSet r = s.executeQuery()) {
        return r.next()
            ? new Existing(
                r.getObject(1, UUID.class),
                r.getString(2),
                id,
                r.getString(3),
                r.getLong(4),
                r.getString(5),
                r.getString(6))
            : null;
      }
    }
  }

  private static UUID batchByChecksum(Connection c, String source, String checksum)
      throws SQLException {
    try (PreparedStatement s =
        c.prepareStatement("SELECT id FROM import_batch WHERE source_id=? AND checksum=?")) {
      s.setString(1, source);
      s.setString(2, checksum);
      try (ResultSet r = s.executeQuery()) {
        return r.next() ? r.getObject(1, UUID.class) : null;
      }
    }
  }

  private static String cursor(Connection c, String source) throws SQLException {
    try (PreparedStatement s =
        c.prepareStatement("SELECT cursor_value FROM import_source WHERE source_id=? FOR UPDATE")) {
      s.setString(1, source);
      try (ResultSet r = s.executeQuery()) {
        if (!r.next()) throw new IllegalStateException("Unknown source");
        return r.getString(1);
      }
    }
  }

  static void enqueueDisable(Connection c, UUID userId) throws SQLException {
    execute(
        c,
        "INSERT INTO directory_disable_task(user_id,state) VALUES (?,'PENDING') ON CONFLICT(user_id) DO UPDATE SET state='PENDING',lease_token=NULL,next_attempt_at=now()",
        userId);
  }

  static void lock(Connection c) throws SQLException {
    // Shared by import and lifecycle writes; ordering prevents identity races across HR sources.
    execute(c, "SET LOCAL lock_timeout = '3s'");
    execute(c, "SET LOCAL statement_timeout = '10s'");
    try (Statement s = c.createStatement()) {
      s.execute("SELECT pg_advisory_xact_lock(78310401)");
    }
  }

  static void execute(Connection c, String sql, Object... args) throws SQLException {
    try (PreparedStatement s = c.prepareStatement(sql)) {
      for (int i = 0; i < args.length; i++) s.setObject(i + 1, args[i]);
      s.executeUpdate();
    }
  }

  private static String checksum(
      String source, String expected, String next, List<HrRow> rows, Type type) {
    try {
      ByteArrayOutputStream bytes = new ByteArrayOutputStream();
      DataOutputStream out = new DataOutputStream(bytes);
      out.writeUTF(type.name());
      out.writeUTF(source);
      out.writeUTF(expected);
      out.writeUTF(next);
      for (HrRow r : rows) {
        for (String value :
            Arrays.asList(r.employeeNo(), r.directoryId(), r.displayName(), r.status())) {
          out.writeBoolean(value != null);
          if (value != null) {
            byte[] b = value.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            out.writeInt(b.length);
            out.write(b);
          }
        }
        out.writeLong(r.sourceVersion());
      }
      return HexFormat.of()
          .formatHex(MessageDigest.getInstance("SHA-256").digest(bytes.toByteArray()));
    } catch (IOException | NoSuchAlgorithmException e) {
      throw new IllegalStateException("Checksum unavailable");
    }
  }
}
