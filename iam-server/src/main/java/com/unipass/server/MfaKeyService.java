package com.unipass.server;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.*;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/** PG is authoritative for the writer and retirement; environment supplies key material only. */
@Service
public final class MfaKeyService {
  private final JdbcTemplate jdbc;
  private final TransactionTemplate tx;
  private final MfaSecretCipher cipher;

  public MfaKeyService(JdbcTemplate jdbc, TransactionTemplate tx, Environment env) {
    this.jdbc = jdbc;
    this.tx = tx;
    cipher =
        new MfaSecretCipher(
            env.getProperty("unipass.mfa.key"), ring(env.getProperty("unipass.mfa.keys-json", "")));
    tx.executeWithoutResult(
        status -> {
          String active = writer(true);
          if (active == null) {
            if (jdbc.queryForObject("SELECT count(*) FROM mfa_encryption_key", Long.class) != 0)
              throw new IllegalStateException("Factor key control unavailable");
            for (String referenced : references().keySet())
              if (!cipher.ids().contains(referenced))
                throw new IllegalStateException("Existing factor key unavailable");
            active =
                cipher.ids().contains(MfaSecretCipher.LEGACY)
                    ? MfaSecretCipher.LEGACY
                    : cipher.ids().size() == 1 ? cipher.ids().iterator().next() : null;
            if (active == null)
              throw new IllegalStateException("Initial factor writer is ambiguous");
            for (String id : cipher.ids())
              jdbc.update(
                  "INSERT INTO mfa_encryption_key(key_id,fingerprint,state) VALUES (?,?,'AVAILABLE')",
                  id,
                  cipher.fingerprint(id));
            jdbc.update("UPDATE mfa_encryption_control SET active_key=? WHERE singleton", active);
            // Do not pin a misconfigured legacy fingerprint during a V8 upgrade.
            // Existing tags must authenticate before any bootstrap metadata commits.
            verifyLocked();
            audit("BOOTSTRAPPED", null, active, "startup", "initial-key-configuration", 0);
          }
          for (String id :
              jdbc.queryForList(
                  "SELECT key_id FROM mfa_encryption_key WHERE state='AVAILABLE'", String.class))
            requireKey(id);
          requireKey(active);
          for (String id : references().keySet()) requireKey(id);
        });
  }

  private static Map<String, String> ring(String json) {
    if (json == null || json.isBlank()) return Map.of();
    if (json.length() > 8192) throw new IllegalArgumentException("Factor key ring is too large");
    try {
      var node =
          new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION).readTree(json);
      if (!node.isObject()) throw new IllegalArgumentException();
      Map<String, String> result = new HashMap<>();
      var fields = node.fields();
      while (fields.hasNext()) {
        var field = fields.next();
        if (!field.getValue().isTextual()) throw new IllegalArgumentException();
        result.put(field.getKey(), field.getValue().textValue());
      }
      return result;
    } catch (Exception invalid) {
      throw new IllegalArgumentException("Invalid factor key ring");
    }
  }

  private String writer(boolean exclusive) {
    return jdbc.queryForObject(
        "SELECT active_key FROM mfa_encryption_control WHERE singleton FOR "
            + (exclusive ? "UPDATE" : "SHARE"),
        String.class);
  }

  private void requireKey(String id) {
    var rows =
        jdbc.query(
            "SELECT fingerprint,state FROM mfa_encryption_key WHERE key_id=?",
            (r, n) -> List.of(r.getString(1), r.getString(2)),
            id);
    if (rows.size() != 1
        || !"AVAILABLE".equals(rows.get(0).get(1))
        || !rows.get(0).get(0).equals(cipher.fingerprint(id)))
      throw new IllegalStateException("Factor key unavailable or retired");
  }

  public byte[] encrypt(UUID owner, byte[] raw) {
    return tx.execute(
        status -> {
          String active = writer(false);
          requireKey(active);
          return cipher.encrypt(owner, raw, active);
        });
  }

  public byte[] decrypt(UUID owner, byte[] encrypted) {
    return tx.execute(
        status -> {
          writer(false);
          requireKey(MfaSecretCipher.keyId(encrypted));
          return cipher.decrypt(owner, encrypted);
        });
  }

  public byte[] reencrypt(UUID owner, byte[] encrypted) {
    return tx.execute(
        status -> {
          String active = writer(false);
          requireKey(active);
          requireKey(MfaSecretCipher.keyId(encrypted));
          byte[] raw = cipher.decrypt(owner, encrypted);
          try {
            return cipher.encrypt(owner, raw, active);
          } finally {
            Arrays.fill(raw, (byte) 0);
          }
        });
  }

  public record KeyStatus(
      String id, String fingerprint, String state, boolean active, long references) {}

  public record Status(String active, List<KeyStatus> keys) {}

  public Status status() {
    return tx.execute(
        status -> {
          String active = writer(false);
          var refs = references();
          return new Status(
              active,
              jdbc.query(
                  "SELECT key_id,fingerprint,state FROM mfa_encryption_key ORDER BY key_id",
                  (r, n) ->
                      new KeyStatus(
                          r.getString(1),
                          r.getString(2),
                          r.getString(3),
                          r.getString(1).equals(active),
                          refs.getOrDefault(r.getString(1), 0L))));
        });
  }

  private Map<String, Long> references() {
    return jdbc.query(
        "SELECT key_id,count(*) FROM (SELECT mfa_envelope_key(secret_cipher) AS key_id FROM mfa_totp UNION ALL SELECT mfa_envelope_key(secret_cipher) FROM mfa_factor_change WHERE secret_cipher IS NOT NULL) factors GROUP BY key_id",
        r -> {
          Map<String, Long> result = new HashMap<>();
          while (r.next()) result.put(r.getString(1), r.getLong(2));
          return result;
        });
  }

  private static void operator(String actor, String evidence) {
    if (actor == null
        || !actor.matches("[A-Za-z0-9][A-Za-z0-9_.:@/-]{2,199}")
        || evidence == null
        || !evidence.matches("[A-Za-z0-9][A-Za-z0-9_.:@/-]{2,499}"))
      throw new IllegalArgumentException("Operator and evidence references required");
  }

  public boolean introduce(String id, String actor, String evidence) {
    operator(actor, evidence);
    return Boolean.TRUE.equals(
        tx.execute(
            status -> {
              writer(true);
              String fingerprint = cipher.fingerprint(id);
              var rows =
                  jdbc.queryForList(
                      "SELECT key_id FROM mfa_encryption_key WHERE key_id=?", String.class, id);
              if (!rows.isEmpty()) {
                requireKey(id);
                return false;
              }
              jdbc.update(
                  "INSERT INTO mfa_encryption_key(key_id,fingerprint,state) VALUES (?,?,'AVAILABLE')",
                  id,
                  fingerprint);
              audit("INTRODUCED", null, id, actor, evidence, 0);
              return true;
            }));
  }

  public boolean activate(String id, String actor, String evidence) {
    operator(actor, evidence);
    return Boolean.TRUE.equals(
        tx.execute(
            status -> {
              String previous = writer(true);
              requireKey(id);
              if (id.equals(previous)) return false;
              jdbc.update("UPDATE mfa_encryption_control SET active_key=? WHERE singleton", id);
              audit("ACTIVATED", previous, id, actor, evidence, 0);
              return true;
            }));
  }

  public int rekey(int batch, String actor, String evidence) {
    operator(actor, evidence);
    if (batch < 1 || batch > 100)
      throw new IllegalArgumentException("Batch must be between 1 and 100");
    return Objects.requireNonNull(
        tx.execute(
            status -> {
              // Do not hold the control row while waiting for identities: all MFA writers
              // acquire identity/factor locks before the shared control-row lock.
              String observed =
                  jdbc.queryForObject(
                      "SELECT active_key FROM mfa_encryption_control WHERE singleton",
                      String.class);
              var users =
                  jdbc.queryForList(
                      "SELECT u.id FROM iam_user u WHERE EXISTS(SELECT 1 FROM mfa_totp f WHERE f.user_id=u.id AND mfa_envelope_key(f.secret_cipher)<>?) OR EXISTS(SELECT 1 FROM mfa_factor_change f WHERE f.user_id=u.id AND f.secret_cipher IS NOT NULL AND mfa_envelope_key(f.secret_cipher)<>?) ORDER BY u.id LIMIT ? FOR UPDATE OF u SKIP LOCKED",
                      UUID.class,
                      observed,
                      observed,
                      batch);
              String active = writer(false);
              requireKey(active);
              int changed = 0;
              for (UUID user : users) {
                var factors =
                    jdbc.queryForList(
                        "SELECT secret_cipher FROM mfa_totp WHERE user_id=? FOR UPDATE",
                        byte[].class,
                        user);
                for (byte[] encrypted : factors)
                  if (!active.equals(MfaSecretCipher.keyId(encrypted))) {
                    jdbc.update(
                        "UPDATE mfa_totp SET secret_cipher=? WHERE user_id=?",
                        reencrypt(user, encrypted),
                        user);
                    changed++;
                  }
                var pending =
                    jdbc.query(
                        "SELECT id,secret_cipher FROM mfa_factor_change WHERE user_id=? AND secret_cipher IS NOT NULL FOR UPDATE",
                        (r, n) -> new Pending(r.getObject(1, UUID.class), r.getBytes(2)),
                        user);
                for (Pending factor : pending)
                  if (!active.equals(MfaSecretCipher.keyId(factor.encrypted))) {
                    jdbc.update(
                        "UPDATE mfa_factor_change SET secret_cipher=? WHERE id=?",
                        reencrypt(user, factor.encrypted),
                        factor.id);
                    changed++;
                  }
              }
              if (changed > 0) audit("REKEYED", null, active, actor, evidence, changed);
              return changed;
            }));
  }

  private record Pending(UUID id, byte[] encrypted) {}

  private long verifyLocked() {
    return Objects.requireNonNull(
        jdbc.query(
            connection -> {
              var statement =
                  connection.prepareStatement(
                      "SELECT user_id,secret_cipher FROM mfa_totp UNION ALL SELECT user_id,secret_cipher FROM mfa_factor_change WHERE secret_cipher IS NOT NULL");
              statement.setFetchSize(100);
              return statement;
            },
            r -> {
              long count = 0;
              while (r.next()) {
                byte[] encrypted = r.getBytes(2);
                requireKey(MfaSecretCipher.keyId(encrypted));
                byte[] raw = cipher.decrypt(r.getObject(1, UUID.class), encrypted);
                Arrays.fill(raw, (byte) 0);
                count++;
              }
              return count;
            }));
  }

  public long verify() {
    return Objects.requireNonNull(
        tx.execute(
            status -> {
              writer(false);
              return verifyLocked();
            }));
  }

  public boolean retire(String id, String actor, String evidence) {
    operator(actor, evidence);
    return Boolean.TRUE.equals(
        tx.execute(
            status -> {
              String active = writer(true);
              if (id.equals(active))
                throw new IllegalStateException("Active factor key cannot retire");
              var states =
                  jdbc.queryForList(
                      "SELECT state FROM mfa_encryption_key WHERE key_id=?", String.class, id);
              if (states.size() != 1) throw new IllegalArgumentException("Unknown factor key");
              if (states.get(0).equals("RETIRED")) return false;
              requireKey(id);
              if (references().getOrDefault(id, 0L) != 0)
                throw new IllegalStateException("Factor key still referenced");
              verifyLocked();
              jdbc.update(
                  "UPDATE mfa_encryption_key SET state='RETIRED',retired_at=now() WHERE key_id=?",
                  id);
              audit("RETIRED", id, active, actor, evidence, 0);
              return true;
            }));
  }

  private void audit(
      String action, String source, String target, String actor, String evidence, int changed) {
    jdbc.update(
        "INSERT INTO mfa_key_audit(id,action,source_key,target_key,operator_ref,evidence_ref,changed_rows) VALUES (?,?,?,?,?,?,?)",
        UUID.randomUUID(),
        action,
        source,
        target,
        actor,
        evidence,
        changed);
  }
}
