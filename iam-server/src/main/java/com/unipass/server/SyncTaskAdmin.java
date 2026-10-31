package com.unipass.server;

import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

/** Offline operator functions. Requeue can repeat an unknown external outcome. */
final class SyncTaskAdmin {
  private final JdbcTemplate jdbc;
  private final TransactionTemplate tx;

  SyncTaskAdmin(JdbcTemplate jdbc, TransactionTemplate transactions) {
    this.jdbc = jdbc;
    this.tx = new TransactionTemplate(Objects.requireNonNull(transactions.getTransactionManager()));
    this.tx.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    this.tx.setTimeout(10);
  }

  record Group(String target, String state, long count, String oldestUpdate) {}

  record Report(List<Group> tasks, long unroutedEvents, long missingTasks) {}

  record Entry(
      UUID id,
      UUID eventId,
      String target,
      String state,
      int attempts,
      long leaseVersion,
      String code) {}

  Report report() {
    return tx.execute(
        ignored ->
            new Report(
                jdbc.query(
                    """
                SELECT target,state,count(*) AS total,min(updated_at) AS oldest FROM sync_task
                GROUP BY target,state ORDER BY target,state
                """,
                    (r, n) ->
                        new Group(
                            r.getString("target"),
                            r.getString("state"),
                            r.getLong("total"),
                            r.getTimestamp("oldest").toInstant().toString())),
                jdbc.queryForObject(
                    "SELECT count(*) FROM outbox_event WHERE published_at IS NULL", Long.class),
                jdbc.queryForObject(
                    """
                        SELECT count(*) FROM outbox_event e
                        CROSS JOIN (VALUES ('FEISHU_APP_REAUTH'),('APP_PUSH')) AS targets(target)
                        WHERE e.event_type IN ('unipass.password.changed','unipass.user.disabled')
                        AND NOT EXISTS (SELECT 1 FROM sync_task t WHERE t.event_id=e.event_id AND t.target=targets.target)
                        """,
                    Long.class)));
  }

  List<Entry> tasks(int limit) {
    if (limit < 1 || limit > 100) throw new IllegalArgumentException("Invalid task limit");
    return jdbc.query(
        """
                SELECT id,event_id,target,state,attempt_count,lease_version,last_error FROM sync_task
                WHERE state IN ('BLOCKED','DEAD') ORDER BY updated_at,id LIMIT ?
                """,
        (r, n) ->
            new Entry(
                r.getObject("id", UUID.class),
                r.getObject("event_id", UUID.class),
                r.getString("target"),
                r.getString("state"),
                r.getInt("attempt_count"),
                r.getLong("lease_version"),
                r.getString("last_error")),
        limit);
  }

  boolean retry(UUID id, String operator, String evidence) {
    requireRef(operator, 200);
    requireRef(evidence, 500);
    return Boolean.TRUE.equals(
        tx.execute(
            ignored -> {
              var rows =
                  jdbc.queryForList(
                      "SELECT state,attempt_count,lease_version FROM sync_task WHERE id=? FOR UPDATE",
                      id);
              if (rows.isEmpty()) throw new IllegalArgumentException("Unknown task");
              var row = rows.get(0);
              if (!Set.of("BLOCKED", "DEAD").contains(row.get("state"))) return false;
              long version = ((Number) row.get("lease_version")).longValue() + 1;
              jdbc.update(
                  """
                    UPDATE sync_task SET state='PENDING',attempt_count=0,last_error='OPERATOR_RETRY',
                    lease_version=?,finished_at=NULL,updated_at=clock_timestamp(),next_retry_at=clock_timestamp() WHERE id=?
                    """,
                  version,
                  id);
              jdbc.update(
                  """
                    INSERT INTO sync_task_audit(id,task_id,action,state,attempt_count,previous_attempt_count,
                    lease_version,result_code,operator_ref,evidence_ref) VALUES (?,?,'REQUEUED','PENDING',0,?,?,'OPERATOR_RETRY',?,?)
                    """,
                  UUID.randomUUID(),
                  id,
                  row.get("attempt_count"),
                  version,
                  operator,
                  evidence);
              return true;
            }));
  }

  private static void requireRef(String ref, int max) {
    if (ref == null || !ref.matches("[A-Za-z0-9][A-Za-z0-9_.:@/-]{2," + (max - 1) + "}"))
      throw new IllegalArgumentException("Operator and evidence references required");
  }
}
