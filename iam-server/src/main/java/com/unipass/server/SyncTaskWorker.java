package com.unipass.server;

import static com.unipass.server.SyncTaskDelivery.*;

import jakarta.annotation.PreDestroy;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

/** Short database leases, bounded calls outside transactions, fenced completion. */
@Service
public final class SyncTaskWorker implements AutoCloseable {
  private static final int MAX_ATTEMPTS = 4;
  private static final org.slf4j.Logger LOG =
      org.slf4j.LoggerFactory.getLogger(SyncTaskWorker.class);
  private final JdbcTemplate jdbc;
  private final TransactionTemplate tx;
  private final Map<String, SyncTaskDelivery> adapters;
  private final UUID owner = UUID.randomUUID();
  private final Duration timeout;
  // An interrupt-ignoring adapter cannot create unbounded threads or queued calls.
  private final ExecutorService calls =
      new ThreadPoolExecutor(
          0,
          2,
          30,
          TimeUnit.SECONDS,
          new SynchronousQueue<>(),
          runnable -> {
            Thread thread = new Thread(runnable, "unipass-sync-call");
            thread.setDaemon(true);
            return thread;
          },
          new ThreadPoolExecutor.AbortPolicy());

  private record Task(
      UUID id, Event event, String target, int attempts, long version, UUID token) {}

  private record Claim(Task task, boolean exhausted) {}

  @Autowired
  public SyncTaskWorker(
      JdbcTemplate jdbc, TransactionTemplate transactions, List<SyncTaskDelivery> adapters) {
    this(jdbc, transactions, adapters, Duration.ofSeconds(5));
  }

  SyncTaskWorker(
      JdbcTemplate jdbc,
      TransactionTemplate transactions,
      List<SyncTaskDelivery> adapters,
      Duration timeout) {
    this.jdbc = jdbc;
    this.tx = new TransactionTemplate(Objects.requireNonNull(transactions.getTransactionManager()));
    this.tx.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    this.tx.setTimeout(10);
    if (timeout.isNegative() || timeout.isZero() || timeout.compareTo(Duration.ofSeconds(10)) > 0)
      throw new IllegalArgumentException("Invalid delivery timeout");
    this.timeout = timeout;
    Map<String, SyncTaskDelivery> registry = new HashMap<>();
    for (SyncTaskDelivery adapter : adapters) {
      if (!adapter.target().matches("[A-Z][A-Z0-9_]{0,63}")
          || registry.putIfAbsent(adapter.target(), adapter) != null)
        throw new IllegalArgumentException("Duplicate or invalid delivery target");
    }
    this.adapters = Map.copyOf(registry);
  }

  public boolean runOnce() {
    Claim claim = tx.execute(ignored -> claim());
    if (claim == null) return false;
    if (claim.exhausted) {
      LOG.warn("Sync delivery exhausted an expired lease");
      return true;
    }
    Task task = claim.task;
    Result result;
    if (task.event == null) result = new Result(Outcome.DEAD, Code.UNSUPPORTED_EVENT, null);
    else if (!adapters.containsKey(task.target)) result = Result.blocked(Code.CAPABILITY_MISSING);
    else result = invoke(task);
    Result completed = result;
    boolean owned = Boolean.TRUE.equals(tx.execute(ignored -> finish(task, completed)));
    if (owned
        && (result.outcome() == Outcome.BLOCKED
            || result.outcome() == Outcome.DEAD
            || result.outcome() == Outcome.RETRY && task.attempts >= MAX_ATTEMPTS))
      LOG.warn(
          "Sync delivery requires operator attention: target={}, code={}",
          task.target,
          result.code());
    return true;
  }

  private Claim claim() {
    var tasks =
        jdbc.query(
            """
                SELECT t.*,e.aggregate_id,e.event_type,e.schema_version,e.auth_epoch,e.created_at AS event_created_at
                FROM sync_task t JOIN outbox_event e ON e.event_id=t.event_id
                WHERE (t.state='PENDING' AND t.next_retry_at<=clock_timestamp())
                   OR (t.state='RUNNING' AND t.lease_until<=clock_timestamp())
                ORDER BY t.next_retry_at,t.id LIMIT 1 FOR UPDATE OF t SKIP LOCKED
                """,
            (r, n) ->
                new Task(
                    r.getObject("id", UUID.class),
                    r.getInt("schema_version") == 1
                            && Set.of("unipass.password.changed", "unipass.user.disabled")
                                .contains(r.getString("event_type"))
                            && r.getLong("auth_epoch") >= 0
                        ? new Event(
                            r.getObject("event_id", UUID.class),
                            r.getObject("aggregate_id", UUID.class),
                            r.getString("event_type"),
                            r.getLong("auth_epoch"),
                            r.getTimestamp("event_created_at").toInstant())
                        : null,
                    r.getString("target"),
                    r.getInt("attempt_count"),
                    r.getLong("lease_version"),
                    UUID.randomUUID()));
    if (tasks.isEmpty()) return null;
    Task old = tasks.get(0);
    if (old.attempts >= MAX_ATTEMPTS) {
      jdbc.update(
          """
                    UPDATE sync_task SET state='DEAD',last_error='LEASE_EXPIRED',lease_owner=NULL,lease_token=NULL,
                    lease_until=NULL,lease_version=lease_version+1,updated_at=clock_timestamp(),finished_at=clock_timestamp() WHERE id=?
                    """,
          old.id);
      audit(old.id, "EXHAUSTED", "DEAD", old.attempts, old.version + 1, Code.LEASE_EXPIRED);
      return new Claim(null, true);
    }
    Task task =
        new Task(old.id, old.event, old.target, old.attempts + 1, old.version + 1, old.token);
    jdbc.update(
        """
                UPDATE sync_task SET state='RUNNING',attempt_count=?,lease_owner=?,lease_token=?,lease_version=?,
                lease_until=clock_timestamp()+interval '30 seconds',last_error=NULL,finished_at=NULL,updated_at=clock_timestamp() WHERE id=?
                """,
        task.attempts,
        owner,
        task.token,
        task.version,
        task.id);
    audit(task.id, "CLAIMED", "RUNNING", task.attempts, task.version, null);
    return new Claim(task, false);
  }

  private Result invoke(Task task) {
    Future<Result> pending = null;
    try {
      pending = calls.submit(() -> adapters.get(task.target).deliver(task.event));
      return Objects.requireNonNull(pending.get(timeout.toMillis(), TimeUnit.MILLISECONDS));
    } catch (RejectedExecutionException saturated) {
      return Result.retry(Code.LOCAL_CAPACITY);
    } catch (InterruptedException interrupted) {
      Thread.currentThread().interrupt();
      return Result.retry(Code.OUTCOME_UNKNOWN);
    } catch (ExecutionException | TimeoutException | NullPointerException failure) {
      // Exception and remote response messages may contain credentials; persist only a fixed code.
      return Result.retry(Code.OUTCOME_UNKNOWN);
    } finally {
      if (pending != null && !pending.isDone()) pending.cancel(true);
    }
  }

  private boolean finish(Task task, Result result) {
    var owned =
        jdbc.queryForList(
            """
                SELECT id FROM sync_task WHERE id=? AND state='RUNNING' AND lease_token=? AND lease_owner=?
                AND lease_version=? AND lease_until>clock_timestamp() FOR UPDATE
                """,
            task.id,
            task.token,
            owner,
            task.version);
    if (owned.isEmpty()) return false;
    String state =
        result.outcome() == Outcome.RETRY
            ? task.attempts >= MAX_ATTEMPTS ? "DEAD" : "PENDING"
            : result.outcome().name();
    long delay = 0;
    if (state.equals("PENDING")) {
      delay =
          new long[] {60_000, 300_000, 900_000}[task.attempts - 1]
              + ThreadLocalRandom.current().nextLong(10_001);
      if (result.retryAfter() != null) delay = Math.max(delay, result.retryAfter().toMillis());
    }
    jdbc.update(
        """
                UPDATE sync_task SET state=?,last_error=?,next_retry_at=statement_timestamp()+(? * interval '1 millisecond'),
                lease_owner=NULL,lease_token=NULL,lease_until=NULL,updated_at=statement_timestamp(),
                finished_at=CASE WHEN ?='PENDING' THEN NULL ELSE statement_timestamp() END WHERE id=?
                """,
        state,
        result.code().name(),
        delay,
        state,
        task.id);
    audit(task.id, "FINISHED", state, task.attempts, task.version, result.code());
    return true;
  }

  private void audit(UUID id, String action, String state, int attempts, long version, Code code) {
    jdbc.update(
        """
                INSERT INTO sync_task_audit(id,task_id,action,state,attempt_count,lease_version,result_code,operator_ref)
                VALUES (?,?,?,?,?,?,?,?)
                """,
        UUID.randomUUID(),
        id,
        action,
        state,
        attempts,
        version,
        code == null ? null : code.name(),
        "worker:" + owner);
  }

  @Override
  @PreDestroy
  public void close() {
    calls.shutdownNow();
  }
}
