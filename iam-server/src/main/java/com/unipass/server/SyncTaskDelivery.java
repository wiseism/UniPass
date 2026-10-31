package com.unipass.server;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/**
 * At-least-once adapter boundary. Use eventId as the external idempotency key. No password,
 * arbitrary JSON payload, token or remote error text crosses this boundary.
 */
public interface SyncTaskDelivery {
  String target();

  Result deliver(Event event) throws Exception;

  record Event(UUID eventId, UUID userId, String type, long authEpoch, Instant createdAt) {}

  enum Outcome {
    SUCCESS,
    SUCCESS_DEGRADED,
    RETRY,
    BLOCKED,
    DEAD
  }

  enum Code {
    DELIVERY_CONFIRMED,
    LOCAL_ACCESS_REVOKED,
    CAPABILITY_MISSING,
    PERMISSION_DENIED,
    RATE_LIMITED,
    TEMPORARY_FAILURE,
    OUTCOME_UNKNOWN,
    UNSUPPORTED_EVENT,
    LEASE_EXPIRED,
    LOCAL_CAPACITY,
    OPERATOR_RETRY
  }

  record Result(Outcome outcome, Code code, Duration retryAfter) {
    public Result {
      java.util.Objects.requireNonNull(outcome);
      java.util.Objects.requireNonNull(code);
      if (retryAfter != null
          && (outcome != Outcome.RETRY
              || retryAfter.isNegative()
              || retryAfter.compareTo(Duration.ofDays(7)) > 0))
        throw new IllegalArgumentException("Invalid retry delay");
      if ((outcome == Outcome.SUCCESS && code != Code.DELIVERY_CONFIRMED)
          || (outcome == Outcome.SUCCESS_DEGRADED && code != Code.LOCAL_ACCESS_REVOKED))
        throw new IllegalArgumentException("Unconfirmed delivery result");
    }

    public static Result retry(Code code) {
      return new Result(Outcome.RETRY, code, null);
    }

    public static Result blocked(Code code) {
      return new Result(Outcome.BLOCKED, code, null);
    }
  }
}
