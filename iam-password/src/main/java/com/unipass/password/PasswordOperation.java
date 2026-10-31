package com.unipass.password;

import java.time.Instant;
import java.util.UUID;

/** Non-secret status view. */
public record PasswordOperation(
    UUID id,
    UUID userId,
    State state,
    long fencedEpoch,
    Instant createdAt,
    Instant finishedAt,
    String errorCode) {
  public enum State {
    PREPARED,
    COMMITTED,
    REJECTED,
    UNKNOWN
  }

  public boolean requiresRecovery() {
    return state == State.UNKNOWN;
  }
}
