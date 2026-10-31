package com.unipass.password;

import java.time.Instant;
import java.util.*;

/** Constructed by the authentication boundary, never deserialized from an API request body. */
public record AuthenticatedActor(
    UUID userId,
    long authEpoch,
    Instant authenticatedAt,
    Set<String> authorities,
    Instant mfaAt,
    UUID loginId) {
  public AuthenticatedActor(
      UUID userId,
      long authEpoch,
      Instant authenticatedAt,
      Set<String> authorities,
      Instant mfaAt) {
    this(userId, authEpoch, authenticatedAt, authorities, mfaAt, null);
  }

  public AuthenticatedActor {
    Objects.requireNonNull(userId);
    Objects.requireNonNull(authenticatedAt);
    authorities = Set.copyOf(authorities);
  }

  public static AuthenticatedActor user(UUID id, long epoch, Instant at) {
    return new AuthenticatedActor(id, epoch, at, Set.of("USER"), null);
  }

  public static AuthenticatedActor user(UUID id, long epoch, Instant at, UUID loginId) {
    return new AuthenticatedActor(
        id, epoch, at, Set.of("USER"), null, Objects.requireNonNull(loginId));
  }
}
