package com.unipass.password;

import static com.unipass.password.PasswordFailure.Code.*;

import com.unipass.identity.Database;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.*;
import java.time.*;
import java.util.*;

/**
 * Consumes an identity verification already persisted by a trusted factor adapter, not a user
 * assertion.
 */
public final class ResetGrantService {
  private final Database database;
  private final Clock clock;

  public ResetGrantService(Database database, Clock clock) {
    this.database = database;
    this.clock = clock;
  }

  public static final class Grant {
    private final String token;
    private final Instant expiresAt;

    private Grant(String token, Instant expiresAt) {
      this.token = token;
      this.expiresAt = expiresAt;
    }

    public String token() {
      return token;
    }

    public Instant expiresAt() {
      return expiresAt;
    }

    @Override
    public String toString() {
      return "ResetGrant[REDACTED]";
    }
  }

  public Grant issueFromVerification(UUID verificationId) {
    try (Connection c = database.open()) {
      c.setAutoCommit(false);
      try {
        UUID userId;
        try (PreparedStatement s =
            c.prepareStatement("SELECT user_id FROM identity_verification WHERE id=?")) {
          s.setObject(1, verificationId);
          try (ResultSet r = s.executeQuery()) {
            if (!r.next()) throw new PasswordFailure(INVALID_REQUEST);
            userId = r.getObject(1, UUID.class);
          }
        }
        long epoch;
        try (PreparedStatement s =
            c.prepareStatement(
                "SELECT auth_epoch,status,password_gate FROM iam_user WHERE id=? FOR UPDATE")) {
          s.setObject(1, userId);
          try (ResultSet r = s.executeQuery()) {
            if (!r.next() || !r.getString(2).equals("ACTIVE") || !r.getString(3).equals("OPEN"))
              throw new PasswordFailure(ACCOUNT_BLOCKED);
            epoch = r.getLong(1);
          }
        }
        String factor;
        Instant verifiedAt;
        try (PreparedStatement s =
            c.prepareStatement("SELECT * FROM identity_verification WHERE id=? FOR UPDATE")) {
          s.setObject(1, verificationId);
          try (ResultSet r = s.executeQuery()) {
            r.next();
            verifiedAt = r.getTimestamp("verified_at").toInstant();
            if (r.getTimestamp("consumed_at") != null
                || !r.getTimestamp("expires_at").toInstant().isAfter(clock.instant())
                || r.getLong("auth_epoch") != epoch
                || verifiedAt.isAfter(clock.instant())
                || verifiedAt.plusSeconds(300).isBefore(clock.instant()))
              throw new PasswordFailure(INVALID_REQUEST);
            factor = r.getString("factor");
          }
        }
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        Arrays.fill(bytes, (byte) 0);
        Instant expires = clock.instant().plusSeconds(600);
        try (PreparedStatement s =
            c.prepareStatement(
                "INSERT INTO password_reset_grant(token_digest,user_id,auth_epoch,factor,verified_at,expires_at) VALUES (?,?,?,?,?,?)")) {
          s.setString(1, digest(token));
          s.setObject(2, userId);
          s.setLong(3, epoch);
          s.setString(4, factor);
          s.setTimestamp(5, Timestamp.from(verifiedAt));
          s.setTimestamp(6, Timestamp.from(expires));
          s.executeUpdate();
        }
        try (PreparedStatement s =
            c.prepareStatement("UPDATE identity_verification SET consumed_at=? WHERE id=?")) {
          s.setTimestamp(1, Timestamp.from(clock.instant()));
          s.setObject(2, verificationId);
          s.executeUpdate();
        }
        c.commit();
        return new Grant(token, expires);
      } catch (SQLException | RuntimeException e) {
        c.rollback();
        throw e;
      }
    } catch (SQLException e) {
      throw new PasswordFailure(STORAGE_UNAVAILABLE);
    }
  }

  static String digest(String token) {
    try {
      return HexFormat.of()
          .formatHex(
              MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 unavailable");
    }
  }
}
