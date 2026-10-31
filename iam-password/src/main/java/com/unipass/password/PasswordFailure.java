package com.unipass.password;

import java.util.UUID;

/** Codes are safe to return. Never attach raw LDAP or database exception text. */
public final class PasswordFailure extends RuntimeException {
  public enum Code {
    INVALID_REQUEST,
    RECENT_AUTH_REQUIRED,
    ACCOUNT_BLOCKED,
    STALE_SESSION,
    RATE_LIMITED,
    POLICY_REJECTED,
    OLD_PASSWORD_INCORRECT,
    DIRECTORY_UNAVAILABLE,
    CONCURRENT_OPERATION,
    NOT_FOUND,
    RECOVERY_NOT_PERMITTED,
    RECOVERY_EVIDENCE_REQUIRED,
    DIRECTORY_POLICY_NOT_VERIFIED,
    STORAGE_UNAVAILABLE
  }

  private final Code code;
  private final UUID operationId;

  public PasswordFailure(Code code) {
    this(code, null);
  }

  public PasswordFailure(Code code, UUID operationId) {
    super(code.name());
    this.code = code;
    this.operationId = operationId;
  }

  public Code code() {
    return code;
  }

  public UUID operationId() {
    return operationId;
  }
}
