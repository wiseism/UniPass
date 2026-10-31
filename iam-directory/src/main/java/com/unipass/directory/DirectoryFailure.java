package com.unipass.directory;

/** Sanitized failure. Write timeout is deliberately distinct from a definite rejection. */
public final class DirectoryFailure extends RuntimeException {
  public enum Kind {
    UNAVAILABLE,
    REJECTED,
    UNKNOWN_WRITE,
    AMBIGUOUS_IDENTITY
  }

  private final Kind kind;

  public DirectoryFailure(Kind kind) {
    super("Directory operation: " + kind);
    this.kind = kind;
  }

  public Kind kind() {
    return kind;
  }
}
