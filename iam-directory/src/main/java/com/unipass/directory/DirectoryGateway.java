package com.unipass.directory;

import java.util.Optional;

/** Credentials are request-scoped; implementations must never log or persist them. */
public interface DirectoryGateway {
  DirectoryConfig.Type type();

  Optional<DirectoryUser> findByStableId(String stableId);

  boolean verifyCredential(String stableId, char[] password);

  void changePassword(String stableId, char[] oldPassword, char[] newPassword);

  void disableUser(String stableId);

  /** Evidence only. A changed version alone never proves which password write succeeded. */
  default Optional<String> passwordVersion(String stableId) {
    return Optional.empty();
  }

  default boolean supportsPasswordReset() {
    return false;
  }

  default void resetPassword(String stableId, char[] newPassword) {
    throw new UnsupportedOperationException("Directory reset not supported");
  }

  record DirectoryUser(String stableId, String employeeNo, String dn, boolean disabled) {}
}
