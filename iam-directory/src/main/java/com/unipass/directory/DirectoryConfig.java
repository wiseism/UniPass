package com.unipass.directory;

import java.net.URI;
import java.util.Objects;

public record DirectoryConfig(
    URI endpoint,
    String baseDn,
    String readDn,
    String readPassword,
    String writeDn,
    String writePassword,
    Type type,
    boolean writableConfirmed) {
  public enum Type {
    OPENLDAP,
    AD
  }

  public DirectoryConfig {
    Objects.requireNonNull(endpoint);
    Objects.requireNonNull(type);
    if (!"ldaps".equals(endpoint.getScheme())
        || endpoint.getHost() == null
        || endpoint.getUserInfo() != null
        || endpoint.getQuery() != null
        || endpoint.getFragment() != null
        || (endpoint.getPath() != null && !endpoint.getPath().isEmpty()))
      throw new IllegalArgumentException(
          "Directory endpoint must be ldaps://host:port without credentials/path");
    if (baseDn == null
        || baseDn.isBlank()
        || readDn == null
        || readDn.isBlank()
        || readPassword == null
        || readPassword.isEmpty())
      throw new IllegalArgumentException("Base DN and non-anonymous read credentials required");
  }

  @Override
  public String toString() {
    return "DirectoryConfig[" + type + ", credentials=REDACTED]";
  }
}
