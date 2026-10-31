package com.unipass.identity;

import java.sql.*;
import org.flywaydb.core.Flyway;

public record Database(String url, String username, String password) {
  public Database {
    if (url == null || !url.startsWith("jdbc:postgresql:"))
      throw new IllegalArgumentException("PostgreSQL JDBC URL required");
  }

  public Connection open() throws SQLException {
    java.util.Properties props = new java.util.Properties();
    props.setProperty("user", username);
    props.setProperty("password", password);
    props.setProperty("connectTimeout", "3");
    props.setProperty("socketTimeout", "10");
    Connection c = DriverManager.getConnection(url, props);
    c.setNetworkTimeout(Runnable::run, 10000);
    return c;
  }

  public void migrate() {
    Flyway.configure().dataSource(url, username, password).load().migrate();
  }

  @Override
  public String toString() {
    return "Database[REDACTED]";
  }
}
