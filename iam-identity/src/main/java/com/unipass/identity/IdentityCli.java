package com.unipass.identity;

import com.unipass.directory.*;
import java.net.URI;
import java.nio.file.Path;
import java.util.*;

/**
 * Local operator CLI. No HTTP management interface is exposed before T2/T8 authorization exists.
 */
public final class IdentityCli {
  private IdentityCli() {}

  public static void main(String[] args) {
    try {
      run(args);
    } catch (Exception e) {
      // LDAP/JDBC exception strings can contain private identity or credential material.
      System.err.println(
          "Operation failed ("
              + e.getClass().getSimpleName()
              + "). Check configuration and sanitized reports.");
      System.exit(1);
    }
  }

  static void run(String[] args) throws Exception {
    if (args.length == 0) throw new IllegalArgumentException("Command required");
    Database db =
        new Database(env("UNIPASS_DB_URL"), env("UNIPASS_DB_USER"), env("UNIPASS_DB_PASSWORD"));
    if (args[0].equals("migrate") && args.length == 1) {
      db.migrate();
      return;
    }
    // Reporting never needs a directory credential.
    if (args[0].equals("report") && args.length == 2) {
      print(new IdentityImportService(db, null, null).report(UUID.fromString(args[1])));
      return;
    }
    DirectoryConfig.Type type = DirectoryConfig.Type.valueOf(env("UNIPASS_DIRECTORY_TYPE"));
    DirectoryConfig config =
        new DirectoryConfig(
            URI.create(env("UNIPASS_LDAP_URL")),
            env("UNIPASS_LDAP_BASE_DN"),
            env("UNIPASS_LDAP_READ_DN"),
            env("UNIPASS_LDAP_READ_PASSWORD"),
            System.getenv("UNIPASS_LDAP_WRITE_DN"),
            System.getenv("UNIPASS_LDAP_WRITE_PASSWORD"),
            type,
            "true".equals(System.getenv("UNIPASS_LDAP_WRITABLE_CONFIRMED")));
    DirectoryGateway gateway = new LdapDirectoryGateway(config);
    IdentityImportService imports = new IdentityImportService(db, gateway, type);
    switch (args[0]) {
      case "preview" -> {
        if (args.length != 5)
          throw new IllegalArgumentException(
              "preview <source> <expected-cursor|-> <next-cursor> <csv>");
        print(
            imports.preview(
                args[1],
                args[2].equals("-") ? "" : args[2],
                args[3],
                HrCsv.read(Path.of(args[4]))));
      }
      case "apply" -> {
        if (args.length != 3 || !args[2].equals("--confirm"))
          throw new IllegalArgumentException("apply <batch-id> --confirm");
        System.out.println(imports.apply(UUID.fromString(args[1])));
      }
      case "disable" -> {
        if (args.length != 3 || !args[2].equals("--confirm"))
          throw new IllegalArgumentException("disable <user-id> --confirm");
        UUID trace = UUID.randomUUID();
        new IdentityLifecycleService(db, gateway).disable(UUID.fromString(args[1]), trace);
        System.out.println("Local access disabled; trace_id=" + trace + "; directory task=PENDING");
      }
      case "reconcile" -> {
        if (args.length != 1) throw new IllegalArgumentException("reconcile takes no arguments");
        boolean attempted = new IdentityLifecycleService(db, gateway).reconcileOne();
        System.out.println(
            "directory_task_attempted="
                + attempted
                + "; inspect directory_disable_task for result");
      }
      default ->
          throw new IllegalArgumentException(
              "Commands: migrate, preview, report, apply, disable, reconcile");
    }
  }

  private static String env(String key) {
    String value = System.getenv(key);
    if (value == null || value.isBlank())
      throw new IllegalArgumentException("Required environment variable missing");
    return value;
  }

  private static void print(IdentityImportService.Preview preview) {
    System.out.println(
        "batch_id="
            + preview.batchId()
            + " state="
            + preview.state()
            + " valid="
            + preview.validCount()
            + " total="
            + preview.rows().size());
    for (var row : preview.rows())
      System.out.println(
          "row="
              + row.rowNo()
              + " action="
              + row.action()
              + " result="
              + (row.errorCode() == null ? "VALID" : row.errorCode()));
  }
}
