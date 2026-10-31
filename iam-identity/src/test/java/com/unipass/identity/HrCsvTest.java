package com.unipass.identity;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class HrCsvTest {
  @TempDir Path temp;

  @Test
  void parsesQuotedChineseNamesAndQuarantinableBadVersion() throws Exception {
    Path csv = temp.resolve("hr.csv");
    Files.writeString(
        csv,
        "employee_no,directory_id,display_name,status,source_version\r\nE1,id,\"张,三\",ACTIVE,bad\r\n");
    var rows = HrCsv.read(csv);
    assertEquals("张,三", rows.get(0).displayName());
    assertEquals(-1, rows.get(0).sourceVersion());
  }

  @Test
  void rejectsUnexpectedSensitiveColumnsAndMalformedRows() throws Exception {
    Path csv = temp.resolve("hr.csv");
    Files.writeString(csv, "employee_no,password\nE1,secret\n");
    assertThrows(IllegalArgumentException.class, () -> HrCsv.read(csv));
    Files.writeString(
        csv, "employee_no,directory_id,display_name,status,source_version\nE1,id,Name\n");
    assertThrows(IllegalArgumentException.class, () -> HrCsv.read(csv));
  }
}
