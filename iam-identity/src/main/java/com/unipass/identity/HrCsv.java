package com.unipass.identity;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.apache.commons.csv.*;

public final class HrCsv {
  private HrCsv() {}

  public static List<HrRow> read(Path path) throws IOException {
    try (Reader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8);
        CSVParser parser =
            CSVFormat.RFC4180.builder().setHeader().setSkipHeaderRecord(true).get().parse(reader)) {
      if (!parser
          .getHeaderNames()
          .equals(
              List.of("employee_no", "directory_id", "display_name", "status", "source_version")))
        throw new IllegalArgumentException("Unexpected HR CSV header");
      List<HrRow> rows = new ArrayList<>();
      for (CSVRecord r : parser) {
        if (rows.size() >= 50000)
          throw new IllegalArgumentException("Import limited to 50000 rows");
        if (!r.isConsistent())
          throw new IllegalArgumentException("Inconsistent CSV row " + r.getRecordNumber());
        long version;
        try {
          version = Long.parseLong(r.get("source_version"));
        } catch (NumberFormatException e) {
          version = -1;
        }
        rows.add(
            new HrRow(
                r.get("employee_no"),
                r.get("directory_id"),
                r.get("display_name"),
                r.get("status"),
                version));
      }
      return List.copyOf(rows);
    }
  }
}
