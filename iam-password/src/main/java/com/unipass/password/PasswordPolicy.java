package com.unipass.password;

import java.text.Normalizer;
import java.util.*;

/** Local rules supplement, never replace, directory history and complexity policies. */
public final class PasswordPolicy {
  private final Set<String> dictionary;

  public PasswordPolicy(Set<String> dictionary) {
    Set<String> normalized = new HashSet<>();
    dictionary.forEach(s -> normalized.add(s.toLowerCase(Locale.ROOT)));
    this.dictionary = Set.copyOf(normalized);
  }

  public static PasswordPolicy defaults() {
    return new PasswordPolicy(
        Set.of("password", "password123!", "qwerty123!", "unipass", "admin123!"));
  }

  public List<String> violations(char[] password, String employeeNo, String displayName) {
    List<String> violations = new ArrayList<>();
    if (password == null) return List.of("REQUIRED");
    // The temporary string is needed by Unicode APIs; it is never persisted or logged.
    String value = Normalizer.normalize(new String(password), Normalizer.Form.NFKC);
    int[] points = value.codePoints().toArray();
    if (points.length < 10) violations.add("MIN_LENGTH");
    if (points.length > 128) violations.add("MAX_LENGTH");
    if (Arrays.stream(points).anyMatch(Character::isISOControl))
      violations.add("CONTROL_CHARACTER");
    boolean upper = false, lower = false, digit = false, symbol = false;
    for (int cp : points) {
      upper |= Character.isUpperCase(cp);
      lower |= Character.isLowerCase(cp);
      digit |= Character.isDigit(cp);
      symbol |= !Character.isLetterOrDigit(cp) && !Character.isWhitespace(cp);
    }
    if ((upper ? 1 : 0) + (lower ? 1 : 0) + (digit ? 1 : 0) + (symbol ? 1 : 0) < 3)
      violations.add("CHARACTER_CLASSES");
    String folded = value.toLowerCase(Locale.ROOT);
    if (dictionary.contains(folded) || folded.contains("unipass"))
      violations.add("COMMON_PASSWORD");
    for (String identity : Arrays.asList(employeeNo, displayName)) {
      if (identity != null
          && identity.codePointCount(0, identity.length()) >= 2
          && folded.contains(
              Normalizer.normalize(identity, Normalizer.Form.NFKC).toLowerCase(Locale.ROOT))) {
        violations.add("CONTAINS_IDENTITY");
        break;
      }
    }
    for (int i = 2; i < points.length; i++) {
      int a = points[i - 2], b = points[i - 1], c = points[i];
      if (a == b && b == c || b - a == 1 && c - b == 1 || a - b == 1 && b - c == 1) {
        violations.add("SEQUENCE_OR_REPETITION");
        break;
      }
    }
    Arrays.fill(points, 0);
    return List.copyOf(violations);
  }
}
