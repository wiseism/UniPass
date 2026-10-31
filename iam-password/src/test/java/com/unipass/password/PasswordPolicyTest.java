package com.unipass.password;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Set;
import org.junit.jupiter.api.Test;

class PasswordPolicyTest {
  private final PasswordPolicy policy = PasswordPolicy.defaults();

  @Test
  void rejectsWeakIdentityAndDictionaryValues() {
    assertTrue(policy.violations("short".toCharArray(), "E001", "张三").contains("MIN_LENGTH"));
    assertTrue(
        policy.violations("E001-xQ@7kp".toCharArray(), "E001", "张三").contains("CONTAINS_IDENTITY"));
    assertTrue(
        policy.violations("张三-xQ@7kp9".toCharArray(), "E001", "张三").contains("CONTAINS_IDENTITY"));
    assertTrue(
        policy.violations("Unipass-7Q!".toCharArray(), "E001", "张三").contains("COMMON_PASSWORD"));
    assertTrue(
        new PasswordPolicy(Set.of("qx!7vn2$pk"))
            .violations("Qx!7vN2$pk".toCharArray(), null, null)
            .contains("COMMON_PASSWORD"));
  }

  @Test
  void countsUnicodeCodePointsAndRejectsControlAndSequences() {
    assertTrue(
        policy.violations("Aa7!😀😀😀😀😀".toCharArray(), null, null).contains("MIN_LENGTH"));
    assertTrue(
        policy.violations("Rz@8mP4#\nks".toCharArray(), null, null).contains("CONTROL_CHARACTER"));
    assertTrue(
        policy
            .violations("Rz@8mP4#aaa".toCharArray(), null, null)
            .contains("SEQUENCE_OR_REPETITION"));
    assertTrue(
        policy
            .violations("Rz@8mP4#abc".toCharArray(), null, null)
            .contains("SEQUENCE_OR_REPETITION"));
    assertTrue(policy.violations("Rz@8mP4#中文😀".toCharArray(), null, null).isEmpty());
  }
}
