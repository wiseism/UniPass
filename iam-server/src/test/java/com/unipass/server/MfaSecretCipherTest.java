package com.unipass.server;

import static org.junit.jupiter.api.Assertions.*;

import java.util.*;
import org.junit.jupiter.api.Test;

class MfaSecretCipherTest {
  private static String key(int value) {
    byte[] raw = new byte[32];
    Arrays.fill(raw, (byte) value);
    return Base64.getEncoder().encodeToString(raw);
  }

  @Test
  void secretEnvelopeAuthenticatesItsOwnerAndRejectsTampering() {
    var cipher = new MfaSecretCipher(Base64.getEncoder().encodeToString(new byte[32]));
    UUID owner = UUID.randomUUID();
    byte[] raw = new byte[20];
    new java.security.SecureRandom().nextBytes(raw);
    byte[] encrypted = cipher.encrypt(owner, raw);
    assertFalse(Arrays.equals(raw, encrypted));
    assertArrayEquals(raw, cipher.decrypt(owner, encrypted));
    assertThrows(IllegalStateException.class, () -> cipher.decrypt(UUID.randomUUID(), encrypted));
    encrypted[encrypted.length - 1] ^= 1;
    assertThrows(IllegalStateException.class, () -> cipher.decrypt(owner, encrypted));
    assertThrows(
        IllegalArgumentException.class,
        () -> new MfaSecretCipher(Base64.getEncoder().encodeToString(new byte[16])));
  }

  @Test
  void keyedEnvelopeReadsLegacyAndAuthenticatesOwnerAndKeyIdentifier() {
    UUID user = UUID.randomUUID();
    byte[] raw = new byte[20];
    Arrays.fill(raw, (byte) 7);
    var cipher = new MfaSecretCipher(key(0), Map.of("a", key(1)));
    assertArrayEquals(raw, cipher.decrypt(user, new MfaSecretCipher(key(0)).encrypt(user, raw)));
    byte[] encrypted = cipher.encrypt(user, raw, "a");
    assertEquals("a", MfaSecretCipher.keyId(encrypted));
    assertArrayEquals(raw, cipher.decrypt(user, encrypted));
    assertThrows(IllegalStateException.class, () -> cipher.decrypt(UUID.randomUUID(), encrypted));
    byte[] renamed = encrypted.clone();
    renamed[2] = 'b';
    assertThrows(
        IllegalStateException.class,
        () -> new MfaSecretCipher(null, Map.of("b", key(1))).decrypt(user, renamed));
    encrypted[encrypted.length - 1] ^= 1;
    assertThrows(IllegalStateException.class, () -> cipher.decrypt(user, encrypted));
  }

  @Test
  void configurationAndMalformedEnvelopeNeverFallBackToAnotherKey() {
    assertThrows(
        IllegalArgumentException.class, () -> new MfaSecretCipher(key(0), Map.of("new", key(0))));
    assertThrows(
        IllegalArgumentException.class,
        () -> new MfaSecretCipher(key(0), Map.of("legacy", key(1))));
    assertThrows(IllegalArgumentException.class, () -> new MfaSecretCipher(null, Map.of()));
    assertThrows(
        IllegalArgumentException.class,
        () -> new MfaSecretCipher(null, Map.of("bad:name", key(1))));
    byte[] invalid = new byte[40];
    invalid[0] = 2;
    invalid[1] = (byte) 255;
    assertThrows(IllegalStateException.class, () -> MfaSecretCipher.keyId(invalid));
    var cipher = new MfaSecretCipher(null, Map.of("new", key(1)));
    byte[] raw = new byte[20];
    assertThrows(
        IllegalStateException.class,
        () ->
            cipher.decrypt(
                UUID.randomUUID(), new MfaSecretCipher(key(0)).encrypt(UUID.randomUUID(), raw)));
  }
}
