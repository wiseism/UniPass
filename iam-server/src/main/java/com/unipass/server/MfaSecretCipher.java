package com.unipass.server;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.spec.*;

/** V1 remains readable; V2 authenticates the key identifier as well as the owner. */
final class MfaSecretCipher {
  static final String LEGACY = "legacy";
  private final Map<String, SecretKeySpec> keys = new HashMap<>();
  private static final SecureRandom RANDOM = new SecureRandom();

  MfaSecretCipher(String legacy) {
    this(legacy, Map.of());
  }

  MfaSecretCipher(String legacy, Map<String, String> ring) {
    if (ring.size() > 16 || ring.containsKey(LEGACY))
      throw new IllegalArgumentException("Invalid factor key ring");
    if (legacy != null && !legacy.isBlank()) add(LEGACY, legacy);
    ring.forEach(this::add);
    if (keys.isEmpty()) throw new IllegalArgumentException("Factor key configuration required");
    if (keys.keySet().stream().map(this::fingerprint).distinct().count() != keys.size())
      throw new IllegalArgumentException("Factor keys must have distinct material");
  }

  private void add(String id, String encoded) {
    if (id == null || !id.matches("[A-Za-z0-9][A-Za-z0-9_-]{0,47}") || encoded == null)
      throw new IllegalArgumentException("Invalid factor key configuration");
    byte[] raw = Base64.getDecoder().decode(encoded);
    try {
      if (raw.length != 32) throw new IllegalArgumentException("Factor key must contain 256 bits");
      keys.put(id, new SecretKeySpec(raw, "AES"));
    } finally {
      Arrays.fill(raw, (byte) 0);
    }
  }

  Set<String> ids() {
    return Set.copyOf(keys.keySet());
  }

  String fingerprint(String id) {
    byte[] raw = key(id).getEncoded();
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));
    } catch (NoSuchAlgorithmException unavailable) {
      throw new IllegalStateException("Digest unavailable");
    } finally {
      Arrays.fill(raw, (byte) 0);
    }
  }

  private SecretKeySpec key(String id) {
    var key = keys.get(id);
    if (key == null) throw new IllegalStateException("Factor key unavailable");
    return key;
  }

  byte[] encrypt(UUID owner, byte[] secret) {
    return encrypt(owner, secret, LEGACY);
  }

  byte[] encrypt(UUID owner, byte[] secret, String id) {
    byte[] iv = new byte[12];
    RANDOM.nextBytes(iv);
    byte[] payload = crypt(Cipher.ENCRYPT_MODE, owner, id, iv, secret);
    if (LEGACY.equals(id))
      return ByteBuffer.allocate(1 + 12 + payload.length)
          .put((byte) 1)
          .put(iv)
          .put(payload)
          .array();
    byte[] name = id.getBytes(StandardCharsets.US_ASCII);
    return ByteBuffer.allocate(2 + name.length + 12 + payload.length)
        .put((byte) 2)
        .put((byte) name.length)
        .put(name)
        .put(iv)
        .put(payload)
        .array();
  }

  static String keyId(byte[] envelope) {
    if (envelope == null || envelope.length < 29)
      throw new IllegalStateException("Invalid factor envelope");
    if (envelope[0] == 1) return LEGACY;
    if (envelope[0] != 2) throw new IllegalStateException("Invalid factor envelope");
    int size = Byte.toUnsignedInt(envelope[1]);
    if (size < 1 || size > 48 || envelope.length < 2 + size + 28)
      throw new IllegalStateException("Invalid factor envelope");
    String id = new String(envelope, 2, size, StandardCharsets.US_ASCII);
    if (LEGACY.equals(id) || !id.matches("[A-Za-z0-9][A-Za-z0-9_-]{0,47}"))
      throw new IllegalStateException("Invalid factor envelope");
    return id;
  }

  byte[] decrypt(UUID owner, byte[] envelope) {
    String id = keyId(envelope);
    int offset = envelope[0] == 1 ? 1 : 2 + Byte.toUnsignedInt(envelope[1]);
    return crypt(
        Cipher.DECRYPT_MODE,
        owner,
        id,
        Arrays.copyOfRange(envelope, offset, offset + 12),
        Arrays.copyOfRange(envelope, offset + 12, envelope.length));
  }

  private byte[] crypt(int mode, UUID owner, String id, byte[] iv, byte[] input) {
    try {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(mode, key(id), new GCMParameterSpec(128, iv));
      String prefix = LEGACY.equals(id) ? "unipass:totp:v1:" : "unipass:totp:v2:" + id + ":";
      cipher.updateAAD((prefix + owner).getBytes(StandardCharsets.US_ASCII));
      return cipher.doFinal(input);
    } catch (Exception unavailable) {
      throw new IllegalStateException("Factor key unavailable or ciphertext invalid");
    }
  }

  @Override
  public String toString() {
    return "MfaSecretCipher[REDACTED]";
  }
}
