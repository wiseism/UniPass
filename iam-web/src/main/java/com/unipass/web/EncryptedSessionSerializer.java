package com.unipass.web;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.springframework.data.redis.serializer.*;

/**
 * Encrypts security context, authorization requests and authorized clients, not only access tokens.
 */
public final class EncryptedSessionSerializer implements RedisSerializer<Object> {
  private final RedisSerializer<Object> delegate = new JdkSerializationRedisSerializer();
  private final byte[] key, aad;

  public EncryptedSessionSerializer(String encoded, String namespace) {
    key = Base64.getDecoder().decode(encoded);
    if (key.length != 32)
      throw new IllegalArgumentException("RP session key must contain 32 bytes");
    aad = namespace.getBytes(StandardCharsets.UTF_8);
  }

  @Override
  public byte[] serialize(Object value) {
    if (value == null) return new byte[0];
    byte[] plain = delegate.serialize(value), nonce = new byte[12];
    new SecureRandom().nextBytes(nonce);
    try {
      var cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(
          Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
      cipher.updateAAD(aad);
      return ByteBuffer.allocate(1 + 12 + plain.length + 16)
          .put((byte) 1)
          .put(nonce)
          .put(cipher.doFinal(plain))
          .array();
    } catch (Exception e) {
      throw new SerializationException("RP session encryption failed");
    } finally {
      if (plain != null) Arrays.fill(plain, (byte) 0);
    }
  }

  @Override
  public Object deserialize(byte[] value) {
    if (value == null || value.length == 0) return null;
    byte[] plain = null;
    try {
      if (value.length < 29 || value[0] != 1) throw new IllegalArgumentException();
      var cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(
          Cipher.DECRYPT_MODE,
          new SecretKeySpec(key, "AES"),
          new GCMParameterSpec(128, value, 1, 12));
      cipher.updateAAD(aad);
      plain = cipher.doFinal(value, 13, value.length - 13);
      return delegate.deserialize(plain);
    } catch (Exception e) {
      throw new SerializationException("RP session invalid");
    } finally {
      if (plain != null) Arrays.fill(plain, (byte) 0);
    }
  }
}
