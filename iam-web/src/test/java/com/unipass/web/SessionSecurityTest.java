package com.unipass.web;

import static org.junit.jupiter.api.Assertions.*;

import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.serializer.SerializationException;
import org.springframework.mock.env.MockEnvironment;

class SessionSecurityTest {
  @Test
  void encryptedSessionBindsApplicationAndRejectsTamperingOrWrongKey() {
    String key = Base64.getEncoder().encodeToString(new byte[32]);
    var serializer = new EncryptedSessionSerializer(key, "crm");
    Map<String, String> secret = Map.of("access_token", "test-bearer-credential");
    byte[] value = serializer.serialize(secret);
    assertFalse(
        new String(value, java.nio.charset.StandardCharsets.ISO_8859_1)
            .contains("test-bearer-credential"));
    assertEquals(secret, serializer.deserialize(value));
    assertThrows(
        SerializationException.class,
        () -> new EncryptedSessionSerializer(key, "hr").deserialize(value));
    byte[] changed = value.clone();
    changed[changed.length - 1] ^= 1;
    assertThrows(SerializationException.class, () -> serializer.deserialize(changed));
    byte[] other = new byte[32];
    Arrays.fill(other, (byte) 1);
    assertThrows(
        SerializationException.class,
        () ->
            new EncryptedSessionSerializer(Base64.getEncoder().encodeToString(other), "crm")
                .deserialize(value));
    assertThrows(
        IllegalArgumentException.class, () -> new EncryptedSessionSerializer("a2V5", "crm"));
  }

  private MockEnvironment env() {
    return new MockEnvironment()
        .withProperty("unipass.rp.id", "crm")
        .withProperty("unipass.rp.secret", "x".repeat(32))
        .withProperty("unipass.rp.issuer", "https://iam.example.test")
        .withProperty("unipass.rp.origin", "https://crm.example.test");
  }

  @Test
  void localHttpRequiresExplicitLoopbackAndProductionOriginsAreExact() {
    assertDoesNotThrow(() -> new RpSettings(env()));
    assertThrows(
        IllegalArgumentException.class,
        () -> new RpSettings(env().withProperty("unipass.rp.origin", "http://localhost:8081")));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new RpSettings(
                env().withProperty("unipass.rp.origin", "https://crm.example.test/path")));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new RpSettings(
                env().withProperty("unipass.rp.issuer", "https://name:secret@iam.example.test")));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new RpSettings(
                env()
                    .withProperty("unipass.rp.local-http", "true")
                    .withProperty("server.address", "0.0.0.0")));
    assertDoesNotThrow(
        () ->
            new RpSettings(
                env()
                    .withProperty("unipass.rp.local-http", "true")
                    .withProperty("server.address", "127.0.0.1")
                    .withProperty("unipass.rp.origin", "http://localhost:8081")));
  }
}
