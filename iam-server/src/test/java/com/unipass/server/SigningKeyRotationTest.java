package com.unipass.server;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.*;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import java.nio.file.*;
import java.security.KeyStore;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;

class SigningKeyRotationTest {
  @TempDir static Path directory;
  private static Path bundle;
  private static final String PASSWORD = "test-only-rotation-password";

  @BeforeAll
  static void keys() throws Exception {
    bundle = directory.resolve("overlap.p12");
    generate(bundle, "first", 2048);
    generate(bundle, "next", 2048);
  }

  private static void generate(Path store, String alias, int bits) throws Exception {
    Path log = directory.resolve(alias + "-keytool.log");
    Process process =
        new ProcessBuilder(
                Path.of(
                        System.getProperty("java.home"),
                        "bin",
                        System.getProperty("os.name").startsWith("Windows")
                            ? "keytool.exe"
                            : "keytool")
                    .toString(),
                "-genkeypair",
                "-alias",
                alias,
                "-keyalg",
                "RSA",
                "-keysize",
                Integer.toString(bits),
                "-validity",
                "30",
                "-dname",
                "CN=UniPass Signing Test",
                "-storetype",
                "PKCS12",
                "-keystore",
                store.toString(),
                "-storepass",
                PASSWORD,
                "-noprompt")
            .redirectErrorStream(true)
            .redirectOutput(log.toFile())
            .start();
    try {
      assertTrue(process.waitFor(20, TimeUnit.SECONDS));
      assertEquals(0, process.exitValue(), Files.readString(log));
    } finally {
      if (process.isAlive()) process.destroyForcibly();
    }
  }

  private JWKSource<SecurityContext> keys(Path store, String alias) throws Exception {
    var env =
        new MockEnvironment()
            .withProperty("unipass.signing.store", store.toString())
            .withProperty("unipass.signing.password", PASSWORD)
            .withProperty("unipass.signing.alias", alias);
    return new CoreConfiguration().signingKeys(env);
  }

  private String token(JWKSource<SecurityContext> keys, String kid) {
    Instant now = Instant.now();
    return new NimbusJwtEncoder(keys)
        .encode(
            JwtEncoderParameters.from(
                JwsHeader.with(SignatureAlgorithm.RS256).keyId(kid).build(),
                JwtClaimsSet.builder()
                    .issuer("https://issuer.example.test")
                    .subject("rotation-test")
                    .issuedAt(now)
                    .expiresAt(now.plusSeconds(60))
                    .build()))
        .getTokenValue();
  }

  private JwtDecoder decoder(JWKSource<SecurityContext> keys) {
    var processor = new DefaultJWTProcessor<SecurityContext>();
    processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, keys));
    return new NimbusJwtDecoder(processor);
  }

  @Test
  void overlapPublishesBothPublicKeysSignsOnlyCurrentAndRejectsRetiredKey() throws Exception {
    var first = keys(bundle, "first");
    String old = token(first, "first");
    var rotated = keys(bundle, "next");
    String next = token(rotated, "next");
    assertEquals("rotation-test", decoder(rotated).decode(old).getSubject());
    assertEquals("rotation-test", decoder(rotated).decode(next).getSubject());
    List<JWK> exposed = rotated.get(new JWKSelector(new JWKMatcher.Builder().build()), null);
    assertEquals(1, exposed.stream().filter(JWK::isPrivate).count());
    JWKSet publicKeys = new JWKSet(exposed).toPublicJWKSet();
    assertEquals(
        Set.of("first", "next"),
        publicKeys.getKeys().stream()
            .map(JWK::getKeyID)
            .collect(java.util.stream.Collectors.toSet()));
    assertTrue(publicKeys.getKeys().stream().noneMatch(key -> key.toJSONObject().containsKey("d")));
    assertThrows(JwtEncodingException.class, () -> token(rotated, "first"));
    KeyStore source = KeyStore.getInstance("PKCS12");
    try (var input = Files.newInputStream(bundle)) {
      source.load(input, PASSWORD.toCharArray());
    }
    KeyStore retired = KeyStore.getInstance("PKCS12");
    retired.load(null, PASSWORD.toCharArray());
    retired.setKeyEntry(
        "next",
        source.getKey("next", PASSWORD.toCharArray()),
        PASSWORD.toCharArray(),
        source.getCertificateChain("next"));
    Path store = directory.resolve("retired.p12");
    try (var output = Files.newOutputStream(store)) {
      retired.store(output, PASSWORD.toCharArray());
    }
    var afterRetirement = keys(store, "next");
    assertThrows(JwtException.class, () -> decoder(afterRetirement).decode(old));
    assertEquals("rotation-test", decoder(afterRetirement).decode(next).getSubject());
  }

  @Test
  void missingOrWeakSigningKeyFailsDuringConfiguration() throws Exception {
    assertThrows(IllegalArgumentException.class, () -> keys(bundle, "missing"));
    Path weak = directory.resolve("weak.p12");
    generate(weak, "weak", 1024);
    assertThrows(IllegalArgumentException.class, () -> keys(weak, "weak"));
  }
}
