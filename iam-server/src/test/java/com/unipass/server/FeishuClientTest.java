package com.unipass.server;

import static org.junit.jupiter.api.Assertions.*;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.*;

class FeishuClientTest {
  private FeishuFixture remote;

  @BeforeEach
  void start() throws Exception {
    remote = new FeishuFixture();
  }

  @AfterEach
  void stop() {
    remote.close();
  }

  @Test
  void authorizationAndV3ExchangeUseMatchingS256WithoutExposingTokens() throws Exception {
    var client = remote.client();
    String state = "s".repeat(43);
    URI authorize = URI.create(client.authorization(state));
    assertEquals(FeishuClient.AUTHORIZE, authorize.toString().split("\\?")[0]);
    var params = FeishuFixture.parameters(authorize.getRawQuery());
    assertEquals("S256", params.get("code_challenge_method"));
    assertEquals(state, params.get("state"));
    assertFalse(params.containsKey("scope"));
    assertFalse(authorize.toString().contains(FeishuFixture.SECRET));
    var identity = client.exchange("one_time_code", state);
    assertEquals(FeishuFixture.TENANT, identity.tenant());
    assertEquals("ou_fixture", identity.openId());
    assertEquals("authorization_code", remote.form.get("grant_type"));
    assertEquals(FeishuFixture.APP, remote.form.get("client_id"));
    assertEquals(FeishuFixture.SECRET, remote.form.get("client_secret"));
    assertEquals(params.get("redirect_uri"), remote.form.get("redirect_uri"));
    assertEquals("one_time_code", remote.form.get("code"));
    String verifier = remote.form.get("code_verifier");
    assertTrue(verifier.matches("[A-Za-z0-9_-]{43}"));
    assertEquals(
        params.get("code_challenge"),
        Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(
                MessageDigest.getInstance("SHA-256")
                    .digest(verifier.getBytes(StandardCharsets.US_ASCII))));
    assertEquals("Bearer fixture-user-token", remote.authorization);
    assertEquals(1, remote.calls.get());
    assertFalse(identity.toString().contains("ou_fixture"));
  }

  @Test
  void malformedOrAmbiguousResponsesAndUnknownTokenTypeFailClosed() {
    for (String body :
        List.of(
            "{\"code\":0,\"code\":0}",
            "{\"code\":0} {}",
            "{\"code\":4294967296}",
            "{\"code\":0,\"access_token\":\"a\",\"token_type\":\"MAC\",\"expires_in\":3600}",
            "{\"code\":0,\"access_token\":\"a\",\"token_type\":\"Bearer\",\"expires_in\":0}")) {
      remote.tokenBody = body;
      assertThrows(
          FeishuClient.Failure.class, () -> remote.client().exchange("code", "s".repeat(43)));
      assertNull(remote.authorization);
    }
    remote.reset();
    remote.mime = "text/html";
    assertEquals(
        502,
        assertThrows(FeishuClient.Failure.class, () -> remote.client().exchange("code", "s"))
            .status());
  }

  @Test
  void tenantMismatchAndPlatformErrorsCannotAuthenticate() {
    remote.userBody =
        "{\"code\":0,\"data\":{\"tenant_key\":\"another\",\"open_id\":\"ou_fixture\"}}";
    assertEquals(
        401,
        assertThrows(FeishuClient.Failure.class, () -> remote.client().exchange("code", "s"))
            .status());
    remote.reset();
    remote.userBody = "{\"code\":20021,\"msg\":\"sensitive_remote_details\"}";
    assertEquals(
        "Feishu identity unavailable",
        assertThrows(FeishuClient.Failure.class, () -> remote.client().exchange("code", "s"))
            .getMessage());
  }

  @Test
  void failuresAndRedirectsAreNeverRetried() {
    for (int status : List.of(429, 500, 302)) {
      remote.reset();
      remote.tokenStatus = status;
      assertEquals(
          status == 429 ? 429 : status == 500 ? 503 : 401,
          assertThrows(FeishuClient.Failure.class, () -> remote.client().exchange("code", "s"))
              .status());
      assertEquals(1, remote.calls.get());
      assertNull(remote.authorization);
    }
  }

  @Test
  void responseBodyHasSizeAndTotalTimeBounds() throws Exception {
    remote.tokenBody = "x".repeat(65537);
    assertThrows(FeishuClient.Failure.class, () -> remote.client().exchange("code", "s"));
    remote.reset();
    var release = new CountDownLatch(1);
    remote.afterHeaders =
        () -> {
          try {
            release.await(5, TimeUnit.SECONDS);
          } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
          }
        };
    try {
      assertTimeoutPreemptively(
          Duration.ofSeconds(3),
          () ->
              assertEquals(
                  503,
                  assertThrows(
                          FeishuClient.Failure.class,
                          () -> remote.client(Duration.ofMillis(300)).exchange("code", "s"))
                      .status()));
    } finally {
      release.countDown();
    }
    assertEquals(1, remote.calls.get());
  }
}
