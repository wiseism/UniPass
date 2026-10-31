package com.unipass.server;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.*;
import java.io.ByteArrayOutputStream;
import java.net.*;
import java.net.http.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.Flow;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Fixed-origin OAuth v3 client. No access/refresh token leaves this object. */
final class FeishuClient {
  static final String AUTHORIZE = "https://accounts.feishu.cn/open-apis/authen/v1/authorize";
  private final String app, tenant, secret, callback;
  private final URI tokenUri, userUri;
  private final Clock clock;
  private final Duration timeout;
  private final ObjectMapper json =
      new ObjectMapper()
          .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
          .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
  private final HttpClient http =
      HttpClient.newBuilder()
          .connectTimeout(Duration.ofSeconds(2))
          .followRedirects(HttpClient.Redirect.NEVER)
          .build();

  record Identity(String tenant, String openId) {
    @Override
    public String toString() {
      return "FeishuIdentity[REDACTED]";
    }
  }

  static final class Failure extends RuntimeException {
    private final int status;

    Failure(int status) {
      super("Feishu identity unavailable");
      this.status = status;
    }

    int status() {
      return status;
    }
  }

  FeishuClient(String app, String tenant, String secret, String callback, Clock clock) {
    this(
        app,
        tenant,
        secret,
        callback,
        clock,
        URI.create("https://accounts.feishu.cn/oauth/v3/token"),
        URI.create("https://open.feishu.cn/open-apis/authen/v1/user_info"),
        Duration.ofSeconds(3));
  }

  // Explicit loopback constructor is test-only; production URLs have no environment override.
  FeishuClient(
      String app,
      String tenant,
      String secret,
      String callback,
      Clock clock,
      URI tokenUri,
      URI userUri,
      Duration timeout) {
    if (!app.matches("[A-Za-z0-9_-]{3,128}")
        || !tenant.matches("[A-Za-z0-9_-]{1,128}")
        || secret.length() < 16
        || secret.length() > 512)
      throw new IllegalArgumentException("Invalid connector configuration");
    this.app = app;
    this.tenant = tenant;
    this.secret = secret;
    this.callback = callback;
    this.clock = clock;
    this.tokenUri = tokenUri;
    this.userUri = userUri;
    this.timeout = timeout;
  }

  String app() {
    return app;
  }

  String tenant() {
    return tenant;
  }

  static String encode(String value) {
    return URLEncoder.encode(value, StandardCharsets.UTF_8);
  }

  private String verifier(String state) {
    try {
      var mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
      return Base64.getUrlEncoder()
          .withoutPadding()
          .encodeToString(
              mac.doFinal(
                  ("unipass:feishu:pkce:v1:" + app + ":" + tenant + ":" + state)
                      .getBytes(StandardCharsets.UTF_8)));
    } catch (java.security.GeneralSecurityException failure) {
      throw new IllegalStateException("PKCE unavailable");
    }
  }

  String authorization(String state) {
    String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(sha(verifier(state)));
    return AUTHORIZE
        + "?client_id="
        + encode(app)
        + "&response_type=code&redirect_uri="
        + encode(callback)
        + "&state="
        + encode(state)
        + "&code_challenge_method=S256&code_challenge="
        + challenge;
  }

  Identity exchange(String code, String state) {
    try {
      var body =
          Map.of(
              "grant_type",
              "authorization_code",
              "client_id",
              app,
              "client_secret",
              secret,
              "code",
              code,
              "redirect_uri",
              callback,
              "code_verifier",
              verifier(state));
      String form =
          body.entrySet().stream()
              .map(entry -> encode(entry.getKey()) + "=" + encode(entry.getValue()))
              .collect(java.util.stream.Collectors.joining("&"));
      Instant started = clock.instant();
      JsonNode token =
          send(
              HttpRequest.newBuilder(tokenUri)
                  .timeout(timeout)
                  .header("Content-Type", "application/x-www-form-urlencoded")
                  .POST(HttpRequest.BodyPublishers.ofString(form))
                  .build());
      String access = text(token, "access_token", 8192);
      if (!"Bearer".equals(token.path("token_type").asText())
          || !token.path("expires_in").isIntegralNumber()
          || !token.path("expires_in").canConvertToLong()) throw new Failure(502);
      long seconds = token.path("expires_in").longValue();
      if (seconds <= 0
          || seconds > 86400
          || !started.plusSeconds(seconds).isAfter(clock.instant())
          || access.chars().anyMatch(Character::isWhitespace)) throw new Failure(502);
      JsonNode info =
          send(HttpRequest.newBuilder(userUri)
                  .timeout(timeout)
                  .header("Authorization", "Bearer " + access)
                  .GET()
                  .build())
              .path("data");
      if (!started.plusSeconds(seconds).isAfter(clock.instant())) throw new Failure(401);
      String actualTenant = text(info, "tenant_key", 128), open = text(info, "open_id", 128);
      if (!tenant.equals(actualTenant) || !open.matches("[A-Za-z0-9_-]{1,128}"))
        throw new Failure(401);
      return new Identity(actualTenant, open);
    } catch (Failure failure) {
      throw failure;
    } catch (RuntimeException failure) {
      throw new Failure(502);
    }
  }

  private JsonNode send(HttpRequest request) {
    var pending = http.sendAsync(request, ignored -> new LimitedBody());
    try {
      HttpResponse<byte[]> response = pending.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
      byte[] body = response.body();
      try {
        int status = response.statusCode();
        if (status != 200) throw new Failure(status == 429 ? 429 : status >= 500 ? 503 : 401);
        if (!response
            .headers()
            .firstValue("Content-Type")
            .orElse("")
            .toLowerCase(Locale.ROOT)
            .matches("application/json(?:;.*)?")) throw new Failure(502);
        JsonNode value = json.readTree(body);
        if (value == null
            || !value.isObject()
            || !value.path("code").isIntegralNumber()
            || !value.path("code").canConvertToInt()) throw new Failure(502);
        if (value.path("code").intValue() != 0) throw new Failure(401);
        return value;
      } finally {
        Arrays.fill(body, (byte) 0);
      }
    } catch (InterruptedException interrupted) {
      Thread.currentThread().interrupt();
      throw new Failure(503);
    } catch (Failure failure) {
      throw failure;
    } catch (Exception failure) {
      throw new Failure(503);
    } finally {
      if (!pending.isDone()) pending.cancel(true);
    }
  }

  private static String text(JsonNode value, String field, int max) {
    JsonNode item = value.path(field);
    if (!item.isTextual()
        || item.textValue().isEmpty()
        || item.textValue().length() > max
        || item.textValue().chars().anyMatch(Character::isISOControl)) throw new Failure(502);
    return item.textValue();
  }

  private static byte[] sha(String value) {
    try {
      return java.security.MessageDigest.getInstance("SHA-256")
          .digest(value.getBytes(StandardCharsets.UTF_8));
    } catch (Exception failure) {
      throw new IllegalStateException();
    }
  }

  private static final class LimitedBody implements HttpResponse.BodySubscriber<byte[]> {
    private final CompletableFuture<byte[]> body = new CompletableFuture<>();
    private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    private Flow.Subscription subscription;

    public CompletionStage<byte[]> getBody() {
      return body;
    }

    public void onSubscribe(Flow.Subscription value) {
      subscription = value;
      value.request(1);
    }

    public void onNext(List<ByteBuffer> chunks) {
      for (ByteBuffer chunk : chunks) {
        if (chunk.remaining() > 65536 - bytes.size()) {
          subscription.cancel();
          body.completeExceptionally(new IllegalStateException("Response too large"));
          return;
        }
        while (chunk.hasRemaining()) bytes.write(chunk.get());
      }
      subscription.request(1);
    }

    public void onError(Throwable failure) {
      body.completeExceptionally(failure);
    }

    public void onComplete() {
      body.complete(bytes.toByteArray());
    }
  }

  @Override
  public String toString() {
    return "FeishuClient[REDACTED]";
  }
}
