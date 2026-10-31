package com.unipass.server;

import com.sun.net.httpserver.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/** Owned loopback transport fixture; it never contacts a Feishu tenant. */
final class FeishuFixture implements AutoCloseable {
  static final String APP = "cli_fixture",
      TENANT = "tenant_fixture",
      SECRET = "fixture-secret-not-for-production";
  final HttpServer server;
  private final ExecutorService threads =
      Executors.newFixedThreadPool(
          2,
          r -> {
            var t = new Thread(r, "feishu-fixture");
            t.setDaemon(true);
            return t;
          });
  final AtomicInteger calls = new AtomicInteger();
  volatile Map<String, String> form = Map.of();
  volatile String authorization;
  volatile String tokenBody, userBody, mime;
  volatile int tokenStatus;
  volatile Runnable afterToken, afterHeaders;

  FeishuFixture() throws Exception {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.setExecutor(threads);
    server.createContext(
        "/token",
        exchange -> {
          calls.incrementAndGet();
          form =
              parameters(
                  new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
          afterToken.run();
          reply(exchange, tokenStatus, tokenBody);
        });
    server.createContext(
        "/user",
        exchange -> {
          authorization = exchange.getRequestHeaders().getFirst("Authorization");
          reply(exchange, 200, userBody);
        });
    reset();
    server.start();
  }

  void reset() {
    calls.set(0);
    form = Map.of();
    authorization = null;
    mime = "application/json";
    tokenStatus = 200;
    afterToken = () -> {};
    afterHeaders = () -> {};
    tokenBody =
        "{\"code\":0,\"access_token\":\"fixture-user-token\",\"token_type\":\"Bearer\",\"expires_in\":3600}";
    userBody =
        "{\"code\":0,\"data\":{\"tenant_key\":\"" + TENANT + "\",\"open_id\":\"ou_fixture\"}}";
  }

  FeishuClient client() {
    return client(Duration.ofSeconds(2));
  }

  FeishuClient client(Duration timeout) {
    String base = "http://127.0.0.1:" + server.getAddress().getPort();
    return new FeishuClient(
        APP,
        TENANT,
        SECRET,
        "https://localhost:9999/api/connector/feishu/callback",
        Clock.systemUTC(),
        URI.create(base + "/token"),
        URI.create(base + "/user"),
        timeout);
  }

  private void reply(HttpExchange exchange, int status, String body) throws java.io.IOException {
    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().set("Content-Type", mime);
    exchange.sendResponseHeaders(status, bytes.length);
    afterHeaders.run();
    try (var out = exchange.getResponseBody()) {
      out.write(bytes);
    } finally {
      exchange.close();
    }
  }

  static Map<String, String> parameters(String query) {
    var result = new HashMap<String, String>();
    for (String pair : query.split("&")) {
      String[] parts = pair.split("=", 2);
      result.put(
          URLDecoder.decode(parts[0], StandardCharsets.UTF_8),
          parts.length == 2 ? URLDecoder.decode(parts[1], StandardCharsets.UTF_8) : "");
    }
    return result;
  }

  @Override
  public void close() {
    server.stop(0);
    threads.shutdownNow();
  }
}
