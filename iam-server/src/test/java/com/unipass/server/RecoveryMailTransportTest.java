package com.unipass.server;

import static org.junit.jupiter.api.Assertions.*;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.springframework.mail.MailException;
import org.springframework.mock.env.MockEnvironment;

class RecoveryMailTransportTest {
  @Test
  void serverWithoutStartTlsCannotReceiveCredentialsOrRecoveryLink() throws Exception {
    try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
      server.setSoTimeout(6000);
      ExecutorService pool = Executors.newSingleThreadExecutor();
      List<String> commands = new ArrayList<>();
      Future<?> peer =
          pool.submit(
              () -> {
                try (Socket client = server.accept()) {
                  client.setSoTimeout(6000);
                  var input =
                      new BufferedReader(
                          new InputStreamReader(
                              client.getInputStream(), StandardCharsets.US_ASCII));
                  var output =
                      new PrintWriter(
                          new OutputStreamWriter(
                              client.getOutputStream(), StandardCharsets.US_ASCII),
                          true);
                  output.print("220 localhost SMTP\r\n");
                  output.flush();
                  String line;
                  while ((line = input.readLine()) != null) {
                    commands.add(line);
                    if (line.startsWith("EHLO") || line.startsWith("HELO")) {
                      output.print("250 localhost\r\n");
                      output.flush();
                    } else if (line.startsWith("QUIT")) {
                      output.print("221 bye\r\n");
                      output.flush();
                      break;
                    } else {
                      output.print("500 unavailable\r\n");
                      output.flush();
                    }
                  }
                } catch (IOException e) {
                  throw new UncheckedIOException(e);
                }
              });
      try {
        var env =
            new MockEnvironment()
                .withProperty("unipass.recovery.email.enabled", "true")
                .withProperty("UNIPASS_SMTP_HOST", server.getInetAddress().getHostAddress())
                .withProperty("UNIPASS_SMTP_PORT", Integer.toString(server.getLocalPort()))
                .withProperty("UNIPASS_SMTP_USER", "test-user")
                .withProperty("UNIPASS_SMTP_PASSWORD", "test-only-smtp-password")
                .withProperty("UNIPASS_SMTP_FROM", "iam@example.test");
        var sender = new RecoveryMailConfiguration().recoveryEmailSender(env);
        assertThrows(
            MailException.class,
            () -> sender.send("user@example.test", "https://iam.example/reset#token=test-proof"));
        peer.get(8, TimeUnit.SECONDS);
        assertTrue(commands.stream().anyMatch(line -> line.startsWith("EHLO")));
        assertTrue(
            commands.stream()
                .noneMatch(
                    line ->
                        line.startsWith("AUTH")
                            || line.startsWith("MAIL")
                            || line.startsWith("DATA")
                            || line.contains("test-proof")));
      } finally {
        pool.shutdownNow();
      }
    }
  }

  @Test
  void invalidMailAddressesAndDisabledTransportAreRejected() {
    for (String address :
        List.of(
            "user@example.test\r\nBcc:other@example.test",
            "Person <user@example.test>",
            "user@example.test,other@example.test",
            "not-an-address"))
      assertThrows(
          IllegalArgumentException.class,
          () -> RecoveryMailConfiguration.validatedAddress(address));
    assertEquals(
        "verified@example.test",
        RecoveryMailConfiguration.validatedAddress("verified@example.test"));
    assertFalse(
        new RecoveryMailConfiguration().recoveryEmailSender(new MockEnvironment()).available());
  }
}
