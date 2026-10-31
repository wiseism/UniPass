package com.unipass.server;

/** Raw link is request-scoped, must never be logged or persisted by a delivery adapter. */
public interface RecoveryEmailSender {
  boolean available();

  void send(String recipient, String resetLink);
}
