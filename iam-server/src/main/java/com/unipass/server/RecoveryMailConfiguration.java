package com.unipass.server;

import jakarta.mail.internet.InternetAddress;
import java.util.Properties;
import org.springframework.context.annotation.*;
import org.springframework.core.env.Environment;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSenderImpl;

@Configuration
public class RecoveryMailConfiguration {
  @Bean
  RecoveryEmailSender recoveryEmailSender(Environment env) {
    if (!env.getProperty("unipass.recovery.email.enabled", Boolean.class, false))
      return new RecoveryEmailSender() {
        public boolean available() {
          return false;
        }

        public void send(String recipient, String link) {
          throw new IllegalStateException("Email recovery disabled");
        }
      };
    var mail = new JavaMailSenderImpl();
    mail.setHost(env.getRequiredProperty("UNIPASS_SMTP_HOST"));
    mail.setPort(env.getProperty("UNIPASS_SMTP_PORT", Integer.class, 587));
    mail.setUsername(env.getRequiredProperty("UNIPASS_SMTP_USER"));
    mail.setPassword(env.getRequiredProperty("UNIPASS_SMTP_PASSWORD"));
    String from = validatedAddress(env.getRequiredProperty("UNIPASS_SMTP_FROM"));
    Properties options = mail.getJavaMailProperties();
    options.setProperty("mail.smtp.auth", "true");
    options.setProperty("mail.smtp.starttls.enable", "true");
    options.setProperty("mail.smtp.starttls.required", "true");
    options.setProperty("mail.smtp.ssl.checkserveridentity", "true");
    options.setProperty("mail.smtp.connectiontimeout", "3000");
    options.setProperty("mail.smtp.timeout", "5000");
    options.setProperty("mail.smtp.writetimeout", "5000");
    options.setProperty("mail.debug", "false");
    return new RecoveryEmailSender() {
      public boolean available() {
        return true;
      }

      public void send(String recipient, String link) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(validatedAddress(recipient));
        message.setSubject("UniPass password recovery");
        message.setText(
            "Open this link to verify your recovery email. It expires in 10 minutes.\n"
                + link
                + "\nIf you did not request this, ignore it.");
        mail.send(message);
      }
    };
  }

  static String validatedAddress(String address) {
    if (address == null
        || address.length() > 254
        || !address.matches("[\\x21-\\x7e]+")
        || address.contains("\\")
        || address.contains("<")
        || address.contains(">")) throw new IllegalArgumentException("Invalid email address");
    try {
      InternetAddress parsed = new InternetAddress(address, true);
      parsed.validate();
      if (!address.equals(parsed.getAddress()) || !address.contains("@"))
        throw new IllegalArgumentException("Invalid email address");
      return address;
    } catch (jakarta.mail.internet.AddressException e) {
      throw new IllegalArgumentException("Invalid email address");
    }
  }
}
