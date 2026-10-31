package com.unipass.server;

import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.unipass.directory.*;
import com.unipass.identity.Database;
import com.unipass.password.*;
import java.net.URI;
import java.nio.file.*;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.util.*;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.*;
import org.springframework.core.env.Environment;
import org.springframework.session.web.http.*;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@Configuration
public class CoreConfiguration {
  @Bean
  Clock clock() {
    return Clock.systemUTC();
  }

  @Bean
  TransactionTemplate transactions(PlatformTransactionManager manager) {
    TransactionTemplate tx = new TransactionTemplate(manager);
    tx.setTimeout(10);
    return tx;
  }

  @Bean
  Database database(Environment env) {
    return new Database(
        env.getRequiredProperty("spring.datasource.url"),
        env.getRequiredProperty("spring.datasource.username"),
        env.getRequiredProperty("spring.datasource.password"));
  }

  @Bean
  @ConditionalOnProperty(
      name = "unipass.directory.enabled",
      havingValue = "true",
      matchIfMissing = true)
  DirectoryGateway directory(Environment env) {
    return new LdapDirectoryGateway(
        new DirectoryConfig(
            URI.create(env.getRequiredProperty("UNIPASS_LDAP_URL")),
            env.getRequiredProperty("UNIPASS_LDAP_BASE_DN"),
            env.getRequiredProperty("UNIPASS_LDAP_READ_DN"),
            env.getRequiredProperty("UNIPASS_LDAP_READ_PASSWORD"),
            env.getProperty("UNIPASS_LDAP_WRITE_DN"),
            env.getProperty("UNIPASS_LDAP_WRITE_PASSWORD"),
            DirectoryConfig.Type.valueOf(env.getRequiredProperty("UNIPASS_DIRECTORY_TYPE")),
            env.getProperty("UNIPASS_LDAP_WRITABLE_CONFIRMED", Boolean.class, false)));
  }

  @Bean
  PasswordChangeService passwords(
      Database db, DirectoryGateway directory, Clock clock, Environment env) {
    return new PasswordChangeService(
        db,
        directory,
        PasswordPolicy.defaults(),
        clock,
        env.getProperty("unipass.password.history-verified", Boolean.class, false),
        env.getProperty("unipass.password.reset-history-verified", Boolean.class, false),
        (connection, actor) -> {
          try (var statement =
              connection.prepareStatement(
                  "SELECT EXISTS(SELECT 1 FROM iam_login WHERE id=? AND user_id=? AND auth_epoch=? AND revoked_at IS NULL)")) {
            statement.setObject(1, actor.loginId());
            statement.setObject(2, actor.userId());
            statement.setLong(3, actor.authEpoch());
            try (var rows = statement.executeQuery()) {
              if (!rows.next() || !rows.getBoolean(1))
                throw new PasswordFailure(PasswordFailure.Code.STALE_SESSION);
            }
          }
        });
  }

  @Bean
  CookieSerializer cookieSerializer(Environment env) {
    DefaultCookieSerializer cookie = new DefaultCookieSerializer();
    cookie.setCookieName("UNIPASS_SSO");
    cookie.setUseHttpOnlyCookie(true);
    cookie.setUseSecureCookie(!env.getProperty("unipass.local-http", Boolean.class, false));
    cookie.setSameSite("Lax");
    cookie.setCookiePath("/");
    return cookie;
  }

  @Bean
  JWKSource<SecurityContext> signingKeys(Environment env) throws Exception {
    String alias = env.getRequiredProperty("unipass.signing.alias");
    char[] password = env.getRequiredProperty("unipass.signing.password").toCharArray();
    try {
      KeyStore store = KeyStore.getInstance("PKCS12");
      try (var input =
          Files.newInputStream(Path.of(env.getRequiredProperty("unipass.signing.store")))) {
        store.load(input, password);
      }
      List<JWK> keys = new ArrayList<>();
      for (String name : Collections.list(store.aliases())) {
        var certificate = store.getCertificate(name);
        if (certificate == null || !(certificate.getPublicKey() instanceof RSAPublicKey pub))
          continue;
        if (pub.getModulus().bitLength() < 2048)
          throw new IllegalArgumentException("Signing RSA key must contain at least 2048 bits");
        RSAKey.Builder builder =
            new RSAKey.Builder(pub)
                .keyID(name)
                .algorithm(com.nimbusds.jose.JWSAlgorithm.RS256)
                .keyUse(KeyUse.SIGNATURE);
        if (name.equals(alias)) builder.privateKey((RSAPrivateKey) store.getKey(name, password));
        keys.add(builder.build());
      }
      if (keys.stream().noneMatch(k -> k.getKeyID().equals(alias) && k.isPrivate()))
        throw new IllegalArgumentException("Signing alias missing");
      JWKSet set = new JWKSet(keys);
      return (selector, context) -> selector.select(set);
    } finally {
      Arrays.fill(password, '\0');
    }
  }
}
