package com.unipass.server;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.net.URI;
import java.time.Duration;
import java.util.*;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.client.*;
import org.springframework.security.oauth2.server.authorization.settings.*;

/** Called only by the offline operator CLI or an authorized management boundary. */
public final class ClientRegistrationService {
  public enum Kind {
    CONFIDENTIAL,
    NATIVE,
    SPA
  }

  public record Spec(
      @JsonProperty("client_id") String clientId,
      String name,
      Kind kind,
      @JsonProperty("redirect_uris") List<String> redirects,
      @JsonProperty("post_logout_redirect_uris") List<String> logoutRedirects,
      Set<String> scopes,
      @JsonProperty("backchannel_logout_uri") String backchannel) {
    public Spec(
        String clientId,
        String name,
        Kind kind,
        List<String> redirects,
        List<String> logoutRedirects,
        Set<String> scopes) {
      this(clientId, name, kind, redirects, logoutRedirects, scopes, null);
    }
  }

  private final RegisteredClientRepository clients;
  private final boolean localHttp;

  public ClientRegistrationService(RegisteredClientRepository clients, boolean localHttp) {
    this.clients = clients;
    this.localHttp = localHttp;
  }

  public String register(Spec spec, String secret) {
    if (spec == null
        || spec.clientId() == null
        || !spec.clientId().matches("[A-Za-z0-9_.-]{3,100}")
        || spec.name() == null
        || spec.name().isBlank()
        || spec.name().length() > 200
        || spec.kind() == null
        || spec.redirects() == null
        || spec.redirects().isEmpty()
        || spec.redirects().size() > 10
        || spec.logoutRedirects() == null
        || spec.logoutRedirects().size() > 10
        || spec.scopes() == null
        || !spec.scopes().contains("openid")
        || !Set.of("openid", "profile", "email", "api.read").containsAll(spec.scopes()))
      throw new IllegalArgumentException("Invalid client specification");
    if (clients.findByClientId(spec.clientId()) != null)
      throw new IllegalStateException("Client already registered");
    spec.redirects().forEach(value -> validateRedirect(value, spec.kind()));
    spec.logoutRedirects().forEach(value -> validateRedirect(value, spec.kind()));
    if (spec.backchannel() != null) {
      validateBackchannel(spec.backchannel(), spec.redirects(), spec.kind());
    }
    var builder =
        RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId(spec.clientId())
            .clientName(spec.name())
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .clientSettings(
                ClientSettings.builder()
                    .requireProofKey(true)
                    .requireAuthorizationConsent(false)
                    .setting("unipass.native", spec.kind() == Kind.NATIVE)
                    .setting(
                        "unipass.backchannel_logout_uri",
                        spec.backchannel() == null ? "" : spec.backchannel())
                    .build())
            .tokenSettings(
                TokenSettings.builder()
                    .authorizationCodeTimeToLive(Duration.ofSeconds(60))
                    .accessTokenTimeToLive(Duration.ofHours(1))
                    .refreshTokenTimeToLive(Duration.ofDays(30))
                    .reuseRefreshTokens(false)
                    .build());
    spec.redirects().forEach(builder::redirectUri);
    spec.logoutRedirects().forEach(builder::postLogoutRedirectUri);
    spec.scopes().forEach(builder::scope);
    if (spec.kind() == Kind.CONFIDENTIAL) {
      if (secret == null || !secret.matches("[\\x21-\\x7e]{32,64}"))
        throw new IllegalArgumentException(
            "Client secret must contain 32 to 64 printable ASCII characters");
      builder
          .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
          .clientSecret(PasswordEncoderFactories.createDelegatingPasswordEncoder().encode(secret));
    } else builder.clientAuthenticationMethod(ClientAuthenticationMethod.NONE);
    if (spec.kind() != Kind.SPA)
      builder.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
    RegisteredClient client = builder.build();
    clients.save(client);
    return client.getId();
  }

  private void validateRedirect(String value, Kind kind) {
    if (value == null || value.length() > 1000)
      throw new IllegalArgumentException("Invalid callback URI");
    URI uri = URI.create(value);
    boolean https = "https".equals(uri.getScheme()) && uri.getHost() != null;
    boolean loopback =
        localHttp
            && "http".equals(uri.getScheme())
            && uri.getHost() != null
            && Set.of("127.0.0.1", "localhost", "[::1]").contains(uri.getHost());
    boolean nativeScheme =
        kind == Kind.NATIVE
            && uri.getScheme() != null
            && uri.getScheme().matches("[a-z][a-z0-9-]*(\\.[a-z0-9-]+)+")
            && uri.getPath() != null
            && !uri.getPath().isBlank();
    if (uri.getUserInfo() != null
        || uri.getFragment() != null
        || !(https || loopback || nativeScheme))
      throw new IllegalArgumentException("Invalid callback URI");
  }

  private void validateBackchannel(String value, List<String> callbacks, Kind kind) {
    validateRedirect(value, kind);
    URI uri = URI.create(value);
    if (kind != Kind.CONFIDENTIAL
        || uri.getRawQuery() != null
        || !"/logout/backchannel".equals(uri.getRawPath())
        || callbacks.stream()
            .map(URI::create)
            .noneMatch(
                callback ->
                    Objects.equals(callback.getScheme(), uri.getScheme())
                        && Objects.equals(callback.getRawAuthority(), uri.getRawAuthority())))
      throw new IllegalArgumentException(
          "Back-channel must use a registered confidential callback origin and the fixed logout path");
  }
}
