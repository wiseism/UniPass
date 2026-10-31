package com.unipass.server;

import static org.junit.jupiter.api.Assertions.*;

import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.client.*;

class ClientRegistrationTest {
  private final RegisteredClientRepository clients =
      new InMemoryRegisteredClientRepository(
          RegisteredClient.withId("seed")
              .clientId("seed")
              .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
              .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
              .redirectUri("https://seed.example/cb")
              .scope("openid")
              .build());

  private ClientRegistrationService.Spec spec(
      String id, ClientRegistrationService.Kind kind, String callback) {
    return new ClientRegistrationService.Spec(
        id, "Test application", kind, List.of(callback), List.of(), Set.of("openid", "api.read"));
  }

  @Test
  void confidentialClientStoresHashAndRequiresPkceAndRefreshRotation() {
    String secret = "random-test-only-credential-0123456789";
    var service = new ClientRegistrationService(clients, false);
    service.register(
        spec("crm", ClientRegistrationService.Kind.CONFIDENTIAL, "https://crm.example/cb"), secret);
    var client = clients.findByClientId("crm");
    assertNotEquals(secret, client.getClientSecret());
    assertTrue(
        PasswordEncoderFactories.createDelegatingPasswordEncoder()
            .matches(secret, client.getClientSecret()));
    assertTrue(client.getClientSettings().isRequireProofKey());
    assertFalse(client.getTokenSettings().isReuseRefreshTokens());
    assertTrue(client.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN));
    assertThrows(
        IllegalStateException.class,
        () ->
            service.register(
                spec("crm", ClientRegistrationService.Kind.CONFIDENTIAL, "https://crm.example/cb"),
                secret));
  }

  @Test
  void publicClientKindsHaveDifferentRefreshPolicyAndStrictCallbacks() {
    var service = new ClientRegistrationService(clients, false);
    service.register(
        spec("mobile", ClientRegistrationService.Kind.NATIVE, "com.example.mobile:/oauth/callback"),
        null);
    assertTrue(
        clients
            .findByClientId("mobile")
            .getAuthorizationGrantTypes()
            .contains(AuthorizationGrantType.REFRESH_TOKEN));
    service.register(
        spec("portal", ClientRegistrationService.Kind.SPA, "https://portal.example/callback"),
        null);
    assertFalse(
        clients
            .findByClientId("portal")
            .getAuthorizationGrantTypes()
            .contains(AuthorizationGrantType.REFRESH_TOKEN));
    for (String callback :
        List.of(
            "http://public.example/cb",
            "https://user:pass@rp.example/cb",
            "https://rp.example/cb#fragment",
            "app:/callback"))
      assertThrows(
          IllegalArgumentException.class,
          () ->
              service.register(
                  spec("invalid", ClientRegistrationService.Kind.NATIVE, callback), null));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            service.register(
                spec("weak", ClientRegistrationService.Kind.CONFIDENTIAL, "https://rp.example/cb"),
                "short"));
  }

  @Test
  void backchannelOnlyAllowsAnExplicitConfidentialCallbackOrigin() {
    var service = new ClientRegistrationService(clients, false);
    String secret = "random-test-only-credential-0123456789";
    var valid =
        new ClientRegistrationService.Spec(
            "backchannel",
            "Test",
            ClientRegistrationService.Kind.CONFIDENTIAL,
            List.of("https://crm.example/cb"),
            List.of(),
            Set.of("openid"),
            "https://crm.example/logout/backchannel");
    service.register(valid, secret);
    assertEquals(
        valid.backchannel(),
        clients
            .findByClientId("backchannel")
            .getClientSettings()
            .getSetting("unipass.backchannel_logout_uri"));
    for (String bad :
        List.of(
            "https://other.example/logout/backchannel",
            "https://crm.example/logout/backchannel?target=internal",
            "https://crm.example/logout/other",
            "http://127.0.0.1/logout/backchannel"))
      assertThrows(
          IllegalArgumentException.class,
          () ->
              service.register(
                  new ClientRegistrationService.Spec(
                      "invalid-backchannel",
                      "Test",
                      ClientRegistrationService.Kind.CONFIDENTIAL,
                      valid.redirects(),
                      List.of(),
                      Set.of("openid"),
                      bad),
                  secret));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            service.register(
                new ClientRegistrationService.Spec(
                    "public-backchannel",
                    "Test",
                    ClientRegistrationService.Kind.SPA,
                    valid.redirects(),
                    List.of(),
                    Set.of("openid"),
                    valid.backchannel()),
                null));
  }
}
