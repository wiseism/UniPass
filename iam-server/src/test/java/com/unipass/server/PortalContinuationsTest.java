package com.unipass.server;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.server.ResponseStatusException;

class PortalContinuationsTest {
  private final AccountState accounts = mock(AccountState.class);
  private final MfaService mfa = mock(MfaService.class);
  private final AtomicReference<Instant> now =
      new AtomicReference<>(Instant.parse("2026-10-22T00:00:00Z"));
  private final Clock clock = mock(Clock.class);
  private final IdentityPrincipal owner =
      new IdentityPrincipal(UUID.randomUUID(), 2, now.get(), List.of("ROLE_USER"));

  private PortalContinuations service() {
    when(clock.instant()).thenAnswer(ignored -> now.get());
    when(accounts.allowed(any(IdentityPrincipal.class))).thenReturn(true);
    return new PortalContinuations(accounts, mfa, clock);
  }

  private MockHttpServletRequest request() {
    var request = new MockHttpServletRequest();
    request.setServletPath("/oauth/authorize");
    request.setParameter("response_type", "code");
    request.setParameter("client_id", "web");
    request.setParameter("redirect_uri", "https://rp.example.test/callback");
    request.setParameter("state", "original-state");
    request.setParameter("code_challenge", "x".repeat(43));
    request.setParameter("code_challenge_method", "S256");
    request.setParameter("return_to", "https://evil.example/steal");
    return request;
  }

  @Test
  void continuationExpiresAtTheExactBoundaryEvenWhileTheLoginRemainsValid() {
    var service = service();
    var request = request();
    when(accounts.mustChange(owner.getUserId())).thenReturn(true);
    UUID id = service.capture(request, owner);
    now.set(now.get().plusSeconds(599));
    assertEquals("/portal/password?continue=" + id, service.resume(request, owner, id));
    now.set(now.get().plusSeconds(1));
    assertEquals(
        400,
        assertThrows(ResponseStatusException.class, () -> service.resume(request, owner, id))
            .getStatusCode()
            .value());
  }

  @Test
  void aDifferentFreshIdentityCannotTakeOverAnExistingBoundRequest() {
    var service = service();
    var request = request();
    UUID id = service.capture(request, owner);
    var stranger = new IdentityPrincipal(UUID.randomUUID(), 0, now.get(), List.of("ROLE_USER"));
    assertThrows(ResponseStatusException.class, () -> service.resume(request, stranger, id));
    assertEquals("/portal/", service.afterLogin(request, stranger));
    assertThrows(ResponseStatusException.class, () -> service.resume(request, owner, id));
  }

  @Test
  void invalidationRetainsOnlyTheValidatedRequestAndRequiresANewLogin() {
    var service = service();
    var request = request();
    UUID id = service.capture(request, owner);
    request.getSession().setAttribute("SPRING_SECURITY_CONTEXT", "old-authentication");
    request.getSession().setAttribute(MfaController.CONTEXT, UUID.randomUUID());
    String previous = request.getSession().getId();
    service.retainAcrossInvalidation(request, owner);
    assertNotEquals(previous, request.getSession().getId());
    assertNull(request.getSession().getAttribute("SPRING_SECURITY_CONTEXT"));
    assertNull(request.getSession().getAttribute(MfaController.CONTEXT));
    var fresh = new IdentityPrincipal(owner.getUserId(), 3, now.get(), List.of("ROLE_USER"));
    String target = service.afterLogin(request, fresh);
    assertTrue(target.startsWith("/oauth/authorize?"));
    assertTrue(target.contains("state=original-state"));
    assertFalse(target.contains("evil.example"));
    assertThrows(ResponseStatusException.class, () -> service.resume(request, fresh, id));
  }

  @Test
  void directAuthorizedNavigationConsumesTheMatchingPendingRequest() {
    var service = service();
    var request = request();
    UUID id = service.capture(request, owner);
    service.authorized(request);
    assertThrows(ResponseStatusException.class, () -> service.resume(request, owner, id));
  }
}
