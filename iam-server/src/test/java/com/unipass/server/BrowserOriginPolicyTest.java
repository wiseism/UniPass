package com.unipass.server;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class BrowserOriginPolicyTest {
  private MockHttpServletRequest request(String method, String path, String... origins) {
    var request = new MockHttpServletRequest(method, path);
    request.setServletPath(path);
    for (String origin : origins) request.addHeader("Origin", origin);
    return request;
  }

  /** Returns true when the request reached the chain; asserts 403 JSON rejection otherwise. */
  private boolean pass(
      boolean protocol, String issuer, String method, String path, String... origins)
      throws Exception {
    var response = new MockHttpServletResponse();
    var chain = new MockFilterChain();
    new BrowserOriginPolicy(issuer)
        .filter(protocol)
        .doFilter(request(method, path, origins), response, chain);
    if (chain.getRequest() != null) return true;
    assertEquals(
        403, response.getStatus(), "unexpected rejection status for " + Arrays.toString(origins));
    assertEquals("{\"error\":\"ORIGIN_REJECTED\"}", response.getContentAsString());
    assertEquals("application/json", response.getContentType());
    return false;
  }

  @Test
  void browserUnsafeRequestsAcceptOnlyTheCanonicalSingleOrigin() throws Exception {
    assertTrue(
        pass(false, "https://iam.example.test", "POST", "/login", "https://iam.example.test"));
    assertTrue(
        pass(
            false,
            "https://iam.example.test",
            "POST",
            "/api/password/change",
            "https://iam.example.test"));
    assertFalse(pass(false, "https://iam.example.test", "POST", "/login", "https://evil.example"));
  }

  @Test
  void missingNullOrDuplicateOriginsAreRejectedBeforeMutation() throws Exception {
    assertFalse(pass(false, "https://iam.example.test", "POST", "/login"));
    // The literal sandboxed-iframe "null" origin is a value, not the absence of Origin.
    assertFalse(pass(false, "https://iam.example.test", "POST", "/login", "null"));
    assertFalse(
        pass(
            false,
            "https://iam.example.test",
            "POST",
            "/login",
            "https://iam.example.test",
            "https://iam.example.test"));
  }

  @Test
  void canonicalOriginDropsSchemeDefaultPortsAndKeepsExplicitPorts() throws Exception {
    assertTrue(
        pass(false, "https://iam.example.test", "POST", "/login", "https://iam.example.test"));
    assertTrue(pass(false, "http://iam.example.test", "POST", "/login", "http://iam.example.test"));
    assertTrue(
        pass(false, "http://localhost:9999", "POST", "/portal/continue", "http://localhost:9999"));
    assertFalse(
        pass(false, "http://localhost:9999", "POST", "/portal/continue", "http://localhost:9998"));
    // Issuers carrying a scheme default port canonicalize to the stripped form; the
    // literal default-port Origin no longer matches the canonical origin.
    assertTrue(
        pass(false, "https://iam.example.test:443", "POST", "/login", "https://iam.example.test"));
    assertFalse(
        pass(
            false,
            "https://iam.example.test:443",
            "POST",
            "/login",
            "https://iam.example.test:443"));
    assertTrue(
        pass(false, "http://iam.example.test:80", "POST", "/login", "http://iam.example.test"));
    assertFalse(
        pass(false, "http://iam.example.test:80", "POST", "/login", "http://iam.example.test:80"));
  }

  @Test
  void safeMethodsAndNonBrowserProtocolEndpointsRemainCompatibleWithoutOrigin() throws Exception {
    assertTrue(pass(false, "https://iam.example.test", "GET", "/login"));
    assertTrue(pass(false, "https://iam.example.test", "HEAD", "/login"));
    // Only /oauth/authorize and /oauth/logout are browser-facing inside the protocol chain.
    assertTrue(pass(true, "https://iam.example.test", "POST", "/oauth/token"));
    assertTrue(pass(true, "https://iam.example.test", "POST", "/oauth/introspect"));
    assertTrue(pass(true, "https://iam.example.test", "POST", "/oauth/revoke"));
    assertTrue(
        pass(
            true,
            "https://iam.example.test",
            "POST",
            "/oauth/authorize",
            "https://iam.example.test"));
    assertFalse(pass(true, "https://iam.example.test", "POST", "/oauth/authorize"));
    assertFalse(
        pass(true, "https://iam.example.test", "POST", "/oauth/logout", "https://evil.example"));
  }
}
