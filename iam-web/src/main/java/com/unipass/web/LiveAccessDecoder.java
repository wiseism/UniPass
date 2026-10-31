package com.unipass.web;

import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.introspection.*;
import org.springframework.stereotype.Component;

/** Signature/type/audience first; then IAM's live epoch, gate and authorization-family decision. */
@Component
public final class LiveAccessDecoder implements JwtDecoder {
  private final NimbusJwtDecoder signature;
  private final OpaqueTokenIntrospector state;
  private final RpSettings settings;

  public LiveAccessDecoder(RpSettings settings) {
    this.settings = settings;
    signature =
        NimbusJwtDecoder.withJwkSetUri(settings.issuer + "/oauth/jwks")
            .restOperations(RpConfiguration.http())
            .validateType(false)
            .build();
    signature.setJwtValidator(JwtValidators.createDefaultWithIssuer(settings.issuer));
    var rest = RpConfiguration.http();
    rest.getInterceptors()
        .add(
            (request, body, execution) -> {
              request
                  .getHeaders()
                  .setBasicAuth(
                      java.net.URLEncoder.encode(
                          settings.id, java.nio.charset.StandardCharsets.UTF_8),
                      java.net.URLEncoder.encode(
                          settings.secret, java.nio.charset.StandardCharsets.UTF_8));
              return execution.execute(request, body);
            });
    state = new SpringOpaqueTokenIntrospector(settings.issuer + "/oauth/introspect", rest);
  }

  @Override
  public Jwt decode(String raw) {
    Jwt jwt = signature.decode(raw);
    if (!"at+jwt".equals(jwt.getHeaders().get("typ"))
        || !jwt.getAudience().contains(settings.id)
        || !jwt.getAudience().contains("unipass-api")
        || !settings.id.equals(jwt.getClaimAsString("client_id")))
      throw new BadJwtException("Wrong access token context");
    try {
      var current = state.introspect(raw);
      if (!jwt.getSubject().equals(current.getAttribute("sub"))
          || !settings.id.equals(current.getAttribute("client_id")))
        throw new BadJwtException("Inactive credential");
    } catch (BadOpaqueTokenException invalid) {
      throw new BadJwtException("Inactive credential");
    } catch (OAuth2IntrospectionException unavailable) {
      throw new JwtException("Identity state unavailable", unavailable);
    }
    return jwt;
  }
}
