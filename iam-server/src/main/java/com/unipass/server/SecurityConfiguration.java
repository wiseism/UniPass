package com.unipass.server;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.unipass.directory.DirectoryGateway;
import java.net.URI;
import java.time.Clock;
import java.util.*;
import org.springframework.context.annotation.*;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.*;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.web.*;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.transaction.support.TransactionTemplate;

@Configuration
public class SecurityConfiguration {
  @Bean
  org.springframework.security.core.session.SessionRegistry sessionRegistry(
      org.springframework.session.data.redis.RedisIndexedSessionRepository sessions) {
    return new org.springframework.session.security.SpringSessionBackedSessionRegistry<>(sessions);
  }

  @Bean
  RegisteredClientRepository clients(JdbcTemplate jdbc) {
    return new JdbcRegisteredClientRepository(jdbc);
  }

  @Bean
  OAuth2AuthorizationConsentService consents(
      JdbcTemplate jdbc, RegisteredClientRepository clients) {
    return new JdbcOAuth2AuthorizationConsentService(jdbc, clients);
  }

  @Bean
  DigestAuthorizationService authorizations(
      JdbcTemplate jdbc,
      RegisteredClientRepository clients,
      AccountState accounts,
      TransactionTemplate tx) {
    return new DigestAuthorizationService(jdbc, clients, accounts, tx);
  }

  @Bean
  AuthorizationServerSettings endpoints(Environment env) {
    String issuer = env.getRequiredProperty("unipass.issuer");
    URI uri = URI.create(issuer);
    boolean local = env.getProperty("unipass.local-http", Boolean.class, false);
    if (local
        && (!"http".equals(uri.getScheme())
            || !Set.of("localhost", "127.0.0.1", "::1").contains(uri.getHost())
            || !Set.of("localhost", "127.0.0.1", "::1")
                .contains(env.getProperty("server.address", ""))))
      throw new IllegalArgumentException("Local HTTP requires loopback issuer and bind address");
    if (uri.getHost() == null
        || uri.getUserInfo() != null
        || uri.getQuery() != null
        || uri.getFragment() != null
        || !"https".equals(uri.getScheme())
            && !(local
                && "http".equals(uri.getScheme())
                && Set.of("localhost", "127.0.0.1", "::1").contains(uri.getHost())))
      throw new IllegalArgumentException(
          "HTTPS issuer required; HTTP only allowed for explicit loopback development");
    return AuthorizationServerSettings.builder()
        .issuer(issuer)
        .authorizationEndpoint("/oauth/authorize")
        .tokenEndpoint("/oauth/token")
        .jwkSetEndpoint("/oauth/jwks")
        .tokenRevocationEndpoint("/oauth/revoke")
        .tokenIntrospectionEndpoint("/oauth/introspect")
        .oidcUserInfoEndpoint("/oauth/userinfo")
        .oidcLogoutEndpoint("/oauth/logout")
        .build();
  }

  @Bean
  DirectoryAuthenticationProvider directoryAuthentication(
      DirectoryGateway directory,
      AccountState accounts,
      TransactionTemplate tx,
      Clock clock,
      LoginAttemptLimiter limiter) {
    return new DirectoryAuthenticationProvider(directory, accounts, tx, clock, limiter);
  }

  @Bean
  OAuth2TokenCustomizer<JwtEncodingContext> claims(
      AccountState accounts, Environment env, MfaService mfa) {
    return context -> {
      if (!(context.getPrincipal().getPrincipal() instanceof IdentityPrincipal principal))
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
      if (!accounts.allowed(principal) || accounts.mustChange(principal.getUserId()))
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
      if (mfa.recoveryRequired(principal.getUserId())
          || mfa.required(principal) && principal.getMfaAt() == null)
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
      context.getJwsHeader().keyId(env.getRequiredProperty("unipass.signing.alias"));
      context
          .getClaims()
          .subject(principal.getUserId().toString())
          .claim("auth_epoch", principal.getEpoch())
          .claim("unipass_family", context.getAuthorization().getId())
          .claim("amr", principal.getAuthenticationMethods())
          .claim("unipass_auth_method", principal.getAuthenticationMethod().name())
          .claim("unipass_login", principal.getLoginId().toString());
      if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
        context.getJwsHeader().type("at+jwt");
        List<String> audiences =
            new ArrayList<>(List.of(context.getRegisteredClient().getClientId()));
        if (context.getAuthorizedScopes().contains("api.read")) audiences.add("unipass-api");
        context
            .getClaims()
            .audience(audiences)
            .claim("client_id", context.getRegisteredClient().getClientId());
      }
    };
  }

  @Bean
  OAuth2TokenGenerator<?> tokenGenerator(
      JWKSource<SecurityContext> keys,
      OAuth2TokenCustomizer<JwtEncodingContext> claims,
      RegisteredClientRepository clients,
      Clock clock) {
    JwtGenerator jwt = new JwtGenerator(new NimbusJwtEncoder(keys));
    jwt.setJwtCustomizer(claims);
    return new DelegatingOAuth2TokenGenerator(
        jwt, new OAuth2AccessTokenGenerator(), new NativeRefreshSupport(clients, clock));
  }

  @Bean
  JwtDecoder decoder(
      JWKSource<SecurityContext> keys,
      AuthorizationServerSettings settings,
      AccountState accounts,
      JdbcTemplate jdbc) {
    var processor = new com.nimbusds.jwt.proc.DefaultJWTProcessor<SecurityContext>();
    processor.setJWSKeySelector(
        new com.nimbusds.jose.proc.JWSVerificationKeySelector<>(
            com.nimbusds.jose.JWSAlgorithm.RS256, keys));
    processor.setJWSTypeVerifier(
        new com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier<>(
            com.nimbusds.jose.JOSEObjectType.JWT, new com.nimbusds.jose.JOSEObjectType("at+jwt")));
    JwtDecoder delegate = new NimbusJwtDecoder(processor);
    var issuer = JwtValidators.createDefaultWithIssuer(settings.getIssuer());
    return value -> {
      Jwt jwt = delegate.decode(value);
      try {
        if (issuer.validate(jwt).hasErrors()
            || jwt.getClaim("auth_epoch") == null
            || jwt.getClaimAsString("unipass_family") == null
            || !accounts.allowed(
                UUID.fromString(jwt.getSubject()),
                ((Number) jwt.getClaim("auth_epoch")).longValue())
            || !accounts.loginAllowed(
                UUID.fromString(jwt.getSubject()),
                ((Number) jwt.getClaim("auth_epoch")).longValue(),
                UUID.fromString(jwt.getClaimAsString("unipass_login")))
            || "FEISHU".equals(jwt.getClaimAsString("unipass_auth_method"))
                && !accounts.federatedAllowed(
                    UUID.fromString(jwt.getSubject()),
                    ((Number) jwt.getClaim("auth_epoch")).longValue())
            || !Boolean.TRUE.equals(
                jdbc.queryForObject(
                    "SELECT EXISTS(SELECT 1 FROM oauth2_authorization WHERE id=? AND revoked=false AND principal_name=?)",
                    Boolean.class,
                    jwt.getClaimAsString("unipass_family"),
                    jwt.getSubject()))) throw new IllegalArgumentException("Inactive credential");
      } catch (RuntimeException e) {
        throw new BadJwtException("Credential inactive or state unavailable");
      }
      return jwt;
    };
  }

  @Bean
  @Order(1)
  SecurityFilterChain protocol(
      HttpSecurity http,
      DirectoryAuthenticationProvider provider,
      DigestAuthorizationService authorizations,
      RegisteredClientRepository clients,
      AccountState accounts,
      Clock clock,
      TransactionTemplate tx,
      LogoutService logoutService,
      MfaService mfa,
      LoginSessions sessions,
      PortalContinuations continuations,
      BrowserOriginPolicy origins)
      throws Exception {
    var server = OAuth2AuthorizationServerConfigurer.authorizationServer();
    NativeRefreshSupport nativeClients = new NativeRefreshSupport(clients, clock);
    var logoutSuccess =
        new org.springframework.security.oauth2.server.authorization.oidc.web.authentication
            .OidcLogoutAuthenticationSuccessHandler();
    http.securityMatcher(server.getEndpointsMatcher())
        .with(
            server,
            as ->
                as.authorizationService(authorizations)
                    .oidc(
                        oidc ->
                            oidc.providerConfigurationEndpoint(
                                    config ->
                                        config.providerConfigurationCustomizer(
                                            metadata ->
                                                metadata
                                                    .claim("backchannel_logout_supported", true)
                                                    .claim(
                                                        "backchannel_logout_session_supported",
                                                        true)))
                                .userInfoEndpoint(
                                    userinfo ->
                                        userinfo.errorResponseHandler(
                                            (request, response, error) -> {
                                              response.setStatus(401);
                                              response.setContentType("application/json");
                                              response
                                                  .getWriter()
                                                  .write("{\"error\":\"invalid_token\"}");
                                            }))
                                .logoutEndpoint(
                                    logout ->
                                        logout
                                            .logoutResponseHandler(
                                                (request, response, authentication) -> {
                                                  try {
                                                    logoutService.oidc(authentication);
                                                  } catch (RuntimeException e) {
                                                    response.setStatus(503);
                                                    response.setContentType("application/json");
                                                    response
                                                        .getWriter()
                                                        .write(
                                                            "{\"error\":\"temporarily_unavailable\"}");
                                                    return;
                                                  }
                                                  logoutSuccess.onAuthenticationSuccess(
                                                      request, response, authentication);
                                                })
                                            .errorResponseHandler(
                                                (request, response, error) -> {
                                                  response.setStatus(400);
                                                  response.setContentType("application/json");
                                                  response
                                                      .getWriter()
                                                      .write("{\"error\":\"invalid_request\"}");
                                                })))
                    .clientAuthentication(
                        client ->
                            client
                                .authenticationConverter(nativeClients)
                                .authenticationProvider(nativeClients)))
        .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
        .exceptionHandling(
            ex -> ex.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
        .oauth2ResourceServer(resource -> resource.jwt(Customizer.withDefaults()));
    http.requestCache(
        cache ->
            cache.requestCache(
                new org.springframework.security.web.savedrequest.NullRequestCache()));
    http.addFilterBefore(
        origins.filter(true), org.springframework.security.web.csrf.CsrfFilter.class);
    http.addFilterAfter(
        new SessionEpochFilter(accounts, clock, sessions, continuations),
        SecurityContextHolderFilter.class);
    http.addFilterAfter(
        new AuthorizationRequestGuard(clients, accounts, mfa, continuations),
        SessionEpochFilter.class);
    http.addFilterAfter(new TokenTransactionFilter(tx), AuthorizationRequestGuard.class);
    return http.build();
  }

  @Bean
  @Order(2)
  SecurityFilterChain resource(HttpSecurity http, JwtDecoder decoder) throws Exception {
    JwtDecoder api =
        raw -> {
          Jwt jwt = decoder.decode(raw);
          if (!jwt.getAudience().contains("unipass-api")
              || !"at+jwt".equals(jwt.getHeaders().get("typ")))
            throw new BadJwtException("Wrong resource audience");
          return jwt;
        };
    http.securityMatcher("/api/resource/**")
        .authorizeHttpRequests(auth -> auth.anyRequest().hasAuthority("SCOPE_api.read"))
        .sessionManagement(
            session ->
                session.sessionCreationPolicy(
                    org.springframework.security.config.http.SessionCreationPolicy.STATELESS))
        .csrf(csrf -> csrf.disable())
        .oauth2ResourceServer(resource -> resource.jwt(jwt -> jwt.decoder(api)));
    return http.build();
  }

  @Bean
  @Order(3)
  SecurityFilterChain browser(
      HttpSecurity http,
      DirectoryAuthenticationProvider provider,
      AccountState accounts,
      Clock clock,
      LogoutService logoutService,
      LoginSessions sessions,
      PortalContinuations continuations,
      BrowserOriginPolicy origins)
      throws Exception {
    http.authenticationProvider(provider)
        .authorizeHttpRequests(
            auth ->
                auth.requestMatchers(
                        "/login",
                        "/error",
                        "/api/public/csrf",
                        "/api/password/reset/**",
                        "/",
                        "/reset",
                        "/portal/",
                        "/portal/mfa",
                        "/portal/password",
                        "/portal/factors",
                        "/portal/sessions",
                        "/portal/binding",
                        "/portal/assets/**",
                        "/api/connector/feishu/login/start",
                        "/api/connector/feishu/callback")
                    .permitAll()
                    .anyRequest()
                    .authenticated())
        .requestCache(
            cache ->
                cache.requestCache(
                    new org.springframework.security.web.savedrequest.NullRequestCache()))
        .exceptionHandling(
            errors ->
                errors.defaultAuthenticationEntryPointFor(
                    (request, response, error) -> {
                      response.setStatus(401);
                      response.setContentType("application/json");
                      response.getWriter().write("{\"error\":\"AUTHENTICATION_REQUIRED\"}");
                    },
                    request -> request.getServletPath().startsWith("/api/")))
        .formLogin(
            login ->
                login
                    .loginPage("/login")
                    .failureUrl("/login?error")
                    .successHandler(
                        (request, response, authentication) ->
                            response.sendRedirect(
                                continuations.afterLogin(
                                    request, (IdentityPrincipal) authentication.getPrincipal()))))
        .logout(
            logout ->
                logout
                    .logoutSuccessUrl("/login?logout")
                    .addLogoutHandler(
                        (request, response, authentication) ->
                            logoutService.browser(authentication)));
    http.headers(
        headers ->
            headers.referrerPolicy(
                policy ->
                    policy.policy(
                        org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter
                            .ReferrerPolicy.SAME_ORIGIN)));
    http.headers(
        headers ->
            headers.contentSecurityPolicy(
                policy ->
                    policy.policyDirectives(
                        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")));
    http.addFilterBefore(
        origins.filter(false), org.springframework.security.web.csrf.CsrfFilter.class);
    http.addFilterAfter(
        new SessionEpochFilter(accounts, clock, sessions, continuations),
        SecurityContextHolderFilter.class);
    return http.build();
  }
}
