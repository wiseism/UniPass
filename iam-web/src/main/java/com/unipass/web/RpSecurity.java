package com.unipass.web;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.context.annotation.*;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.*;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenValidator;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.*;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.web.*;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.oidc.*;
import org.springframework.security.oauth2.core.oidc.user.*;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.web.*;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.web.context.request.*;
import org.springframework.web.filter.OncePerRequestFilter;

@Configuration
public class RpSecurity {
  @Bean
  JwtDecoderFactory<ClientRegistration> idDecoders() {
    Map<String, JwtDecoder> cache = new ConcurrentHashMap<>();
    return registration ->
        cache.computeIfAbsent(
            registration.getRegistrationId(),
            id -> {
              var decoder =
                  NimbusJwtDecoder.withJwkSetUri(registration.getProviderDetails().getJwkSetUri())
                      .restOperations(RpConfiguration.http())
                      .build();
              decoder.setJwtValidator(
                  new DelegatingOAuth2TokenValidator<>(
                      JwtValidators.createDefaultWithIssuer(
                          registration.getProviderDetails().getIssuerUri()),
                      new OidcIdTokenValidator(registration)));
              return decoder;
            });
  }

  @Bean
  OAuth2AuthorizedClientManager manager(
      ClientRegistrationRepository clients,
      OAuth2AuthorizedClientRepository repository,
      JwtDecoderFactory<ClientRegistration> decoders,
      StringRedisTemplate redis,
      RpSettings settings) {
    var delegate = new DefaultRefreshTokenTokenResponseClient();
    delegate.setRestOperations(RpConfiguration.oauthHttp());
    OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> refresh =
        request -> {
          // Burn an attempt before the network call. Even a stalled request outliving its
          // session lease must never replay the same rotated refresh credential.
          String digest;
          try {
            digest =
                HexFormat.of()
                    .formatHex(
                        MessageDigest.getInstance("SHA-256")
                            .digest(
                                request
                                    .getRefreshToken()
                                    .getTokenValue()
                                    .getBytes(StandardCharsets.UTF_8)));
          } catch (Exception unavailable) {
            throw new OAuth2AuthorizationException(new OAuth2Error("temporarily_unavailable"));
          }
          if (!Boolean.TRUE.equals(
              redis
                  .opsForValue()
                  .setIfAbsent(
                      settings.namespace + ":refresh-attempt:" + digest,
                      "used",
                      Duration.ofDays(31))))
            throw new OAuth2AuthorizationException(new OAuth2Error("invalid_grant"));
          var result = delegate.getTokenResponse(request);
          Object raw = result.getAdditionalParameters().get("id_token");
          var current = SecurityContextHolder.getContext().getAuthentication();
          if (!(raw instanceof String token)
              || !(current instanceof OAuth2AuthenticationToken login)
              || !(login.getPrincipal() instanceof OidcUser user))
            throw new OAuth2AuthorizationException(new OAuth2Error("invalid_grant"));
          Jwt jwt = decoders.createDecoder(request.getClientRegistration()).decode(token);
          if (!user.getSubject().equals(jwt.getSubject())
              || !Objects.equals(
                  user.getIdToken().getClaim("auth_epoch"), jwt.getClaim("auth_epoch"))
              || !Objects.equals(user.getIdToken().getClaim("sid"), jwt.getClaim("sid")))
            throw new OAuth2AuthorizationException(new OAuth2Error("invalid_grant"));
          var next =
              new DefaultOidcUser(
                  user.getAuthorities(),
                  new OidcIdToken(token, jwt.getIssuedAt(), jwt.getExpiresAt(), jwt.getClaims()),
                  user.getUserInfo(),
                  "sub");
          var context = SecurityContextHolder.createEmptyContext();
          context.setAuthentication(
              new OAuth2AuthenticationToken(
                  next, login.getAuthorities(), login.getAuthorizedClientRegistrationId()));
          SecurityContextHolder.setContext(context);
          var servlet = (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
          new HttpSessionSecurityContextRepository()
              .saveContext(context, servlet.getRequest(), servlet.getResponse());
          return result;
        };
    var manager = new DefaultOAuth2AuthorizedClientManager(clients, repository);
    manager.setAuthorizedClientProvider(
        OAuth2AuthorizedClientProviderBuilder.builder()
            .authorizationCode()
            .refreshToken(
                config ->
                    config.clockSkew(Duration.ofSeconds(30)).accessTokenResponseClient(refresh))
            .build());
    return manager;
  }

  @Bean
  @Order(1)
  SecurityFilterChain api(HttpSecurity http, LiveAccessDecoder decoder) throws Exception {
    http.securityMatcher("/api/resource/**")
        .authorizeHttpRequests(auth -> auth.anyRequest().hasAuthority("SCOPE_api.read"))
        .sessionManagement(
            session ->
                session.sessionCreationPolicy(
                    org.springframework.security.config.http.SessionCreationPolicy.STATELESS))
        .csrf(csrf -> csrf.disable())
        .oauth2ResourceServer(
            resource ->
                resource
                    .jwt(jwt -> jwt.decoder(decoder))
                    .authenticationEntryPoint(
                        (request, response, error) ->
                            response.setStatus(
                                error instanceof AuthenticationServiceException ? 503 : 401))
                    .withObjectPostProcessor(
                        new org.springframework.security.config.ObjectPostProcessor<
                            org.springframework.security.oauth2.server.resource.web.authentication
                                .BearerTokenAuthenticationFilter>() {
                          @Override
                          public <
                                  O extends
                                      org.springframework.security.oauth2.server.resource.web
                                              .authentication.BearerTokenAuthenticationFilter>
                              O postProcess(O filter) {
                            filter.setAuthenticationFailureHandler(
                                (request, response, error) ->
                                    response.setStatus(
                                        error instanceof AuthenticationServiceException
                                            ? 503
                                            : 401));
                            return filter;
                          }
                        }));
    return http.build();
  }

  @Bean
  @Order(2)
  SecurityFilterChain backchannel(HttpSecurity http) throws Exception {
    http.securityMatcher("/logout/backchannel")
        .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
        .csrf(csrf -> csrf.disable())
        .sessionManagement(
            session ->
                session.sessionCreationPolicy(
                    org.springframework.security.config.http.SessionCreationPolicy.STATELESS));
    return http.build();
  }

  @Bean
  @Order(3)
  SecurityFilterChain browser(
      HttpSecurity http,
      ClientRegistrationRepository clients,
      OAuth2AuthorizedClientRepository repository,
      OAuth2AuthorizedClientManager manager,
      LiveAccessDecoder decoder,
      RpSettings settings,
      BackchannelSessions sessions)
      throws Exception {
    var resolver = new DefaultOAuth2AuthorizationRequestResolver(clients, "/oauth2/authorization");
    resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());
    var code = new DefaultAuthorizationCodeTokenResponseClient();
    code.setRestOperations(RpConfiguration.oauthHttp());
    var userInfo = new DefaultOAuth2UserService();
    userInfo.setRestOperations(RpConfiguration.http());
    var oidc = new OidcUserService();
    oidc.setOauth2UserService(userInfo);
    var logout = new OidcClientInitiatedLogoutSuccessHandler(clients);
    logout.setPostLogoutRedirectUri(settings.origin + "/");
    logout.setDefaultTargetUrl(settings.origin + "/");
    http.authorizeHttpRequests(
            auth ->
                auth.requestMatchers(
                        "/",
                        "/health",
                        "/csrf",
                        "/app.js",
                        "/error",
                        "/oauth2/**",
                        "/login/oauth2/**")
                    .permitAll()
                    .anyRequest()
                    .authenticated())
        .exceptionHandling(
            errors ->
                errors.authenticationEntryPoint(
                    (request, response, error) -> response.setStatus(401)))
        .oauth2Login(
            login ->
                login
                    .authorizedClientRepository(repository)
                    .authorizationEndpoint(
                        endpoint -> endpoint.authorizationRequestResolver(resolver))
                    .tokenEndpoint(endpoint -> endpoint.accessTokenResponseClient(code))
                    .userInfoEndpoint(endpoint -> endpoint.oidcUserService(oidc))
                    .successHandler(
                        (request, response, authentication) -> {
                          try {
                            var user = (OidcUser) authentication.getPrincipal();
                            if (sessions.bind(request.getSession().getId(), user)) {
                              response.sendRedirect(settings.origin + "/");
                              return;
                            }
                          } catch (RuntimeException unavailable) {
                            response.setStatus(503);
                          }
                          request.getSession().invalidate();
                          SecurityContextHolder.clearContext();
                          if (response.getStatus() != 503) response.setStatus(401);
                        })
                    .failureHandler((request, response, error) -> response.setStatus(401)))
        .logout(config -> config.logoutSuccessHandler(logout).deleteCookies(settings.cookie));
    http.headers(
        headers ->
            headers
                .contentSecurityPolicy(
                    policy ->
                        policy.policyDirectives(
                            "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"))
                .referrerPolicy(
                    policy ->
                        policy.policy(
                            org.springframework.security.web.header.writers
                                .ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER)));
    http.addFilterAfter(
        new BffStateFilter(manager, decoder, sessions), SecurityContextHolderFilter.class);
    http.addFilterBefore(
        new OncePerRequestFilter() {
          @Override
          protected void doFilterInternal(
              HttpServletRequest request, HttpServletResponse response, FilterChain chain)
              throws IOException, ServletException {
            if (!Set.of("GET", "HEAD", "OPTIONS").contains(request.getMethod())
                && !settings.origin.equals(request.getHeader("Origin"))) {
              response.setStatus(403);
              return;
            }
            chain.doFilter(request, response);
          }
        },
        CsrfFilter.class);
    return http.build();
  }
}
