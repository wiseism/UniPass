package com.unipass.web;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.*;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.*;
import org.springframework.core.env.Environment;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.registration.*;
import org.springframework.security.oauth2.client.web.*;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.session.web.http.*;
import org.springframework.web.client.RestTemplate;

@Configuration
public class RpConfiguration {
  static RestTemplate http() {
    var factory =
        new JdkClientHttpRequestFactory(
            HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(2))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build());
    factory.setReadTimeout(Duration.ofSeconds(3));
    return new RestTemplate(factory);
  }

  static RestTemplate oauthHttp() {
    var rest = http();
    rest.setMessageConverters(
        List.of(
            new FormHttpMessageConverter(), new OAuth2AccessTokenResponseHttpMessageConverter()));
    rest.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
    return rest;
  }

  @Bean
  ClientRegistrationRepository registrations(RpSettings s) {
    return new InMemoryClientRegistrationRepository(
        ClientRegistration.withRegistrationId("unipass")
            .clientId(s.id)
            .clientSecret(s.secret)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri(s.origin + "/login/oauth2/code/unipass")
            .scope("openid", "profile", "api.read")
            .authorizationUri(s.issuer + "/oauth/authorize")
            .tokenUri(s.issuer + "/oauth/token")
            .userInfoUri(s.issuer + "/oauth/userinfo")
            .userNameAttributeName("sub")
            .jwkSetUri(s.issuer + "/oauth/jwks")
            .issuerUri(s.issuer)
            .providerConfigurationMetadata(
                Map.of("end_session_endpoint", s.issuer + "/oauth/logout"))
            .clientName("UniPass")
            .build());
  }

  @Bean
  OAuth2AuthorizedClientRepository authorizedClients() {
    return new HttpSessionOAuth2AuthorizedClientRepository();
  }

  @Bean(name = "springSessionDefaultRedisSerializer")
  RedisSerializer<Object> sessionSerializer(Environment env, RpSettings s) {
    return new EncryptedSessionSerializer(
        env.getRequiredProperty("unipass.rp.session-key"), s.namespace);
  }

  @Bean
  CookieSerializer cookie(RpSettings s) {
    var cookie = new DefaultCookieSerializer();
    cookie.setCookieName(s.cookie);
    cookie.setCookiePath("/");
    cookie.setUseHttpOnlyCookie(true);
    cookie.setUseSecureCookie(!s.local);
    cookie.setSameSite("Lax");
    return cookie;
  }

  @Bean
  FilterRegistrationBean<SessionRequestLock> requestLock(StringRedisTemplate redis, RpSettings s) {
    var bean = new FilterRegistrationBean<>(new SessionRequestLock(redis, s));
    bean.setOrder(SessionRepositoryFilter.DEFAULT_ORDER - 1);
    bean.setAsyncSupported(false);
    return bean;
  }
}
