package com.unipass.server;

import com.fasterxml.jackson.annotation.*;
import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;
import java.util.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@JsonIgnoreProperties(ignoreUnknown = true)
public final class IdentityPrincipal implements UserDetails, Serializable {
  private static final long serialVersionUID = 1L;
  private final UUID userId;
  private final long epoch;
  private final Instant authenticatedAt;
  private final List<String> roles;
  private final Instant mfaAt;

  public enum Method {
    PASSWORD,
    FEISHU
  }

  private final Method authenticationMethod;
  private final Instant passwordAuthenticatedAt;
  private final UUID loginId;

  public IdentityPrincipal(UUID userId, long epoch, Instant authenticatedAt, List<String> roles) {
    this(userId, epoch, authenticatedAt, roles, null);
  }

  public IdentityPrincipal(
      UUID userId, long epoch, Instant authenticatedAt, List<String> roles, Instant mfaAt) {
    this(userId, epoch, authenticatedAt, roles, mfaAt, Method.PASSWORD, authenticatedAt);
  }

  public IdentityPrincipal(
      UUID userId,
      long epoch,
      Instant authenticatedAt,
      List<String> roles,
      Instant mfaAt,
      Method authenticationMethod,
      Instant passwordAuthenticatedAt) {
    this(
        userId,
        epoch,
        authenticatedAt,
        roles,
        mfaAt,
        authenticationMethod,
        passwordAuthenticatedAt,
        UUID.randomUUID());
  }

  @JsonCreator
  public IdentityPrincipal(
      @JsonProperty("userId") UUID userId,
      @JsonProperty("epoch") long epoch,
      @JsonProperty("authenticatedAt") Instant authenticatedAt,
      @JsonProperty("roles") List<String> roles,
      @JsonProperty("mfaAt") Instant mfaAt,
      @JsonProperty("authenticationMethod") Method authenticationMethod,
      @JsonProperty("passwordAuthenticatedAt") Instant passwordAuthenticatedAt,
      @JsonProperty("loginId") UUID loginId) {
    this.userId = userId;
    this.epoch = epoch;
    this.authenticatedAt = authenticatedAt;
    this.roles = new ArrayList<>(roles);
    this.mfaAt = mfaAt;
    this.loginId = loginId;
    // Old server-written sessions represented directory/password authentication only.
    this.authenticationMethod =
        authenticationMethod == null ? Method.PASSWORD : authenticationMethod;
    this.passwordAuthenticatedAt =
        authenticationMethod == null ? authenticatedAt : passwordAuthenticatedAt;
    Objects.requireNonNull(userId);
    Objects.requireNonNull(authenticatedAt);
    if (this.authenticationMethod == Method.PASSWORD && this.passwordAuthenticatedAt == null)
      throw new IllegalArgumentException("Password proof required");
  }

  public UUID getUserId() {
    return userId;
  }

  public long getEpoch() {
    return epoch;
  }

  public Instant getAuthenticatedAt() {
    return authenticatedAt;
  }

  public List<String> getRoles() {
    return new ArrayList<>(roles);
  }

  // Spring Session currently uses JDK serialization. Absent fields in old streams
  // become null without invoking the JSON creator, so restore the old proof here.
  @Serial
  private Object readResolve() {
    return authenticationMethod == null
        ? new IdentityPrincipal(
            userId, epoch, authenticatedAt, roles, mfaAt, Method.PASSWORD, authenticatedAt, loginId)
        : this;
  }

  public Instant getMfaAt() {
    return mfaAt;
  }

  public Method getAuthenticationMethod() {
    return authenticationMethod;
  }

  public Instant getPasswordAuthenticatedAt() {
    return passwordAuthenticatedAt;
  }

  public UUID getLoginId() {
    return loginId;
  }

  public IdentityPrincipal withMfa(Instant at) {
    return new IdentityPrincipal(
        userId,
        epoch,
        authenticatedAt,
        roles,
        at,
        authenticationMethod,
        passwordAuthenticatedAt,
        loginId);
  }

  public IdentityPrincipal withPassword(Instant at) {
    return new IdentityPrincipal(
        userId,
        epoch,
        authenticatedAt,
        roles,
        mfaAt,
        authenticationMethod,
        Objects.requireNonNull(at),
        loginId);
  }

  public boolean hasRecentPassword(Instant now) {
    return passwordAuthenticatedAt != null
        && !passwordAuthenticatedAt.isAfter(now)
        && passwordAuthenticatedAt.plusSeconds(300).isAfter(now);
  }

  @JsonIgnore
  public List<String> getAuthenticationMethods() {
    List<String> methods = new ArrayList<>();
    if (authenticationMethod == Method.FEISHU) methods.add("feishu");
    if (passwordAuthenticatedAt != null) methods.add("pwd");
    if (mfaAt != null) methods.add("otp");
    return methods;
  }

  @Override
  @JsonIgnore
  public String getUsername() {
    return userId.toString();
  }

  @Override
  @JsonIgnore
  public String getPassword() {
    return "";
  }

  @Override
  @JsonIgnore
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return roles.stream().map(SimpleGrantedAuthority::new).toList();
  }

  @Override
  public String toString() {
    return "IdentityPrincipal[" + userId + "]";
  }
}
