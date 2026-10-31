package com.unipass.directory;

import static com.unipass.directory.DirectoryFailure.Kind.*;

import com.unboundid.ldap.sdk.*;
import com.unboundid.ldap.sdk.extensions.PasswordModifyExtendedRequest;
import com.unboundid.util.ssl.HostNameSSLSocketVerifier;
import java.nio.charset.StandardCharsets;
import java.util.*;
import javax.net.ssl.SSLSocketFactory;

/** One bounded connection per operation. JVM trust store and hostname validation are mandatory. */
public final class LdapDirectoryGateway implements DirectoryGateway {
  private final DirectoryConfig config;
  private final SSLSocketFactory socketFactory;

  public LdapDirectoryGateway(DirectoryConfig config) {
    this(config, (SSLSocketFactory) SSLSocketFactory.getDefault());
  }

  public LdapDirectoryGateway(DirectoryConfig config, SSLSocketFactory socketFactory) {
    this.config = Objects.requireNonNull(config);
    this.socketFactory = Objects.requireNonNull(socketFactory);
  }

  @Override
  public DirectoryConfig.Type type() {
    return config.type();
  }

  private LDAPConnection connect(String dn, String password) throws LDAPException {
    if (dn == null || dn.isBlank() || password == null || password.isEmpty())
      throw new IllegalArgumentException("Anonymous bind forbidden");
    LDAPConnectionOptions options = new LDAPConnectionOptions();
    options.setConnectTimeoutMillis(3000);
    options.setResponseTimeoutMillis(5000);
    options.setFollowReferrals(false);
    options.setSSLSocketVerifier(new HostNameSSLSocketVerifier(true, false));
    LDAPConnection c = new LDAPConnection(socketFactory, options);
    try {
      c.connect(
          config.endpoint().getHost(),
          config.endpoint().getPort() < 0 ? 636 : config.endpoint().getPort());
      c.bind(dn, password);
      return c;
    } catch (LDAPException e) {
      c.close();
      throw e;
    }
  }

  @Override
  public Optional<DirectoryUser> findByStableId(String stableId) {
    UUID anchor = UUID.fromString(Objects.requireNonNull(stableId));
    try (LDAPConnection c = connect(config.readDn(), config.readPassword())) {
      Filter identity =
          config.type() == DirectoryConfig.Type.AD
              ? Filter.createEqualityFilter("objectGUID", guidBytes(anchor))
              : Filter.createEqualityFilter("entryUUID", anchor.toString());
      SearchRequest request =
          new SearchRequest(
              config.baseDn(),
              SearchScope.SUB,
              identity,
              "employeeNumber",
              "userAccountControl",
              "pwdAccountLockedTime");
      request.setSizeLimit(2);
      request.setTimeLimitSeconds(5);
      List<SearchResultEntry> entries = c.search(request).getSearchEntries();
      if (entries.size() > 1) throw new DirectoryFailure(AMBIGUOUS_IDENTITY);
      if (entries.isEmpty()) return Optional.empty();
      SearchResultEntry e = entries.get(0);
      boolean disabled =
          config.type() == DirectoryConfig.Type.AD
              ? (Integer.parseInt(e.getAttributeValue("userAccountControl")) & 2) != 0
              : "000001010000Z".equals(e.getAttributeValue("pwdAccountLockedTime"));
      return Optional.of(
          new DirectoryUser(
              UUID.fromString(stableId).toString(),
              e.getAttributeValue("employeeNumber"),
              e.getDN(),
              disabled));
    } catch (LDAPException e) {
      throw new DirectoryFailure(UNAVAILABLE);
    }
  }

  @Override
  public boolean verifyCredential(String stableId, char[] password) {
    if (password == null || password.length == 0)
      return false; // prevent unauthenticated simple bind
    DirectoryUser user = findByStableId(stableId).orElse(null);
    if (user == null || user.disabled()) return false;
    try (LDAPConnection c = connect(user.dn(), new String(password))) {
      assertIdentity(c, user);
      return true;
    } catch (LDAPException e) {
      if (e.getResultCode() == ResultCode.INVALID_CREDENTIALS) return false;
      throw new DirectoryFailure(UNAVAILABLE);
    }
  }

  private void requireWriter() {
    if (!config.writableConfirmed()
        || config.writeDn() == null
        || config.writeDn().isBlank()
        || config.writePassword() == null
        || config.writePassword().isEmpty())
      throw new IllegalStateException("Explicit writable endpoint and writer credentials required");
  }

  @Override
  public void changePassword(String stableId, char[] oldPassword, char[] newPassword) {
    requireWriter();
    if (oldPassword == null
        || oldPassword.length == 0
        || newPassword == null
        || newPassword.length == 0)
      throw new IllegalArgumentException("Old and new passwords required");
    DirectoryUser user = findByStableId(stableId).orElseThrow(() -> new DirectoryFailure(REJECTED));
    if (user.disabled()) throw new DirectoryFailure(REJECTED);
    // Bind as the user: do not elevate a user password change to an administrative reset.
    try (LDAPConnection c = connect(user.dn(), new String(oldPassword))) {
      assertIdentity(c, user);
      if (config.type() == DirectoryConfig.Type.AD) {
        byte[] oldValue = quoted(oldPassword), newValue = quoted(newPassword);
        try {
          ModifyRequest request =
              new ModifyRequest(
                  user.dn(),
                  new Modification(ModificationType.DELETE, "unicodePwd", oldValue),
                  new Modification(ModificationType.ADD, "unicodePwd", newValue));
          request.addControl(
              new com.unboundid.ldap.sdk.controls.AssertionRequestControl(
                  anchorFilter(user.stableId())));
          c.modify(request);
        } finally {
          Arrays.fill(oldValue, (byte) 0);
          Arrays.fill(newValue, (byte) 0);
        }
      } else {
        ExtendedResult result =
            c.processExtendedOperation(
                new PasswordModifyExtendedRequest(
                    user.dn(), new String(oldPassword), new String(newPassword)));
        if (result.getResultCode() != ResultCode.SUCCESS)
          throw new LDAPException(result.getResultCode());
      }
    } catch (LDAPException e) {
      throw writeFailure(e);
    }
  }

  @Override
  public void disableUser(String stableId) {
    requireWriter();
    DirectoryUser user = findByStableId(stableId).orElseThrow(() -> new DirectoryFailure(REJECTED));
    try (LDAPConnection c = connect(config.writeDn(), config.writePassword())) {
      if (config.type() == DirectoryConfig.Type.AD) {
        // Preserve other UAC flags. Assertion control prevents overwriting a concurrent change.
        SearchResultEntry e = c.getEntry(user.dn(), "userAccountControl");
        String current = e.getAttributeValue("userAccountControl");
        ModifyRequest request =
            new ModifyRequest(
                user.dn(),
                new Modification(
                    ModificationType.REPLACE,
                    "userAccountControl",
                    Integer.toString(Integer.parseInt(current) | 2)));
        request.addControl(
            new com.unboundid.ldap.sdk.controls.AssertionRequestControl(
                Filter.createANDFilter(
                    Filter.createEqualityFilter("userAccountControl", current),
                    anchorFilter(user.stableId()))));
        c.modify(request);
      } else {
        ModifyRequest request =
            new ModifyRequest(
                user.dn(),
                new Modification(
                    ModificationType.REPLACE, "pwdAccountLockedTime", "000001010000Z"));
        request.addControl(
            new com.unboundid.ldap.sdk.controls.AssertionRequestControl(
                Filter.createEqualityFilter("entryUUID", user.stableId())));
        c.modify(request);
      }
    } catch (LDAPException e) {
      throw writeFailure(e);
    }
  }

  private Filter anchorFilter(String stableId) {
    return config.type() == DirectoryConfig.Type.AD
        ? Filter.createEqualityFilter("objectGUID", guidBytes(UUID.fromString(stableId)))
        : Filter.createEqualityFilter("entryUUID", stableId);
  }

  private void assertIdentity(LDAPConnection c, DirectoryUser user) throws LDAPException {
    String attribute = config.type() == DirectoryConfig.Type.AD ? "objectGUID" : "entryUUID";
    SearchResultEntry entry = c.getEntry(user.dn(), attribute);
    boolean same =
        entry != null
            && (config.type() == DirectoryConfig.Type.AD
                ? Arrays.equals(
                    entry.getAttributeValueBytes(attribute),
                    guidBytes(UUID.fromString(user.stableId())))
                : user.stableId().equalsIgnoreCase(entry.getAttributeValue(attribute)));
    if (!same) throw new LDAPException(ResultCode.ASSERTION_FAILED);
  }

  private static DirectoryFailure writeFailure(LDAPException e) {
    ResultCode rc = e.getResultCode();
    return new DirectoryFailure(
        rc == ResultCode.TIMEOUT
                || rc == ResultCode.SERVER_DOWN
                || rc == ResultCode.CONNECT_ERROR
                || rc == ResultCode.LOCAL_ERROR
            ? UNKNOWN_WRITE
            : REJECTED);
  }

  @Override
  public Optional<String> passwordVersion(String stableId) {
    DirectoryUser user = findByStableId(stableId).orElseThrow(() -> new DirectoryFailure(REJECTED));
    String attribute = config.type() == DirectoryConfig.Type.AD ? "pwdLastSet" : "pwdChangedTime";
    try (LDAPConnection c = connect(config.readDn(), config.readPassword())) {
      assertIdentity(c, user);
      SearchResultEntry entry = c.getEntry(user.dn(), attribute);
      return Optional.ofNullable(entry == null ? null : entry.getAttributeValue(attribute));
    } catch (LDAPException e) {
      throw new DirectoryFailure(UNAVAILABLE);
    }
  }

  @Override
  public boolean supportsPasswordReset() {
    return true;
  }

  @Override
  public void resetPassword(String stableId, char[] newPassword) {
    requireWriter();
    if (newPassword == null || newPassword.length == 0)
      throw new IllegalArgumentException("New password required");
    DirectoryUser user = findByStableId(stableId).orElseThrow(() -> new DirectoryFailure(REJECTED));
    try (LDAPConnection c = connect(config.writeDn(), config.writePassword())) {
      assertIdentity(c, user);
      if (config.type() == DirectoryConfig.Type.AD) {
        byte[] value = quoted(newPassword);
        try {
          ModifyRequest request =
              new ModifyRequest(
                  user.dn(), new Modification(ModificationType.REPLACE, "unicodePwd", value));
          request.addControl(
              new com.unboundid.ldap.sdk.controls.AssertionRequestControl(
                  anchorFilter(user.stableId())));
          c.modify(request);
        } finally {
          Arrays.fill(value, (byte) 0);
        }
      } else {
        ExtendedResult result =
            c.processExtendedOperation(
                new PasswordModifyExtendedRequest(user.dn(), null, new String(newPassword)));
        if (result.getResultCode() != ResultCode.SUCCESS)
          throw new LDAPException(result.getResultCode());
      }
    } catch (LDAPException e) {
      throw writeFailure(e);
    }
  }

  private static byte[] quoted(char[] value) {
    return ("\"" + new String(value) + "\"").getBytes(StandardCharsets.UTF_16LE);
  }

  static byte[] guidBytes(UUID id) {
    byte[] bytes = new byte[16];
    java.nio.ByteBuffer b = java.nio.ByteBuffer.wrap(bytes);
    b.order(java.nio.ByteOrder.LITTLE_ENDIAN)
        .putInt((int) (id.getMostSignificantBits() >>> 32))
        .putShort((short) (id.getMostSignificantBits() >>> 16))
        .putShort((short) id.getMostSignificantBits());
    b.order(java.nio.ByteOrder.BIG_ENDIAN).putLong(id.getLeastSignificantBits());
    return bytes;
  }
}
