package com.unipass.directory;

import static org.junit.jupiter.api.Assertions.*;

import com.unboundid.ldap.listener.*;
import com.unboundid.ldap.sdk.*;
import com.unboundid.util.ssl.*;
import java.net.URI;
import java.nio.file.*;
import java.util.*;
import javax.net.ssl.SSLSocketFactory;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

class LdapDirectoryGatewayTest {
  private InMemoryDirectoryServer server;
  private LdapDirectoryGateway gateway;
  private DirectoryConfig config;
  private String id;
  private SSLSocketFactory trustedSockets;
  @TempDir Path temp;

  @BeforeEach
  void start(TestInfo info) throws Exception {
    Path keyStore = temp.resolve("localhost.jks");
    String keytool =
        Path.of(
                System.getProperty("java.home"),
                "bin",
                System.getProperty("os.name").startsWith("Windows") ? "keytool.exe" : "keytool")
            .toString();
    String certHost =
        info.getTestMethod()
                .orElseThrow()
                .getName()
                .equals("wrongHostnameIsRejectedEvenWhenCertificateIsTrusted")
            ? "wrong.invalid"
            : "localhost";
    List<String> command =
        new ArrayList<>(
            List.of(
                keytool,
                "-genkeypair",
                "-alias",
                "localhost",
                "-keyalg",
                "RSA",
                "-keysize",
                "2048",
                "-dname",
                "CN=" + certHost,
                "-ext",
                "SAN=dns:" + certHost,
                "-validity",
                "2",
                "-storetype",
                "JKS",
                "-keystore",
                keyStore.toString(),
                "-storepass",
                "test-only-password",
                "-keypass",
                "test-only-password",
                "-noprompt"));
    if (info.getTestMethod().orElseThrow().getName().equals("expiredCertificateIsRejected"))
      command.addAll(List.of("-startdate", "-3d"));
    Process generation =
        new ProcessBuilder(command)
            .redirectErrorStream(true)
            .redirectOutput(temp.resolve("keytool.txt").toFile())
            .start();
    assertTrue(generation.waitFor(20, java.util.concurrent.TimeUnit.SECONDS));
    assertEquals(0, generation.exitValue());
    char[] password = "test-only-password".toCharArray();
    SSLUtil ssl =
        new SSLUtil(
            new KeyStoreKeyManager(keyStore.toFile(), password),
            new TrustStoreTrustManager(keyStore.toFile(), password, "JKS", true));
    SSLSocketFactory sockets = ssl.createSSLSocketFactory();
    trustedSockets = sockets;
    InMemoryDirectoryServerConfig cfg = new InMemoryDirectoryServerConfig("dc=example,dc=test");
    cfg.setSchema(null);
    cfg.addAdditionalBindCredentials("cn=reader", "reader-test-only");
    cfg.addAdditionalBindCredentials("cn=writer", "writer-test-only");
    cfg.setListenerConfigs(
        InMemoryListenerConfig.createLDAPSConfig(
            "ldaps",
            java.net.InetAddress.getLoopbackAddress(),
            0,
            ssl.createSSLServerSocketFactory(),
            sockets));
    server = new InMemoryDirectoryServer(cfg);
    server.startListening();
    server.add("dn: dc=example,dc=test", "objectClass: domain", "dc: example");
    id = UUID.randomUUID().toString();
    server.add(
        "dn: uid=one,dc=example,dc=test",
        "objectClass: inetOrgPerson",
        "uid: one",
        "cn: One",
        "sn: User",
        "employeeNumber: E001",
        "entryUUID: " + id,
        "userPassword: first-test-password");
    config =
        new DirectoryConfig(
            URI.create("ldaps://localhost:" + server.getListenPort()),
            "dc=example,dc=test",
            "cn=reader",
            "reader-test-only",
            "cn=writer",
            "writer-test-only",
            DirectoryConfig.Type.OPENLDAP,
            true);
    gateway = new LdapDirectoryGateway(config, sockets);
    // Only this generated certificate is trusted. Hostname validation stays enabled.
  }

  @AfterEach
  void close() {
    if (server != null) server.shutDown(true);
  }

  @Test
  void stableIdentitySurvivesDnMoveAndRejectsEmptyOrBadPassword() throws Exception {
    assertEquals("E001", gateway.findByStableId(id).orElseThrow().employeeNo());
    assertFalse(gateway.verifyCredential(id, new char[0]));
    assertFalse(gateway.verifyCredential(id, "wrong".toCharArray()));
    assertTrue(gateway.verifyCredential(id, "first-test-password".toCharArray()));
    server.modifyDN("uid=one,dc=example,dc=test", "uid=moved", true);
    assertEquals("uid=moved,dc=example,dc=test", gateway.findByStableId(id).orElseThrow().dn());
  }

  @Test
  void passwordChangeAndDisableUseTlsAndStableAnchor() {
    gateway.changePassword(
        id, "first-test-password".toCharArray(), "second-test-password".toCharArray());
    assertFalse(gateway.verifyCredential(id, "first-test-password".toCharArray()));
    assertTrue(gateway.verifyCredential(id, "second-test-password".toCharArray()));
    gateway.disableUser(id);
    assertTrue(gateway.findByStableId(id).orElseThrow().disabled());
    assertFalse(gateway.verifyCredential(id, "second-test-password".toCharArray()));
  }

  @Test
  void administrativeResetUsesSeparateWriterAndDoesNotRequireOldPassword() {
    assertTrue(gateway.supportsPasswordReset());
    gateway.resetPassword(id, "reset-test-password".toCharArray());
    assertTrue(gateway.verifyCredential(id, "reset-test-password".toCharArray()));
    assertFalse(gateway.verifyCredential(id, "first-test-password".toCharArray()));
    assertTrue(gateway.passwordVersion(id).isEmpty()); // no ppolicy overlay in the SDK test server
  }

  @Test
  void refusesPlaintextAnonymousWritesAndUntrustedCertificate() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new DirectoryConfig(
                URI.create("ldap://localhost"),
                "dc=x",
                "r",
                "p",
                null,
                null,
                DirectoryConfig.Type.OPENLDAP,
                false));
    var readonly =
        new DirectoryConfig(
            config.endpoint(),
            config.baseDn(),
            config.readDn(),
            config.readPassword(),
            null,
            null,
            config.type(),
            false);
    assertThrows(
        IllegalStateException.class, () -> new LdapDirectoryGateway(readonly).disableUser(id));
    assertThrows(DirectoryFailure.class, () -> new LdapDirectoryGateway(config).findByStableId(id));
    assertFalse(config.toString().contains("reader-test-only"));
  }

  @Test
  void invalidUuidCannotBecomeLdapFilter() {
    assertThrows(IllegalArgumentException.class, () -> gateway.findByStableId("*)(uid=*)"));
    assertArrayEquals(
        HexFormat.of().parseHex("33221100554477668899aabbccddeeff"),
        LdapDirectoryGateway.guidBytes(UUID.fromString("00112233-4455-6677-8899-aabbccddeeff")));
  }

  @Test
  void wrongHostnameIsRejectedEvenWhenCertificateIsTrusted() {
    assertThrows(
        DirectoryFailure.class,
        () -> new LdapDirectoryGateway(config, trustedSockets).findByStableId(id));
  }

  @Test
  void expiredCertificateIsRejected() {
    assertThrows(DirectoryFailure.class, () -> gateway.findByStableId(id));
  }
}
