/*
 * Copyright 2025 Couchbase, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.couchbase.analytics.client.java;

import com.couchbase.analytics.client.java.internal.ThreadSafe;
import okhttp3.Credentials;
import okhttp3.tls.HandshakeCertificates;
import okhttp3.tls.HeldCertificate;
import org.jspecify.annotations.Nullable;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import static com.couchbase.analytics.client.java.internal.utils.lang.CbCollections.listCopyOf;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;

/**
 * Create an instance with one of the static factory methods:
 * <pre>
 * Credential.of(username, password)
 * Credential.ofJwt(jwt)
 * Credential.fromKeyStore(Paths.get("/path/to/client-cert.p12"), "password")
 * Credential.fromPem(Paths.get("/path/to/client-cert.pem"))
 * </pre>
 * The credential can later be rotated by calling {@link Cluster#credential(Credential)}
 * (typical for short-lived JWTs).
 *
 * @see Cluster#credential(Credential)
 */
@ThreadSafe
public abstract class Credential {

  private static class UsernameAndPassword extends Credential {
    private final String authHeaderValue;

    UsernameAndPassword(String username, String password) {
      this.authHeaderValue = Credentials.basic(username, password, UTF_8);
    }

    @Override
    String httpAuthorizationHeaderValue() {
      return authHeaderValue;
    }
  }

  private static class Jwt extends Credential {
    private final String authHeaderValue;

    Jwt(String jwt) {
      this.authHeaderValue = "Bearer " + jwt.trim();
    }

    @Override
    String httpAuthorizationHeaderValue() {
      return authHeaderValue;
    }
  }

  private static class ClientCertificate extends Credential {
    private final HeldCertificate heldCertificate;
    private final List<X509Certificate> intermediates;

    ClientCertificate(HeldCertificate heldCertificate, List<X509Certificate> intermediates) {
      this.heldCertificate = requireNonNull(heldCertificate);
      this.intermediates = listCopyOf(intermediates);
    }

    @Override
    @Nullable String httpAuthorizationHeaderValue() {
      return null;
    }

    @Override
    void addHeldCertificate(HandshakeCertificates.Builder builder) {
      builder.heldCertificate(heldCertificate, intermediates.toArray(new X509Certificate[0]));
    }

    @Override
    @Nullable X509Certificate leafCertificate() {
      return heldCertificate.certificate();
    }

    @Override
    List<X509Certificate> intermediates() {
      return intermediates;
    }
  }

  /**
   * Returns a new instance that holds the given username and password.
   */
  public static Credential of(String username, String password) {
    return new UsernameAndPassword(username, password);
  }

  /**
   * Returns a new instance that holds the given JSON Web Token (JWT).
   * Because JWTs typically expire within minutes, callers are expected to
   * rotate by passing a fresh credential to {@link Cluster#credential(Credential)}
   * before the token expires.
   * <p>
   * Requires Enterprise Analytics 2.2 or later.
   *
   * @see Cluster#credential(Credential)
   */
  public static Credential ofJwt(String jwt) {
    return new Jwt(jwt);
  }

  /**
   * Returns a new instance that holds a client certificate loaded from the specified PKCS#12 key store file.
   * <p>
   * The key store must have a single entry which must contain a private key and certificate chain.
   * The same password must be used for integrity and encryption.
   * <p>
   * <b>TIP:</b>
   * One way to create a suitable PKCS#12 file from a PEM-encoded private key and certificate
   * is to concatenate the key and certificate into a file named "client-cert.pem", then run this command:
   * <pre>
   * openssl pkcs12 -export -in client-cert.pem -out client-cert.p12 -passout pass:password
   * </pre>
   * This creates a PKCS#12 file named "client-cert.p12" protected by the password "password".
   *
   * @param password for verifying key store integrity and decrypting the private key
   */
  public static Credential fromKeyStore(Path pkcs12Path, @Nullable String password) {
    KeyStore keyStore = loadKeyStore(pkcs12Path, password);
    try {
      List<String> aliases = toList(keyStore.aliases());
      if (aliases.size() != 1) {
        throw new IllegalArgumentException("Expected the key store to contain exactly one entry, but got aliases: " + aliases);
      }
      String alias = aliases.get(0);

      PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password == null ? null : password.toCharArray());
      Certificate[] chain = keyStore.getCertificateChain(alias);
      X509Certificate userCert = (X509Certificate) chain[0];

      HeldCertificate heldCertificate = new HeldCertificate(
        new KeyPair(userCert.getPublicKey(), privateKey),
        userCert
      );

      List<X509Certificate> intermediates = new ArrayList<>();
      for (int i = 1; i < chain.length; i++) { // skip zero-th because that's the user's certificate
        intermediates.add((X509Certificate) chain[i]);
      }

      return new ClientCertificate(heldCertificate, intermediates);

    } catch (ClassCastException | GeneralSecurityException e) {
      throw new RuntimeException("Failed to read client certificate from key store.", e);
    }
  }

  /**
   * Returns a new instance that holds a client certificate built from a PEM file
   * containing the leaf X.509 certificate (first), its matching PKCS#8 private key,
   * and any intermediate certificates (after the leaf, in order from leaf to root).
   * <p>
   * For PKCS#1 (legacy {@code -----BEGIN RSA PRIVATE KEY-----}) keys, convert with:
   * <pre>
   * openssl pkcs8 -topk8 -in old.key -out new.key -nocrypt
   * </pre>
   */
  public static Credential fromPem(Path pemPath) {
    requireNonNull(pemPath, "pemPath");
    try {
      return fromPem(new String(Files.readAllBytes(pemPath), UTF_8));
    } catch (IOException e) {
      throw new RuntimeException("Failed to read PEM file: " + pemPath, e);
    }
  }

  /**
   * Returns a new instance that holds a client certificate built from a PEM-encoded
   * string containing the leaf X.509 certificate (first), its matching RSA private key,
   * and any intermediate certificates (after the leaf, in order from leaf to root).
   * <p>
   * The private key may be in either PKCS#8 ({@code -----BEGIN PRIVATE KEY-----})
   * or PKCS#1 ({@code -----BEGIN RSA PRIVATE KEY-----}) form.
   */
  public static Credential fromPem(String pem) {
    requireNonNull(pem, "pem");

    List<String> certBlocks = pemBlocks(pem, "CERTIFICATE");
    if (certBlocks.isEmpty()) {
      throw new IllegalArgumentException("PEM contains no CERTIFICATE block.");
    }

    PrivateKey privateKey = privateKeyFromPem(pem);

    try {
      CertificateFactory factory = CertificateFactory.getInstance("X.509");
      X509Certificate leaf = (X509Certificate) factory.generateCertificate(
        new ByteArrayInputStream(certBlocks.get(0).getBytes(UTF_8))
      );

      // Best-effort sanity check: getBasicConstraints() returns >= 0 only when the BasicConstraints
      // extension is present and marks the cert as a CA. A CA in the leaf position is almost always
      // user error (chain in wrong order). This won't catch a v1 / no-extension CA in leaf position.
      if (leaf.getBasicConstraints() != -1) {
        throw new IllegalArgumentException(
          "PEM does not begin with a leaf (end-entity) certificate. " +
            "The leaf must come first, followed by intermediates in leaf-to-root order."
        );
      }

      HeldCertificate held = new HeldCertificate(new KeyPair(leaf.getPublicKey(), privateKey), leaf);

      List<X509Certificate> intermediates = new ArrayList<>();
      byte[] leafEncoded = leaf.getEncoded();
      for (int i = 1; i < certBlocks.size(); i++) {
        X509Certificate cert = (X509Certificate) factory.generateCertificate(
          new ByteArrayInputStream(certBlocks.get(i).getBytes(UTF_8))
        );
        if (Arrays.equals(cert.getEncoded(), leafEncoded)) {
          throw new IllegalArgumentException(
            "PEM contains the leaf certificate more than once. The leaf must appear exactly once, " +
              "followed by intermediates in leaf-to-root order."
          );
        }
        intermediates.add(cert);
      }
      return new ClientCertificate(held, intermediates);
    } catch (GeneralSecurityException e) {
      throw new RuntimeException("Failed to build client certificate from PEM.", e);
    }
  }

  private static PrivateKey privateKeyFromPem(String pem) {
    boolean hasPkcs8 = pem.contains("-----BEGIN PRIVATE KEY-----");
    boolean hasPkcs1 = pem.contains("-----BEGIN RSA PRIVATE KEY-----");
    if (hasPkcs8 == hasPkcs1) {
      // both true (ambiguous) or both false (none)
      throw new IllegalArgumentException("PEM must contain exactly one PRIVATE KEY or RSA PRIVATE KEY block.");
    }
    try {
      if (hasPkcs8) {
        return KeyFactory.getInstance("RSA").generatePrivate(
          new PKCS8EncodedKeySpec(pemBlock(pem, "PRIVATE KEY"))
        );
      }
      return rsaPrivateKeyFromPkcs1(pemBlock(pem, "RSA PRIVATE KEY"));
    } catch (GeneralSecurityException e) {
      throw new RuntimeException("Failed to parse private key from PEM.", e);
    }
  }

  // Extracts every PEM block of the given type (e.g. "CERTIFICATE"), in input order.
  // Used for certificates because a PEM may contain leaf + intermediates.
  private static List<String> pemBlocks(String pem, String type) {
    String begin = "-----BEGIN " + type + "-----";
    String end = "-----END " + type + "-----";
    List<String> blocks = new ArrayList<>();
    int searchFrom = 0;
    while (true) {
      int start = pem.indexOf(begin, searchFrom);
      if (start < 0) break;
      int stop = pem.indexOf(end, start);
      if (stop < 0) break;
      stop += end.length();
      blocks.add(pem.substring(start, stop));
      searchFrom = stop;
    }
    return blocks;
  }

  // Extracts the base64-decoded body of the first PEM block of the given type.
  private static byte[] pemBlock(String pem, String type) {
    String header = "-----BEGIN " + type + "-----";
    String footer = "-----END " + type + "-----";
    int start = pem.indexOf(header);
    int end = pem.indexOf(footer);
    if (start < 0 || end < 0) {
      throw new IllegalArgumentException("PEM does not contain block: " + type);
    }
    String body = pem.substring(start + header.length(), end).replaceAll("\\s", "");
    return Base64.getDecoder().decode(body);
  }

  // Wraps a PKCS#1 RSA private key in a PKCS#8 PrivateKeyInfo so the JDK KeyFactory can load it,
  // avoiding a Bouncy Castle dependency.
  private static PrivateKey rsaPrivateKeyFromPkcs1(byte[] pkcs1) throws GeneralSecurityException {
    byte[] algorithmId = {
      0x30, 0x0d, 0x06, 0x09, 0x2a, (byte) 0x86, 0x48, (byte) 0x86,
      (byte) 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
    };
    byte[] version = {0x02, 0x01, 0x00};
    byte[] octetString = derTlv(0x04, pkcs1);
    byte[] inner = concat(version, algorithmId, octetString);
    byte[] pkcs8 = derTlv(0x30, inner);
    return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
  }

  private static byte[] derTlv(int tag, byte[] value) {
    byte[] length = derLength(value.length);
    byte[] result = new byte[1 + length.length + value.length];
    result[0] = (byte) tag;
    System.arraycopy(length, 0, result, 1, length.length);
    System.arraycopy(value, 0, result, 1 + length.length, value.length);
    return result;
  }

  private static byte[] derLength(int len) {
    if (len < 0x80) return new byte[]{(byte) len};
    if (len < 0x100) return new byte[]{(byte) 0x81, (byte) len};
    return new byte[]{(byte) 0x82, (byte) (len >> 8), (byte) (len & 0xff)};
  }

  private static byte[] concat(byte[]... arrays) {
    int total = 0;
    for (byte[] a : arrays) total += a.length;
    byte[] result = new byte[total];
    int pos = 0;
    for (byte[] a : arrays) {
      System.arraycopy(a, 0, result, pos, a.length);
      pos += a.length;
    }
    return result;
  }

  private static KeyStore loadKeyStore(Path keyStorePath, @Nullable String password) {
    try (InputStream keyStoreInputStream = Files.newInputStream(keyStorePath)) {
      final KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
      store.load(
        keyStoreInputStream,
        password != null ? password.toCharArray() : null
      );
      return store;
    } catch (Exception ex) {
      throw new RuntimeException("Failed to read key store.", ex);
    }
  }

  private static <T> List<T> toList(Enumeration<T> e) {
    List<T> result = new ArrayList<>();
    while (e.hasMoreElements()) {
      result.add(e.nextElement());
    }
    return result;
  }

  abstract @Nullable String httpAuthorizationHeaderValue();

  /**
   * Hook for client-certificate credentials to attach themselves to the OkHttp
   * {@link HandshakeCertificates.Builder} that backs the SSL context. The default
   * is a no-op so non-cert credentials don't have to override.
   */
  void addHeldCertificate(HandshakeCertificates.Builder builder) {
  }

  /** Returns the leaf X.509 certificate for client-certificate credentials, or {@code null}. */
  @Nullable X509Certificate leafCertificate() {
    return null;
  }

  /** Returns intermediate X.509 certificates for client-certificate credentials, or empty. */
  List<X509Certificate> intermediates() {
    return Collections.emptyList();
  }

  /**
   * @see #of
   * @see #ofJwt
   * @see #fromPem
   * @see #fromKeyStore
   */
  private Credential() {
  }
}
