# wolfSSL OpenJDK 25 FIPS Container (Azul Zulu, Debian 13)

This OpenJDK 25 image is based on the Docker Official Image
[azul-zulu:25.36-25.0.4.1-jdk-debian13](https://hub.docker.com/_/azul-zulu)
(Azul Zulu 25.0.4.1 on Debian 13 "trixie"). It replaces the non-FIPS Java
cryptography providers with wolfJCE and wolfJSSE, which use wolfSSL's FIPS
140-3 validated wolfCrypt module (Certificate #5548). Only Java cryptography
is in scope for FIPS compliance in this container.

The image mirrors the wolfSSL OpenJDK 19 FIPS image
(`../wolfssl-openjdk-fips-root`), adjusted for JDK 25 and Debian 13. See
[Changes for JDK 25](#changes-for-jdk-25-compared-to-the-openjdk-19-image)
for the differences, and
[Known Gaps Compared to a Stock JDK 25](#known-gaps-compared-to-a-stock-jdk-25)
for behavior that differs from a stock JDK 25.

Using this container requires an active wolfCrypt FIPS license. wolfSSL Inc.
provides the .7z archive password with the license. Contact fips@wolfssl.com
for more information.

## Features

- **FIPS 140-3 Validated Cryptography**: Uses wolfSSL's FIPS validated wolfCrypt
cryptographic module, [FIPS Certificate #5548](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5548).
- **Multi-stage Build**: Optimized for minimal final image size.
- **Automatic Container Tests**: The FIPS Power-On Self Test and container
verification tests run at startup.
- **Debug Support**: Configurable debug logging for JCE/JSSE providers.
- **Security Hardened**: Non-FIPS providers are disabled or filtered, so
wolfJCE and wolfJSSE (wolfCrypt FIPS 140-3) are the only implementations of
cryptographic services. Some available algorithms are restricted or not claimed
by the Security Policy. See [FIPS Compliance](#fips-compliance).

## Components

- **Base Image**: `azul-zulu:25.36-25.0.4.1-jdk-debian13` (Azul Zulu OpenJDK
  25.0.4.1, Debian 13). Built and tested on amd64 and arm64.
- **Native wolfSSL/wolfCrypt**: Configured for FIPS 140-3 with JNI support
- **wolfCrypt JNI/JCE**: Java Cryptography Extension (JCE) provider
- **wolfSSL JNI/JSSE**: Java Secure Socket Extension (JSSE) provider
- **Filtered Sun Providers**: Wrappers for the SUN, SunRsaSign and SunEC
providers that expose only their non-cryptographic services. See
[Custom Filtered Security Providers](#custom-filtered-security-providers)
- **WKS cacerts**: System CA certificates in WolfSSL KeyStore (WKS) format
- **Integrity-checked, read-only FIPS files and a non-root user**: the native
libraries, JNI libraries, provider JARs, `java.security`, `cacerts` and
`krb5.conf` are root-owned and checksum-verified at startup, and the
container runs as non-root user `10001` (`wolfssl`)

## Directory Layout

```
wolfssl-openjdk-fips-zulu25-debian13/
├── README.md                       # Image documentation and details
├── build.sh                        # Docker image build script
├── Dockerfile                      # Container definition
├── docker-entrypoint.sh            # Container entry point script
├── java.security                   # FIPS Java security configuration
├── java.security.original          # Stock Azul Zulu 25.0.4.1 java.security
├── krb5.conf                       # FIPS Kerberos configuration (AES only)
├── scripts/
│   ├── integrity-check.sh          # Startup integrity verification script
│   └── update-integrity-checksums.sh  # Generates the integrity manifest (root)
├── src/
│   └── main/
│       └── FipsInitCheck.java      # FIPS POST and container tests
└── test-images/
    └── basic-test-image/           # Example application / JCA + TLS tests
```

## Container Structure

When built, the container organizes files as follows:

```
/
├── etc/
│   └── krb5.conf                   # FIPS Kerberos configuration
├── usr/
│   ├── lib/
│   │   ├── jni/                    # JNI libraries
│   │   │   ├── libwolfcryptjni.so  # wolfJCE JNI library
│   │   │   └── libwolfssljni.so    # wolfJSSE JNI library
│   │   └── jvm/zulu25/             # JAVA_HOME (symlink to zulu25-ca-<arch>)
│   │       ├── conf/security/
│   │       │   └── java.security   # FIPS Java security configuration
│   │       └── lib/security/
│   │           └── cacerts         # CA certificates in WKS format
│   ├── local/lib/
│   │   └── libwolfssl.so*          # Native wolfSSL FIPS library
│   ├── local/bin/
│   │   ├── integrity-check.sh      # Startup integrity verification script
│   │   └── update-integrity-checksums.sh  # Regenerates the manifest (root)
│   └── share/java/                 # JAR files (Std. Debian location)
│       ├── wolfcrypt-jni.jar       # wolfJCE provider
│       ├── wolfssl-jsse.jar        # wolfJSSE provider
│       └── filtered-providers.jar  # Filtered Sun provider wrappers
├── opt/
│   └── wolfssl-fips/
│       ├── BUILD_INFO              # Build sources (base image, wolfSSL
│       │                           # bundle, JNI commits)
│       ├── bin/                    # Compiled Java classes
│       │   └── FipsInitCheck.class
│       └── checksums/
│           └── libraries.sha256    # Integrity check manifest (libraries,
│                                   # JARs, java.security, cacerts, krb5.conf,
│                                   # FipsInitCheck.class)
├── home/wolfssl/                   # Home and WORKDIR of user 10001 (wolfssl)
└── docker-entrypoint.sh            # Container entrypoint
```

## Changes for JDK 25 Compared to the OpenJDK 19 Image

Changes required by JDK 25:

1. **Base image and JAVA_HOME**: `azul-zulu:25.36-25.0.4.1-jdk-debian13`,
   `JAVA_HOME=/usr/lib/jvm/zulu25`.
2. **SunEC moved into java.base (JDK 22)**: the filtered provider EC module
   flags now target `java.base/sun.security.ec` instead of the (now empty)
   `jdk.crypto.ec` module. See [JVM Module Requirements](#jvm-module-requirements).
3. **Restricted JNI (JEP 472, JDK 24)**: `--enable-native-access` is set for
   the wolfJCE and wolfJSSE modules (and `ALL-UNNAMED` for application JNI
   code), so loading the JNI libraries does not print `WARNING: A restricted
   method in java.lang.System has been called`. Future JDK releases will block
   such calls unless native access is enabled.
4. **java.security rebased on Azul Zulu 25.0.4.1**: the FIPS settings from the
   OpenJDK 19 image are applied on top of the JDK 25 file, with the changes
   listed below. The JDK 25 default `jdk.tls.disabledAlgorithms` additions
   (`DTLSv1.0`, `ECDH`, `TLS_RSA_*`, and SHA-1 `usage HandshakeSignature`
   entries) are merged into the FIPS list. JDK 25 removed the `policy.provider`,
   `policy.url.*` and `package.access` properties (Security Manager removal,
   JEP 486).
5. **New JDK service types**: `KEM` (JDK 21) and `KDF` (JDK 25) are covered
   by the startup checks, so a `KEM`/`KDF` service from any provider other than
   wolfJCE or wolfJSSE fails the check. The image has no `KEM` or `KDF` service.
6. **Security Manager**: permanently disabled in JDK 24+ (JEP 486).
   `-Djava.security.manager` makes the JVM exit at startup, so do not pass it
   in `JAVA_OPTS` / `USER_JAVA_OPTS`. The startup checks no longer report the
   Security Manager state.

Changes made on purpose (not required by JDK 25):

7. **Providers on the module path instead of `CLASSPATH`**: the provider JARs
   are loaded from the JVM module path, set in `JAVA_TOOL_OPTIONS`. Every JVM
   in the container gets the providers with no application changes, including
   `java -jar`, applications with their own class path, and JDK tools that
   ignore `CLASSPATH` (`keytool`, `jar`, `jarsigner`, `jshell`). The filtered
   providers' reflection access to JDK internals is granted to their own module
   only, instead of to all class path code. See
   [Provider Discovery](#provider-discovery-module-path-and-serviceloader).
8. **Non-root user and wider integrity check**: the container runs as non-root
   user `10001` (`wolfssl`, home and working directory `/home/wolfssl`) instead
   of root. The integrity check now also covers the two JNI libraries,
   `java.security`, `cacerts`, `/etc/krb5.conf` and `FipsInitCheck.class`, all
   of which are root-owned and read-only. The integrity check script runs as
   non-root. See [Derived Images](#derived-images).
9. **Stronger startup checks**: FipsInitCheck adds or tightens these checks:
   - **FIPS module state**: wolfJCE's wolfCrypt must be a FIPS build
     (`Fips.enabled`) with module version 5 (`Fips.fipsVersion`, wolfCrypt
     FIPS v5.2.3), its algorithm self tests (CASTs) must have passed, and the
     module must not be in an error state (`wolfCrypt_GetStatus_fips`, checked
     again after all other checks).
   - **Provider origin**: checks that the providers were loaded from JARs in
     `/usr/share/java`, and the native libraries from `/usr/local/lib` and
     `/usr/lib/jni`.
   - **Every provider service**: every service of every provider is checked
     against what that provider may offer. The filtered providers may offer
     only their listed services, plus any granted in `java.security` (see
     [Granting Additional Sun Services](#granting-additional-sun-services)).
     Any other copy of a Sun service fails startup, even one an application can
     reach only by naming the provider (for example
     `MessageDigest.getInstance("SHA-256", "FilteredSun")`). A missing filtered
     provider service also fails startup.
   - **Unavailable algorithms**: a list of algorithm names across 12 JCA
     service types (MessageDigest, Mac, Signature, Cipher, SecretKeyFactory,
     KeyAgreement, KeyPairGenerator, KeyFactory, AlgorithmParameters, KDF, KEM
     and KeyStore) must not be available. Requesting one must throw only the
     "not available" exception that API documents. A service granted in
     `java.security` is allowed from the granting filtered provider, and
     reported as granted. KeyStore JKS and PKCS12 are allowed from wolfJCE
     when `java.security` maps them to WKS (see
     [WolfSSLKeyStore (WKS) Format](#wolfsslkeystore-wks-format)), and reported
     as mapped.
   - **TLS cipher suites**: the default `SSLContext` must not enable or
     support a cipher suite that uses a cipher or MAC outside the wolfCrypt
     FIPS module (RC4, RC2, DES / 3DES, IDEA, MD5, ChaCha20-Poly1305,
     Camellia, ARIA, SEED, SM4 / SM3). The startup log lists the enabled
     suites, and the TLS protocols for information. This replaces the
     OpenJDK 19 image's check of three 3DES suites.
   - **Expected algorithms**: the check verifies where each one comes from.
     Its code and output no longer call them FIPS approved, since being
     available does not make an algorithm approved (see
     [FIPS Compliance](#fips-compliance)).
10. **Default command `jshell`**: left the same as the base image, instead of
    the OpenJDK 19 image's `java -version`. The entrypoint runs the startup
    checks first, then starts jshell with `JAVA_OPTS` (including the debug
    settings) passed to the JVM that runs the snippets. Use `docker run -it`
    for an interactive session.
11. **SASL NTLM, CRAM-MD5 and DIGEST-MD5 disabled**:
    `jdk.sasl.disabledMechanisms=NTLM, CRAM-MD5, DIGEST-MD5` in
    `java.security`. NTLM needs DES and the other two need MD5, none of which
    is available in this image. Without this setting, creating an NTLM client
    or server fails with an `AssertionError`, and CRAM-MD5 and DIGEST-MD5
    clients and servers are created but fail with a `SaslException` during
    authentication. All three are now reported as not available, like any
    unsupported mechanism, so a client given a list of mechanisms skips them.
    SunSASL still lists them, so the startup checks mark each one
    `[disabled by jdk.sasl.disabledMechanisms]`. To use CRAM-MD5 or DIGEST-MD5
    with MD5 granted, see
    [Granting Additional Sun Services](#granting-additional-sun-services).
12. **TLS 1.2 Extended Master Secret required**: the image sets
    `-Djdk.tls.allowLegacyMasterSecret=false` in `JAVA_TOOL_OPTIONS`, so
    TLS 1.2 handshakes with peers that do not support EMS fail. The OpenJDK 19
    image completed them with a legacy master secret. See
    [Extended Master Secret (TLS 1.2)](#extended-master-secret-tls-12).
13. **java.security policy settings**: `policy.allowSystemProperty` and
    `policy.expandProperties` are back to the stock `true`, so
    `-Djava.security.auth.login.config` works. On JDK 24+ they only affect
    JAAS login configuration.
14. **JDK-internal MD4 blocked**: the `MessageDigest.MD4` entry in
    `jdk.crypto.disabledAlgorithms` blocks the JDK-internal MD4 used by
    Kerberos `rc4-hmac` key derivation. See
    [Scope of the Provider Restrictions](#scope-of-the-provider-restrictions).
15. **Kerberos RFC 8009 encryption types**: `krb5.conf` prefers
    `aes256-cts-hmac-sha384-192` and `aes128-cts-hmac-sha256-128`, with the
    SHA-1 AES types as fallback for KDCs that do not support them. See
    [Kerberos Configuration](#kerberos-configuration).
16. **PKIX `CertPathBuilder` grant removed**: the OpenJDK 19 image granted
    Sun's PKIX `CertPathBuilder` through FilteredSun
    (`wolfssl.filtered.sun.additionalServices=CertPathBuilder.PKIX`). wolfJCE
    provides it now, so the grant is gone.
17. **SHA-1 legacy warnings restored**: `jdk.security.legacyAlgorithms`
    includes the stock `SHA1` entry again, so `keytool` and `jarsigner` warn
    about SHA-1.
18. **Algorithms not approved by Certificate #5548 disabled**:
    `SHA1withECDSA` and `SHA3-224withRSA` to `SHA3-512withRSA` are in
    `jdk.crypto.disabledAlgorithms` and `jdk.certpath.disabledAlgorithms`.
    RSA encryption with padding (`RSA`, `RSA/ECB/PKCS1Padding` and the OAEP
    transformations) is in `jdk.crypto.disabledAlgorithms`. Raw
    `RSA/ECB/NoPadding` is left available.
    See [Certificate #5548 Restrictions Set by the Image](#certificate-5548-restrictions-set-by-the-image).
19. **Build provenance**: the base image is pinned by digest, the JUnit and
    Hamcrest JARs used by the build-time tests are SHA-256 verified, and
    `/opt/wolfssl-fips/BUILD_INFO` plus image labels record what the image
    was built from. See [Version Information](#version-information).

## Custom Filtered Security Providers

wolfJCE and wolfJSSE use several non-cryptographic services from the Sun
providers, so they do not have to re-implement them. To keep applications from
accidentally using the Sun providers' non-FIPS cryptography, the image replaces
those providers in java.security with filtered wrappers that expose only the
non-cryptographic services. The wrappers use reflection to look up the
original providers' services and aliases, and delegate to them.

The sources are in the
[wolfcrypt-jni](https://github.com/wolfSSL/wolfcrypt-jni) repository under
`examples/filtered-providers/`. Its `build-jce-release` ant target builds
`lib/filtered-providers/filtered-providers.jar`, which the image installs as
`/usr/share/java/filtered-providers.jar`.

Cryptography added in JDK 20-25 stays blocked for two reasons. SunJCE
(ML-KEM, DHKEM, HKDF, PBEWithHmac) is not in the provider list at all, and the
filters are allow-lists, so new algorithms in SUN (ML-DSA, HSS/LMS, SHAKE) and
SunEC (EdDSA, XDH) are not exposed. The exposed services are:

**SunEC** (FilteredSunEC.java):
- AlgorithmParameters (EC)

**SunRsaSign** (FilteredSunRsaSign.java):
- KeyFactory (RSASSA-PSS)

**SUN** (FilteredSun.java):
- CertStore (Collection)
- CertStore (com.sun.security.IndexedCollection)
- CertificateFactory (X.509)
- Configuration (JavaLoginConfig)

`Policy (JavaPolicy)` is still on the FilteredSun allow-list, but JDK 24+ no
longer registers it (JEP 486), so it is not exposed on this image.

The startup checks require these services from the filtered providers. A
missing service, or an extra one that `java.security` does not grant, stops
the container. Changing the list also means updating
`FILTERED_PROVIDER_SERVICES` in `FipsInitCheck.java`.

### Granting Additional Sun Services

> **WARNING:** Granting a service may invalidate FIPS 140-3 compliance. A
> granted service exposes Sun's implementation, outside the wolfCrypt FIPS 140-3
> boundary, and is not FIPS validated. Grant a service only when an approved
> exception covers that specific use (for example, from your customer or
> compliance authority), and use it only for that purpose. The startup checks
> allow and report grants, but cannot tell whether a grant is justified.

When an application needs a Sun service the filters do not expose, grant it in
`java.security` with the filtered provider's `additionalServices` property, a
comma-separated list of canonical `Type.Algorithm` names. For example, to
grant Sun MD5 through FilteredSun:

```
wolfssl.filtered.sun.additionalServices=MessageDigest.MD5
```

Each filtered provider has its own property:
- `wolfssl.filtered.sun.additionalServices`
- `wolfssl.filtered.sunec.additionalServices`
- `wolfssl.filtered.sunrsasign.additionalServices`

- **Application use**: `getInstance()` returns the granted service from the
  filtered provider (for example `MessageDigest.getInstance("MD5")` returns
  FilteredSun's MD5, and `java.util.UUID.nameUUIDFromBytes()` works).
- **SASL CRAM-MD5 and DIGEST-MD5**: granting MD5 does not re-enable them,
  since `jdk.sasl.disabledMechanisms` disables them. To use them with MD5
  granted, also set `jdk.sasl.disabledMechanisms=NTLM` (a later line in
  `java.security` replaces the earlier value). DIGEST-MD5 then supports
  authentication only (`auth`). Integrity (`auth-int`) needs HmacMD5, and
  encryption (`auth-conf`) needs 3DES, RC4 or DES. None of these are in the
  image, so filtered providers cannot grant them.
- **Startup checks**: the startup log lists each grant under "Filtered
  provider grants" with a warning, and marks granted services
  `[granted by ...]` in the service and unavailable algorithm checks. A granted
  service is allowed only from the filtered provider that grants it, and the
  same algorithm from any other provider still fails. An entry that matches no
  Sun service is ignored, and the filtered provider prints a warning naming it.
- **Where to set it**: add the line to this directory's `java.security` before
  building the image, or change `java.security` in a derived image (see
  [Derived Images](#derived-images)). Both update the integrity checksums.
  `-Djava.security.properties` is ignored in this image
  (`security.overridePropertiesFile=false`).

### JVM Module Requirements

The providers are registered through JVM flags set in `JAVA_TOOL_OPTIONS` in
the Dockerfile. The JVM reads `JAVA_TOOL_OPTIONS` for every launcher (`java`,
`keytool`, `jar`, `jarsigner`, `jshell`, ...):

- `--module-path=/usr/share/java/wolfcrypt-jni.jar:/usr/share/java/wolfssl-jsse.jar:/usr/share/java/filtered-providers.jar` - provider JARs
- `--add-modules=com.wolfssl.wolfcrypt,com.wolfssl,com.wolfssl.security.providers` - resolve the wolfJCE, wolfJSSE and filtered provider modules
- `--enable-native-access=com.wolfssl.wolfcrypt,com.wolfssl,ALL-UNNAMED` - JNI library loading without JEP 472 warnings (JDK 24+)
- `--add-exports=java.base/sun.security.ec=com.wolfssl.security.providers` - SunEC provider package access (JDK 22+ location)
- `--add-opens=java.base/sun.security.ec=com.wolfssl.security.providers` - SunEC provider classes reflection access
- `--add-opens=java.base/java.security=com.wolfssl.security.providers` - Provider.Service field access
- `--add-opens=java.base/sun.security.provider=com.wolfssl.security.providers` - Sun provider classes
- `--add-opens=java.base/sun.security.util=com.wolfssl.security.providers` - Sun security utility classes
- `--add-opens=java.base/sun.security.rsa=com.wolfssl.security.providers` - SunRsaSign provider classes
- `-Djava.library.path=/usr/lib/jni:/usr/local/lib` - JNI library path configuration

The module names are `com.wolfssl.wolfcrypt` (wolfcrypt-jni.jar),
`com.wolfssl` (wolfssl-jsse.jar) and `com.wolfssl.security.providers`
(filtered-providers.jar). The image build verifies them, and sets
`Automatic-Module-Name: com.wolfssl.security.providers` when a wolfcrypt-jni
version without the filtered providers module descriptor is used.

The `--add-exports` / `--add-opens` flags target the filtered providers module
only. Application code on the class path (`ALL-UNNAMED`) does not get
reflection access to these JDK security internals.

Every JVM started in the container prints `Picked up JAVA_TOOL_OPTIONS: ...`
to stderr. This is normal JVM behavior.

## Build Process

### Prerequisites

- Docker installed and running
- wolfSSL commercial FIPS package password
    + Commercial wolfCrypt packages are provided directly via wolfSSL
    + This package has been tested with Certificate #5548 / FIPS 140-3 (v5.2.3)
    + Password must be supplied at image build time to extract .7z

### Build Options

By default the build clones the master branch of wolfcrypt-jni and wolfssljni.
The repository and local development options below can change that.

**Repository Configuration:**
- `--wolfcrypt-jni-repo URL` - Custom wolfcrypt-jni repository URL
- `--wolfcrypt-jni-branch BRANCH` - Custom wolfcrypt-jni branch or tag
- `--wolfssl-jni-repo URL` - Custom wolfssljni repository URL
- `--wolfssl-jni-branch BRANCH` - Custom wolfssljni branch or tag

**Local Development:**
- `--wolfcrypt-jni PATH` - Use local wolfcrypt-jni directory
- `--wolfssl-jni PATH` - Use local wolfssljni directory

**Build Configuration:**
- `--no-cache` - Disable Docker build cache
- `--cache-from IMAGE` - Use cache from existing image
- `-v, --verbose` - Enable verbose build output and debug logging

### Build the Image

```bash
# Basic build
./build.sh -p your_wolfssl_password

# With custom name and tag
./build.sh -p your_wolfssl_password -n myapp -t v1.0

# Verbose build output and wolfSSL debug logging in the post-build test
./build.sh -p your_wolfssl_password -v

# Using custom repository and branch
./build.sh -p your_wolfssl_password --wolfcrypt-jni-repo https://github.com/myuser/wolfcrypt-jni.git --wolfcrypt-jni-branch feature-branch

# Using local development directories
./build.sh -p your_wolfssl_password --wolfcrypt-jni ../wolfcrypt-jni-dev --wolfssl-jni ../wolfssljni-dev
```

### Run the Container

```bash
# Basic run (runs startup checks, then opens jshell)
docker run -it wolfssl-openjdk-fips-zulu25-debian13:latest

# Show Java version info instead of opening jshell
docker run --rm wolfssl-openjdk-fips-zulu25-debian13:latest java -version

# With debug logging (also applies to jshell)
docker run -it -e WOLFJCE_DEBUG=true \
           -e WOLFJSSE_DEBUG=true \
           wolfssl-openjdk-fips-zulu25-debian13:latest

# Skip FIPS validation on startup (not recommended for production)
docker run -it -e FIPS_CHECK=false wolfssl-openjdk-fips-zulu25-debian13:latest

# Run a Java application from a mounted directory
docker run -v /path/to/your/app:/app \
           -e CLASSPATH=/app \
           wolfssl-openjdk-fips-zulu25-debian13:latest \
           java MyApplication
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `JAVA_OPTS` | JVM options added by the entrypoint to `java` commands, and to `jshell` commands as `-R` options (the JVM that runs snippets) | `-Xmx512m` |
| `USER_JAVA_OPTS` | Extra JVM options appended to `JAVA_OPTS` by the entrypoint | unset |
| `JAVA_TOOL_OPTIONS` | Provider module path, module access and native access flags, and `-Djdk.tls.allowLegacyMasterSecret=false`. Append to it, do not replace it (see [Provider Discovery](#provider-discovery-module-path-and-serviceloader)) | See Dockerfile |
| `CLASSPATH` | Application class path only. The provider JARs are not on it | unset |
| `WOLFJCE_DEBUG` | Enable wolfJCE debug logging | `false` |
| `WOLFJSSE_DEBUG` | Enable wolfJSSE debug logging | `false` |
| `WOLFJSSE_ENGINE_DEBUG` | Enable wolfJSSE SSLEngine debug logging | `false` |
| `FIPS_CHECK` | Run FIPS validation on startup. Only `false` (any case) disables it | `true` |

## Test and Example Application Images

`./test-images/basic-test-image/` builds a test application image on top of
this image. It runs basic JCA and SSL/TLS tests and shows example usage.

```bash
# Build the base image first
./build.sh -p YOUR_WOLFSSL_PASSWORD

# Build the test application
cd test-images/basic-test-image
./build.sh

# Run complete test suite
docker run --rm wolfssl-fips-zulu25-basic-test-image:latest
```

For details see [`./test-images/basic-test-image/README.md`](./test-images/basic-test-image/README.md).
The netty, OkHttp and Spring Boot test images of the OpenJDK 19 image are not
ported to this image.

## FIPS Compliance

### Cryptographic Operations

Cryptography requested through the Java Cryptography Architecture (by algorithm
name, or by the name of a registered provider) is handled by wolfSSL's FIPS
validated wolfCrypt module, through wolfJCE (cryptography) and wolfJSSE (TLS).
wolfJSSE does not go through the JCE layer. It calls native wolfSSL directly,
which uses native wolfCrypt. See
[Scope of the Provider Restrictions](#scope-of-the-provider-restrictions) for
JDK code that bypasses the provider list.

See wolfJCE's [README\_JCE.md](https://github.com/wolfSSL/wolfcrypt-jni/blob/master/README_JCE.md)
for the supported services and algorithms, and wolfCrypt's
[FIPS 140-3 Security Policy](https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp5548.pdf) (Certificate #5548, document version 1.5,
CAVP certificate A7470) for the module validation details.

An algorithm being available from wolfJCE or wolfJSSE does not make it FIPS
approved. The providers register what the native wolfCrypt FIPS build provides,
and some Security Policy restrictions are documented rather than enforced in
code. The Security Policy defines which algorithms are validated and how they
may be used, and applications are responsible for following it. The startup
checks verify where algorithms come from, not whether a use is approved.

### Certificate #5548 Restrictions Set by the Image

Algorithms that wolfSSL FIPS v5.2.3 leaves out, such as DES, 3DES, RC4,
ChaCha20 and EdDSA, are not offered by wolfJCE or wolfJSSE. On top of that, the
image sets these restrictions to match the Certificate #5548 Security Policy
(a few are stock JDK 25 values that already match):

| Restricted | Reason (Certificate #5548) | Set in |
|---|---|---|
| MD5 | Not approved | native `./configure --disable-md5` (Dockerfile) |
| MD4 (JDK-internal, used by Kerberos `rc4-hmac`) | Not in the module | `jdk.crypto.disabledAlgorithms` |
| MD2, MD4, MD5, RC4, DES and 3DES in certificate chains and signed JARs | Not in the approved algorithm table | `MD2`, `MD4`, `MD5`, `RC4`, `DES`, `DESede` in `jdk.certpath` and `jdk.jar.disabledAlgorithms` |
| `SHA1withECDSA`, signing and verification | ECDSA is approved with SHA-2 and SHA-3 only | `jdk.crypto.disabledAlgorithms`, `jdk.certpath.disabledAlgorithms` |
| `SHA3-224withRSA` to `SHA3-512withRSA`, signing and verification | RSA signatures are approved with SHA-2, plus SHA-1 for verification only | `jdk.crypto.disabledAlgorithms`, `jdk.certpath.disabledAlgorithms` |
| RSA encryption with padding: `RSA`, `RSA/ECB/PKCS1Padding`, `RSA/ECB/OAEPWithSHA-1AndMGF1Padding`, `RSA/ECB/OAEPWithSHA-256AndMGF1Padding` (and the same OAEP names without the hyphen) | Key transport is not claimed. The approved RSA service is the raw primitive, so `RSA/ECB/NoPadding` stays available | `jdk.crypto.disabledAlgorithms` |
| DSA signatures | DSA is approved for key generation only | `DSA` in `jdk.certpath`, `jdk.jar` and `jdk.tls.disabledAlgorithms` |
| Ed25519, Ed448, X25519, X448 | Not in the module | `jdk.disabled.namedCurves`, and `Ed25519`, `Ed448`, `EdDSA` in `jdk.certpath`, `jdk.jar` and `jdk.tls.disabledAlgorithms` |
| RSA keys under 1024 bits in certificate chains | RSA signatures are approved with 2048, 3072 and 4096-bit keys, and 1024-bit keys only for legacy verification | `RSA keySize < 1024` in `jdk.certpath.disabledAlgorithms` |
| RSA keys under 2048 bits in signed JARs | As above (stricter limit kept from the OpenJDK 19 image) | `RSA keySize < 2048` in `jdk.jar.disabledAlgorithms` |
| EC keys under 224 bits (P-192) | ECDSA is approved on P-224 to P-521, and 192-bit keys only for legacy verification | `EC keySize < 224` in `jdk.certpath`, `jdk.jar` and `jdk.tls.disabledAlgorithms` |
| DH groups under 2048 bits in TLS | Diffie-Hellman is approved with ffdhe2048 to ffdhe8192 | `DH keySize < 2048` in `jdk.tls.disabledAlgorithms` |
| TLS 1.2 without Extended Master Secret | The approved TLS 1.2 KDF requires EMS (RFC 7627) | `-Djdk.tls.allowLegacyMasterSecret=false` in `JAVA_TOOL_OPTIONS` (Dockerfile) |
| Kerberos DES, 3DES and RC4 encryption types | Not in the module | `permitted_enctypes` and `allow_weak_crypto = false` in `/etc/krb5.conf` |
| SASL NTLM, CRAM-MD5 and DIGEST-MD5 | NTLM needs DES, which is not in the module. CRAM-MD5 and DIGEST-MD5 need MD5, which is not approved | `jdk.sasl.disabledMechanisms` |

wolfJSSE reads only the protocol names and the `keySize` minimums from
`jdk.tls.disabledAlgorithms`. For its other entries, see
[TLS Restrictions](#tls-restrictions-where-each-is-enforced).

Security Policy restrictions that the image does not enforce include:

- SHA-1 RSA signing (`SHA1withRSA`, or `RSASSA-PSS` with SHA-1 parameters).
  Only verification is approved, and `java.security` cannot allow verification
  without also allowing signing.
- RSA-PSS with a salt length other than the hash length. CAVP certificate
  A7470 tested RSA-PSS only with the salt length equal to the hash length.
- RSA keys of 1024 bits in TLS. They are allowed for legacy verification only,
  not for signing. A wolfJSSE client also accepts a server certificate with a
  smaller RSA key.
- ECDH on P-224 in TLS. Native wolfSSL offers `secp224r1`, but ECDH is approved
  on P-256, P-384 and P-521 only.
- RSA encryption transformations written with extra whitespace (spaces, tabs
  or newlines), for example `"RSA/ECB/PKCS1Padding "`.
  `jdk.crypto.disabledAlgorithms` matches the transformation as written
  (ignoring case), and `Cipher` then trims the whitespace around each part.
- The key size for raw RSA (`RSA/ECB/NoPadding`). The Security Policy requires
  keys of 2048 bits or more, and `java.security` cannot set a key size limit
  for a `Cipher`.
- Signatures built by hand with raw RSA. A raw RSA private key operation is the
  same math as RSA signing, so `RSA/ECB/NoPadding` can produce a signature over
  any hash, including SHA-1. The signature rules above still apply to them.
- TLS peer certificate chains. wolfJSSE verifies them natively, so the
  `jdk.certpath.disabledAlgorithms` entries above (for example `SHA1withECDSA`)
  do not apply there. See
  [TLS Restrictions](#tls-restrictions-where-each-is-enforced).
- CRL and OCSP response signatures in wolfJCE PKIX validation. wolfJCE checks
  `jdk.certpath.disabledAlgorithms` against the certificates only (signature
  algorithm and public key), and verifies CRLs and OCSP responses natively.

AES-CTS (Kerberos AES encryption types) runs outside the module on top of its
validated AES-CBC. See [Kerberos Configuration](#kerberos-configuration).

PBKDF2 (WKS key protection, Kerberos password-based keys) is available and is
built on the module's validated HMAC. PBKDF2 itself will be validated on an
upcoming wolfCrypt FIPS 140-3 certificate.

**Using a different module or certificate:** these restrictions are tied to
Certificate #5548. If migrating to a new or different FIPS 140-3 certificate,
check each one against the other certificate's Security Policy, and adjust:

- `java.security`: `jdk.crypto.disabledAlgorithms`,
  `jdk.certpath.disabledAlgorithms`, `jdk.jar.disabledAlgorithms`,
  `jdk.tls.disabledAlgorithms`, `jdk.disabled.namedCurves`,
  `jdk.sasl.disabledMechanisms` and `jdk.security.legacyAlgorithms` (warnings
  only)
- `/etc/krb5.conf` (`krb5.conf` in this directory): the Kerberos encryption
  types
- `Dockerfile`: the wolfSSL bundle name and its SHA-256, the native
  `./configure` options and `JAVA_TOOL_OPTIONS`
- The startup checks (`src/main/FipsInitCheck.java`: the expected module
  version and the expected and unavailable algorithm lists) and the test
  image (`CryptoTestSuite.java`)

A derived image that changes `java.security` or `krb5.conf` must update the
integrity manifest (see [Derived Images](#derived-images)).

### JDK 25 APIs Without a FIPS Implementation

These JDK APIs throw `NoSuchAlgorithmException` on this image, because the
algorithms are not provided by wolfJCE and the Sun implementations are
removed:

- `javax.crypto.KDF` (JDK 25, JEP 510), e.g. `KDF.getInstance("HKDF-SHA256")`.
  Native HKDF is used internally by TLS 1.3 in wolfSSL, but is not exposed as
  a Java `KDF` service.
- `javax.crypto.KEM` (`ML-KEM`, `DHKEM`).
- ML-DSA, HSS/LMS, EdDSA and XDH (X25519/X448).
- PEM encoding of encrypted private keys (JEP 470 preview), which uses
  `jdk.epkcs8.defaultAlgorithm=PBEWithHmacSHA256AndAES_128`, a PBES2 cipher
  that wolfJCE does not implement.

## Operational Environment

For FIPS compliance, the Operating Environment (OE) this container runs on
must be listed in the Security Policy for wolfCrypt FIPS Certificate #5548.
Contact fips@wolfssl.com for more information.

## Random Entropy

Native wolfCrypt seeds its Hash\_DRBG from /dev/urandom and /dev/random by
default, through its internal `wc_GenerateSeed()` function. The entropy source
can be changed when native wolfSSL is built, depending on the Operating
Environment validation. For questions about entropy sources, contact
support@wolfssl.com or fips@wolfssl.com.

## Security Configuration

This image changes the base image's security configuration as follows:

1. Set wolfJCE as the primary security provider
2. Set wolfJSSE as the secondary security provider
3. Install the filtered Sun provider wrappers (FilteredSun,
   FilteredSunRsaSign, FilteredSunEC), which expose only non-cryptographic
   services
4. Remove the stock Sun cryptography providers (SunJCE, SunJSSE, SunPKCS11,
   SunPCSC, etc.) from java.security
5. Set JVM module access and native access flags for the providers
6. Convert system cacerts from PKCS12 to WKS format for FIPS compliance
7. Set default KeyStore type to WKS for FIPS compliance
8. Configure Kerberos (krb5) to use only FIPS-compliant encryption types

To see every property change, diff `java.security` against
`java.security.original` (the stock Azul Zulu 25.0.4.1 file).

### Kerberos Configuration

`/etc/krb5.conf` restricts Kerberos to AES encryption types. Without it, Java
Kerberos tries to generate keys for all encryption types, including DES, 3DES
and RC4, which are not in the wolfCrypt FIPS module.

**Permitted Encryption Types** (in order of preference):
- `aes256-cts-hmac-sha384-192` (etype 20, RFC 8009)
- `aes128-cts-hmac-sha256-128` (etype 19, RFC 8009)
- `aes256-cts-hmac-sha1-96` (etype 18)
- `aes128-cts-hmac-sha1-96` (etype 17)

**Disabled Encryption Types:**
- DES-CBC-CRC (etype 1)
- DES-CBC-MD5 (etype 3)
- DES3-CBC-SHA1 (etype 16)
- RC4-HMAC (etype 23)
- All other non-AES encryption types

It also sets `allow_weak_crypto = false`. Applications that use Kerberos
inherit these restrictions.

**Note:** Applications that use their own krb5.conf should permit only the
AES encryption types. These use AES in CTS mode (`AES/CTS/NoPadding`). Native
wolfSSL runs the CTS step outside the FIPS module, on top of the module's FIPS
validated AES-CBC, and password-based keys use PBKDF2.

**Password length:** Kerberos derives AES keys from passwords with PBKDF2-HMAC,
using the password as the HMAC key. wolfCrypt FIPS requires HMAC keys of at
least 14 bytes, so deriving a key from a shorter password (for example
`new KerberosKey(principal, password, "aes256-cts-hmac-sha1-96")`, or a JAAS
`Krb5LoginModule` password login) fails with `FIPS Mode HMAC Minimum Key or
Salt Length error`. Use passwords of 14 or more characters, or keytabs. Keys
read from a keytab are not derived from a password and are not affected.

A JAAS login configuration can be passed with
`-Djava.security.auth.login.config=...` (`policy.allowSystemProperty=true`,
the stock JDK value).

### Provider Discovery, Module Path and ServiceLoader

The provider JARs are loaded from the JVM module path, set in the image's
`JAVA_TOOL_OPTIONS` (see [JVM Module Requirements](#jvm-module-requirements)),
not from the application class path. Every JVM in the container reads
`JAVA_TOOL_OPTIONS`, so the `java.security` provider list and
`ServiceLoader.load(Provider.class)` find the providers without any
application changes, for all launch forms:

```bash
docker run wolfssl-openjdk-fips-zulu25-debian13:latest java -cp /app/myapp.jar com.example.MyApplication
docker run wolfssl-openjdk-fips-zulu25-debian13:latest java -jar /app/myapp.jar
docker run -e CLASSPATH=/app/myapp.jar wolfssl-openjdk-fips-zulu25-debian13:latest java MyApp
```

JDK tools that ignore the `CLASSPATH` environment variable (`keytool`, `jar`,
`jarsigner`, `jshell`) also get the providers.

Adding the provider JARs to the class path as well (for example
`-cp "/app/myapp.jar:/usr/share/java/*"`) still works: the modules on the
module path take precedence.

All providers include `META-INF/services/java.security.Provider` service
registrations (`provides java.security.Provider` in the module descriptors):
- `com.wolfssl.provider.jce.WolfCryptProvider`
- `com.wolfssl.provider.jsse.WolfSSLProvider`
- `com.wolfssl.security.providers.FilteredSun`
- `com.wolfssl.security.providers.FilteredSunRsaSign`
- `com.wolfssl.security.providers.FilteredSunEC`

Two rules for applications and deployments:

- **Append to `JAVA_TOOL_OPTIONS`, do not replace it.** For example, use
  `-e JAVA_TOOL_OPTIONS="<image value> -Xmx2g"`, or pass JVM options through
  `JAVA_OPTS` / `USER_JAVA_OPTS` (see [Environment Variables](#environment-variables)).
  Tools that inject agents through `JAVA_TOOL_OPTIONS` (APM agents, Kubernetes
  operators) must append to the image value. If it is replaced, no JVM gets
  the wolfSSL providers. The entrypoint prints a warning, and the startup
  checks fail.
- **Applications with their own `--module-path`** must include the three
  provider JARs, because the last `--module-path` option wins. Otherwise the
  JVM does not start (`Module com.wolfssl.security.providers not found`):

  ```bash
  java --module-path=/usr/share/java/wolfcrypt-jni.jar:/usr/share/java/wolfssl-jsse.jar:/usr/share/java/filtered-providers.jar:/app/mods ...
  ```

### WolfSSLKeyStore (WKS) Format

For FIPS 140-3 compliance, wolfJCE requires the WolfSSLKeyStore (WKS) format
for all KeyStore objects and files. The image build converts the system cacerts
file (PKCS12 in JDK 25) to WKS.

**WKS Format Features:**
- Custom KeyStore implementation designed for FIPS 140-2/140-3 compatibility
- Uses AES-CBC-256 with HMAC-SHA512 in Encrypt-then-MAC mode for key protection
- PBKDF2-HMAC-SHA512 with 210,000 iterations (default) for key derivation
- 16-byte random salt per key storage operation
- Stores PrivateKey, Certificate, and SecretKey objects securely

**FIPS Requirement:**
JKS and PKCS12 KeyStores are not compatible with FIPS validated cryptography,
and must be converted to WKS before use in this container.

**JKS / PKCS12 mapped to WKS:**
For application code that requests a `JKS` or `PKCS12` KeyStore and cannot be
changed, wolfJCE can register those types as WKS. Set either or both in
`java.security`, before building the image or in a derived image (see
[Derived Images](#derived-images)):

```
wolfjce.mapJKStoWKS=true
wolfjce.mapPKCS12toWKS=true
```

`KeyStore.getInstance("JKS")` then returns wolfJCE's WKS KeyStore, so any
KeyStore file loaded through it must already be in WKS format. The startup
checks read the same properties: they allow that type from wolfJCE and mark it
`[mapped to WKS by ...]`, with no changes to `FipsInitCheck.java`.

For more details on WKS format, see the wolfJCE documentation:

[WolfSSLKeyStore Implementation Details and Usage](https://github.com/wolfSSL/wolfcrypt-jni/blob/master/README_JCE.md#wolfsslkeystore-wks-implementation-details-and-usage)

[wolfSSL KeyStore Design Notes](https://github.com/wolfSSL/wolfcrypt-jni/blob/master/docs/design/WolfSSLKeyStore.md)

**Using keytool in the container:**
`keytool` loads wolfJCE (WKS, crypto) and the filtered providers (X.509
CertificateFactory) from the module path like any other JVM, so no extra
options are needed:

```bash
keytool -genkeypair -alias server -keyalg EC -groupname secp256r1 -dname CN=server \
    -storetype WKS -keystore server.wks \
    -storepass changeitchangeit -keypass changeitchangeit

keytool -list -cacerts -storepass changeitchangeit
```

WKS passwords must be at least 14 characters (FIPS minimum HMAC key length).

**System-wide WKS Configuration:**
`keystore.type=WKS` in java.security makes WKS the default KeyStore type. The
WKS cacerts password is `changeitchangeit`, the stock `changeit` doubled, since
wolfCrypt FIPS requires HMAC keys of at least 14 bytes.

**Protection Against Overwrites:**
The WKS cacerts file is root-owned with read-only permissions (444), and its
checksum is verified at startup. The container runs as a non-root user, so
applications cannot modify it. In this base image, `cacerts` is a regular
file owned by the Azul `zulu25-ca-jre-headless` package (it is not managed by
`ca-certificates` / `ca-certificates-java`). To add CA certificates in a
derived image, see [WKS cacerts File Issues](#wks-cacerts-file-issues).

## Known Gaps Compared to a Stock JDK 25

wolfJSSE implements TLS, and wolfJCE certificate path validation, with native
wolfSSL. Some JDK security properties that SunJSSE and the SUN PKIX
implementation honor therefore have no effect here. The same applies to the
OpenJDK 19 image.

### TLS Restrictions: Where Each Is Enforced

| Restriction | Stock JDK 25 | This image |
|---|---|---|
| Protocol versions in `jdk.tls.disabledAlgorithms` (SSLv3, TLSv1, TLSv1.1) | SunJSSE | wolfJSSE (exact wolfSSL protocol names). |
| `DTLSv1.0` in `jdk.tls.disabledAlgorithms` | SunJSSE | No effect (wolfSSL calls it `DTLSv1`). wolfJSSE always disables DTLS 1.0 and 1.2 itself. **DTLS 1.3 is available** (`SSLContext.getInstance("DTLSv1.3")`) |
| `DH keySize < 2048`, `EC keySize < 224` in `jdk.tls.disabledAlgorithms` | SunJSSE | wolfJSSE passes them to native wolfSSL for the handshake. The client refuses smaller DH groups and does not offer P-192 |
| RSA minimum key size for TLS | SunJSSE (no `RSA keySize` token in the stock or FIPS property) | No `RSA keySize <` token is set. Native wolfSSL refuses RSA keys under 1024 bits for the image's own key and trusted CA certificates, but a wolfJSSE client accepts a server certificate with a smaller key |
| `TLS_RSA_*`, `ECDH` (static), 3DES, RC4, NULL, anon cipher suites | SunJSSE | Native wolfSSL FIPS build: these suites are not compiled in. The startup checks fail if the default SSLContext enables or supports a 3DES or RC4 suite (a cipher outside the module). The others are native compile-time choices |
| SHA-1 handshake signatures (`rsa_pkcs1_sha1`, `ecdsa_sha1` `usage HandshakeSignature`) | SunJSSE | Native wolfSSL: SHA-1 signature algorithms are not offered in the ClientHello |
| `jdk.certpath.disabledAlgorithms` for TLS peer chains (e.g. `SHA1 jdkCA & usage TLSServer`) | SunJSSE + PKIX | **Not enforced**: wolfJSSE verifies peer chains with the native wolfSSL certificate manager, and does not call a CertPathValidator. A SHA-1 signed server chain is accepted |
| `jdk.security.caDistrustPolicies` (SYMANTEC\_TLS, ENTRUST\_TLS, CAMERFIRMA\_TLS, CHUNGHWA\_TLS) | SunJSSE | **Not enforced** (see below) |
| `lib/security/blocked.certs` | SunJSSE + PKIX | **Not enforced** |
| `jdk.tls.keyLimits`, `jdk.tls.legacyAlgorithms` | SunJSSE | Not used by wolfJSSE |

`jdk.certpath.disabledAlgorithms` is honored by the wolfJCE
`CertPathValidator` (PKIX) for application-level certificate path validation.

### Distrusted Certificate Authorities

Stock JDK 25 distrusts TLS server certificates issued after per-CA cutoff dates
and anchored by the following roots, which are still present in the JDK cacerts
file and therefore in this image's WKS cacerts:

- SYMANTEC\_TLS (cutoff 2019-04-16): `geotrustglobalca`, `geotrustprimaryca`,
  `geotrustprimarycag2`, `geotrustprimarycag3`, `geotrustuniversalca`,
  `thawteprimaryrootca`, `thawteprimaryrootcag2`, `thawteprimaryrootcag3`,
  `verisignclass3g3ca`, `verisignclass3g4ca`, `verisignclass3g5ca`,
  `verisignuniversalrootca`
- ENTRUST\_TLS (cutoff 2024-11-11): `entrust2048ca`, `entrustevca`,
  `entrustrootcaec1`, `entrustrootcag2`, `entrustrootcag4`
- CAMERFIRMA\_TLS (cutoff 2025-04-15): `camerfirmachambersca`
- CHUNGHWA\_TLS (cutoff 2026-03-17): `chunghwaepkirootca`

wolfJSSE does not implement `jdk.security.caDistrustPolicies` yet, so these
roots are fully trusted for TLS in this image. Applications that must not trust
these roots should use a custom WKS trust store without them.

### Extended Master Secret (TLS 1.2)

The v5.2.3 Security Policy requires the TLS 1.2 Extended Master Secret (EMS,
RFC 7627) for the TLS 1.2 KDF in the approved mode of operation. The image sets
`-Djdk.tls.allowLegacyMasterSecret=false` in `JAVA_TOOL_OPTIONS`, so wolfJSSE
requires EMS: a TLS 1.2 handshake with a client or server that does not support
EMS fails, instead of using the legacy TLS 1.2 master secret. TLS 1.3 is not
affected. The startup checks report the setting, and fail if it is set but
wolfJSSE or native wolfSSL cannot enforce it (this needs a wolfssljni build
with `jdk.tls.allowLegacyMasterSecret` support and native wolfSSL 5.9.4 or
later).

To connect to TLS 1.2 peers without EMS, outside the approved mode, pass
`-Djdk.tls.allowLegacyMasterSecret=true` on the `java` command line. It
overrides the `JAVA_TOOL_OPTIONS` value.
`-Djdk.tls.useExtendedMasterSecret=false` also leaves the approved mode: it
turns EMS off, and `jdk.tls.allowLegacyMasterSecret` is then ignored. Values
of `jdk.tls.allowLegacyMasterSecret` other than `true` and `false` make the
startup checks and TLS handshakes fail.

### Scope of the Provider Restrictions

The provider configuration controls which implementation the JDK returns for
`getInstance(algorithm)` and `getInstance(algorithm, "registeredName")` calls.
It does not control:

- **Signed JAR verification**: the JDK verifies signed JARs with a fixed list
  of its built-in providers (SUN, SunRsaSign, SunEC, SunJCE), independent of
  java.security.
- **Explicit Provider objects**: application code cannot construct the stock
  Sun providers directly, because `sun.security.provider`, `sun.security.rsa`,
  and `sun.security.ec` are not exported to it. An application that adds its
  own `--add-exports` / `--add-opens` flags, or bundles another provider such
  as Bouncy Castle and uses it explicitly, can still bypass the provider list.
  No JDK 24+ mechanism prevents this, since the Security Manager is removed.
- **JDK-internal private providers**: for example Kerberos `rc4-hmac` key
  derivation uses an internal MD4 implementation directly. The image blocks
  it with the `MessageDigest.MD4` entry in `jdk.crypto.disabledAlgorithms`
  (key creation fails with `IllegalArgumentException: key creation error`),
  and the Kerberos configuration does not permit `rc4-hmac`. Setting
  `-Djdk.crypto.disabledAlgorithms` replaces the whole `java.security` value,
  so an override must repeat the image's entries (`MessageDigest.MD4`, the
  disabled signatures and RSA ciphers).
- **Runtime provider changes**: application code can add services to a
  registered provider with `Provider.put()`, or register its own provider that
  points at JDK classes. wolfJCE, wolfJSSE and the filtered providers reject
  `put()` / `remove()` after construction.
- **Runtime security property changes**: application code can call
  `Security.setProperty()` before the first cryptographic operation, for
  example to change `security.provider.N`, `jdk.crypto.disabledAlgorithms` or
  `wolfssl.filtered.sun.additionalServices`. The JVM reads these when it first
  needs them, so the change applies to that JVM. Later changes have no effect.
- **Launch configuration**: whoever launches the container can change the
  image's defaults, for example with a different user, entrypoint or
  environment. This image protects and checks the following:
  - **Protected files**: the non-root container user cannot change protected
    files. Root changes (`docker run --user root`, or a derived image) to files
    in the integrity manifest fail the startup checks unless the checksums are
    regenerated.
  - **When the startup checks run**: once, in their own JVM, before the
    application starts. Overriding the entrypoint or setting
    `FIPS_CHECK=false` skips them.
  - **What the startup checks do**: they check options that come in through
    the environment (`JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`, `JAVA_OPTS`,
    library paths). They detect a look-alike provider module or native library,
    and fail on `--patch-module`, `--upgrade-module-path` and
    `-Xbootclasspath/a`.
  - **What they do not see**: options that appear only on the application's
    own `java` command line, for example a different module named
    `com.wolfssl.wolfcrypt` on its own `--module-path`.
  - **Java agents** (`-javaagent`, `-agentlib`, `-agentpath`) are allowed.
    They can modify loaded classes, including the providers, so use only
    trusted agents.

  Replacing or unsetting `JAVA_TOOL_OPTIONS`, or removing wolfJCE at runtime,
  fails closed: the JVM then has no cryptography providers at all. Enforcing
  the launch configuration belongs to deployment policy, for example admission
  control that forbids running as root and forbids command and environment
  overrides, and a read-only root filesystem.

## Derived Images

- Keep the base image's apt pin of the `zulu25*` packages to 25.0.4.1
  (`/etc/apt/preferences`). Installing another version replaces `java.security`
  and `cacerts` with stock files and fails the integrity check.
- Keep the image's `JAVA_TOOL_OPTIONS` (`ENV JAVA_TOOL_OPTIONS="$JAVA_TOOL_OPTIONS
  <your options>"`), since it carries the provider module path. See
  [Provider Discovery](#provider-discovery-module-path-and-serviceloader).
- The image runs as non-root user `10001:10001` (`wolfssl`), with
  `WORKDIR /home/wolfssl`. Derived images switch to `USER root` for steps that
  install packages or write outside `/home/wolfssl` (for example creating
  `/app`), and back to `USER 10001:10001` at the end, as the
  [basic test image](test-images/basic-test-image/Dockerfile) does. Running
  with another non-root `--user` also works.
- The integrity check covers `libwolfssl.so*`, the JNI libraries, the provider
  JARs, `java.security`, `cacerts`, `/etc/krb5.conf` and `FipsInitCheck.class`.
  A derived image that changes one of these files (for example adding a CA
  certificate to `cacerts`) must run
  `/usr/local/bin/update-integrity-checksums.sh` as root afterwards, or the
  container fails its startup integrity check. For example, to grant Sun's
  MD5, which is not FIPS validated and needs an approved exception (see
  [Granting Additional Sun Services](#granting-additional-sun-services)):

  ```dockerfile
  USER root
  RUN JS=$JAVA_HOME/conf/security/java.security \
      && chmod 644 $JS \
      && echo "wolfssl.filtered.sun.additionalServices=MessageDigest.MD5" >> $JS \
      && chmod 444 $JS \
      && /usr/local/bin/update-integrity-checksums.sh
  USER 10001:10001
  ```

  To also use SASL CRAM-MD5 or DIGEST-MD5, add
  `&& echo "jdk.sasl.disabledMechanisms=NTLM" >> $JS \` after the MD5 line.

## FIPS Container Verification Tests / Docker Entrypoint

The entrypoint script (`docker-entrypoint.sh`) runs these steps when the
container starts:

1. Configures debug logging based on environment variables:
    - `WOLFJCE_DEBUG`
    - `WOLFJSSE_DEBUG`
    - `WOLFJSSE_ENGINE_DEBUG`
2. Sets library paths for JNI libraries in standard Debian locations, and
   warns if `JAVA_TOOL_OPTIONS` no longer carries the provider module settings.
3. Verifies integrity of the FIPS native libraries, JNI libraries, provider
   JARs, `java.security`, `cacerts` and `/etc/krb5.conf` against the checksums
   in `/opt/wolfssl-fips/checksums/libraries.sha256`.
4. Runs the startup checks (`FipsInitCheck.java`):
    - List the registered security providers (informational)
    - Verify wolfJCE and wolfJSSE are registered at priority 1 and 2
    - Verify the wolfSSL provider modules were loaded from their JARs in
      `/usr/share/java`, and the native libraries from `/usr/local/lib` and
      `/usr/lib/jni` (detects look-alike modules or libraries that come in
      through the environment)
    - Fail on JVM options that replace classes (`--patch-module`,
      `--upgrade-module-path`, `-Xbootclasspath/a`)
    - Verify wolfJCE reports a native wolfCrypt FIPS build (`Fips.enabled`)
    - Verify the native FIPS module version (`Fips.fipsVersion`) is 5
      (wolfCrypt FIPS v5.2.3)
    - Verify the FIPS conditional algorithm self tests (CASTs) passed, and
      that the module is not in an error state (`wolfCrypt_GetStatus_fips`)
    - Verify the system cacerts file is in WKS format. If not, the error names
      its format (JKS, JCEKS or PKCS12)
    - Force a wolfCrypt FIPS POST run by calling one service (MessageDigest)
    - Check the java.security provider list for providers that are not allowed
    - Instantiate the expected algorithms without naming a provider (message
      digests, MACs, ciphers, signatures, PBKDF2 `SecretKeyFactory`,
      `SSLContext`, `KeyManagerFactory`, `TrustManagerFactory`,
      PKIX `CertPathBuilder` / `CertPathValidator`, `KeyStore` WKS), and verify
      each one comes from wolfJCE or wolfJSSE
    - Verify that algorithms outside the FIPS boundary are unavailable. Each
      `getInstance()` must report the algorithm as not available with the
      exception that API documents (for example `NoSuchAlgorithmException`).
      Any other exception fails the check. An algorithm granted in
      `java.security` is allowed from the granting filtered provider
    - List every service of every registered provider, and verify each one is
      allowed for its provider: wolfJCE and wolfJSSE may offer any service,
      FilteredSun / FilteredSunEC / FilteredSunRsaSign exactly the services
      listed in [Custom Filtered Security Providers](#custom-filtered-security-providers)
      (all required) plus any granted in `java.security`
      ([Granting Additional Sun Services](#granting-additional-sun-services)),
      and the JDK providers SunJGSS, SunSASL, JdkSASL, XMLDSig and JdkLDAP
      only their non-cryptographic service types. Any other provider or service
      fails the check. SASL mechanisms that are disabled or cannot be used are
      marked in this listing and the provider listing (Changes item 11)
    - Verify `SecureRandom.getInstanceStrong()` comes from wolfJCE and
      `SSLContext.getDefault()` from wolfJSSE
    - List the default `SSLContext`'s TLS protocols (informational), and verify
      it enables and supports no cipher suite with a cipher or MAC outside the
      wolfCrypt FIPS module (listed in Changes item 9)
    - Report whether TLS 1.2 requires the Extended Master Secret, and fail if
      `jdk.tls.allowLegacyMasterSecret=false` is set but wolfJSSE or native
      wolfSSL cannot enforce it, or its value is not `true` or `false`

### Running FIPS Container Verification Tests Manually

```bash
# Run FIPS Container Verification Tests
docker run wolfssl-openjdk-fips-zulu25-debian13:latest java -cp /opt/wolfssl-fips/bin FipsInitCheck

# Run the integrity check
docker run -it wolfssl-openjdk-fips-zulu25-debian13:latest /usr/local/bin/integrity-check.sh
```

## Troubleshooting

### Container Fails to Start

If the container exits with FIPS POST failure:

1. Check the wolfSSL password is correct
2. Verify the wolfSSL commercial FIPS package is valid
3. Enable debug logging: `WOLFJCE_DEBUG=true` and `WOLFJSSE_DEBUG=true`

If a provider is missing at runtime, rerun with
`-Djava.security.debug=provider`. The JDK silently skips providers that fail
to load, for example when `JAVA_TOOL_OPTIONS` was replaced instead of
appended to.

### WKS cacerts File Issues

Common cacerts errors in derived images:

1. **"Permission denied" when modifying cacerts**: The file is root-owned and
   read-only, and the container runs as a non-root user. Change it in a
   derived image Dockerfile as root, then regenerate the integrity
   checksums, otherwise the container fails its startup integrity check
   (`cacerts - INTEGRITY FAILURE`):

   ```dockerfile
   USER root
   COPY my-ca.der /tmp/my-ca.der
   RUN chmod 644 $JAVA_HOME/lib/security/cacerts \
       && keytool -importcert -noprompt -alias my-ca -file /tmp/my-ca.der \
           -cacerts -storepass changeitchangeit \
       && chmod 444 $JAVA_HOME/lib/security/cacerts \
       && rm -f /tmp/my-ca.der \
       && /usr/local/bin/update-integrity-checksums.sh
   USER 10001:10001
   ```

2. **"Unable to load system cacerts file as WKS: it is in PKCS12 format"**
   (or JKS / JCEKS, the message ends with the WKS error "Invalid magic
   number ..., KeyStore not of type WKS"): the cacerts file was overwritten,
   most likely by an upgrade of the `zulu25*` packages, which ship a PKCS12
   cacerts (see [Derived Images](#derived-images)). Use the base image's WKS
   cacerts file instead.

### Algorithms Unavailable

wolfJCE and wolfJSSE offer only the algorithms that native wolfSSL compiles
in. Algorithms outside that set, such as MD5, DES or JKS / PKCS12 KeyStores,
are not available. Applications may need to switch to other algorithms or to
the WKS KeyStore type. Being available does not make an algorithm FIPS
approved (see [FIPS Compliance](#fips-compliance)).

### TLS 1.2 Handshake Fails: Extended Master Secret

`SSLHandshakeException: Extended Master Secret required but not negotiated
with peer (error code: -414)` means the TLS 1.2 peer does not support the
Extended Master Secret, which the image requires (see
[Extended Master Secret (TLS 1.2)](#extended-master-secret-tls-12)). A
wolfJSSE peer reports `received alert fatal error (error code: -313)`. Use
TLS 1.3, enable EMS on the peer, or, outside the approved mode, pass
`-Djdk.tls.allowLegacyMasterSecret=true` on the `java` command line.

### TLS Handshake Fails: Self-Signed Certificate

`SSLHandshakeException: ASN self-signed certificate error (error code: -275)`
when the peer's self-signed certificate is in the trust store means the
certificate is not marked as a CA. wolfJSSE only accepts a self-signed
certificate as a trust anchor if it has BasicConstraints `CA:TRUE`, and
`keytool -genkeypair` does not add that by default. Generate the peer
certificate with `keytool -genkeypair ... -ext bc:c`, or use a certificate
issued by a CA in the trust store.

### Debug Logging

Set `WOLFJCE_DEBUG` (wolfJCE), `WOLFJSSE_DEBUG` (wolfJSSE) or
`WOLFJSSE_ENGINE_DEBUG` (wolfJSSE SSLEngine) to `true` to enable debug logging.
The entrypoint applies them to `java` and `jshell` commands, and to the
startup checks.

```bash
docker run -it -e WOLFJCE_DEBUG=true \
           -e WOLFJSSE_DEBUG=true \
           wolfssl-openjdk-fips-zulu25-debian13:latest
```

## Version Information

- **wolfSSL**: 5.9.4 Commercial FIPS v5.2.3 (Certificate #5548)
- **Base Image**: `azul-zulu:25.36-25.0.4.1-jdk-debian13` (Azul Zulu 25.0.4.1,
  Debian 13)
- **wolfcrypt-jni**: Master branch (GitHub)
- **wolfssljni**: Master branch (GitHub)

`/opt/wolfssl-fips/BUILD_INFO` in the image records what it was built from:
the base image, wolfSSL bundle and its SHA-256, and the wolfcrypt-jni and
wolfssljni repository, branch and commit. A local directory
is recorded as `local`, plus its commit if it includes `.git` (`-dirty` if
tracked files have uncommitted changes). The image labels include the base
image (`docker inspect`).

## Documentation

- [wolfCrypt JNI/JCE Manual](https://www.wolfssl.com/documentation/manuals/wolfcryptjni/)
- [wolfSSL JNI/JSSE Manual](https://www.wolfssl.com/documentation/manuals/wolfssljni/)

## Support

For problems with this container, check the container logs for FIPS error
messages first. Email support@wolfssl.com for wolfSSL issues or questions.
