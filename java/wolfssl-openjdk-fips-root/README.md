# wolfSSL OpenJDK FIPS Root Container

This is an OpenJDK 19 Docker image based on [rootpublic/openjdk:19-jdk-bookworm-slim](https://hub.docker.com/r/rootpublic/openjdk)
that integrates wolfSSL's FIPS 140-3 validated cryptographic library
(Certificate #4718), replacing all non-FIPS compliant Java cryptography
providers with wolfJCE and wolfJSSE. Only Java-based cryptography is in
scope for FIPS compliance in this container.

An active wolfCrypt FIPS license is needed to use this container. The associated
.7z archive password will also be provided when the appropriate FIPS license
is acquired from wolfSSL Inc. Please contact fips@wolfssl.com for more
information.

## Features

- **FIPS 140-3 Validated Cryptography**: Uses wolfSSL's FIPS validated wolfCrypt
cryptographic module, [FIPS Certificate #4718](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4718).
- **Multi-stage Build**: Optimized for minimal final image size.
- **Automatic Container Tests**: FIPS Power-On Self Test and container
verification tests executed on container startup.
- **Debug Support**: Configurable debug logging for JCE/JSSE providers.
- **Security Hardened**: Non-FIPS providers disabled or filtered, leaving only
wolfCrypt FIPS 140-3 validated algorithms available for cryptographic services.

## Components

- **Base Image**: Root.io OpenJDK 19 on Debian Bookworm Slim
- **Native wolfSSL/wolfCrypt**: Configured for FIPS 140-3 with JNI support
- **wolfCrypt JNI/JCE**: Java Cryptography Extension (JCE) provider
- **wolfSSL JNI/JSSE**: Java Secure Socket Extension (JSSE) provider
- **Filtered Sun Providers**: Custom wrappers for Sun providers that expose
non-cryptographic functionality (SunEC, SunRsaSign, SUN) while blocking
non-FIPS compliant cryptography services and algorithms
- **WKS cacerts**: System CA certificates converted to WolfSSL KeyStore format
and protected with read-only file permissions

## Directory Layout

The directory structure of this repository:

```
wolfssl-openjdk-fips-root/
├── README.md                       # Image documentation and details
├── build.sh                        # Docker image build script
├── Dockerfile                      # Container definition
├── docker-entrypoint.sh            # Container entry point script
├── java.security                   # FIPS Java security configuration
├── java.security.original          # Original Java security configuration
├── krb5.conf                       # FIPS Kerberos configuration (AES only)
├── scripts/                        # Utility scripts
│   └── integrity-check.sh          # Library integrity verification script
└── src/
    ├── main/
    │   ├── FipsInitCheck.java      # FIPS POST and container tests
    ├── providers/                  # Custom security providers
    │   ├── FilteredSun.java        # Filtered SUN provider wrapper
    │   ├── FilteredSunEC.java      # Filtered SunEC provider wrapper
    │   └── FilteredSunRsaSign.java # Filtered SunRsaSign provider wrapper
```

## Container Structure

When built, the container organizes files as follows:

```
/
├── etc/
│   └── krb5.conf                   # FIPS Kerberos configuration
├── usr/
│   ├── lib/
│   │   └── jni/                    # JNI libraries
│   │       ├── libwolfcryptjni.so  # wolfJCE JNI library
│   │       └── libwolfssljni.so    # wolfJSSE JNI library
│   ├── local/lib/
│   │   └── libwolfssl.so           # Native wolfSSL FIPS library
│   └── share/java/                 # JAR files (Std. Debian location)
│       ├── wolfcrypt-jni.jar       # wolfJCE provider
│       ├── wolfssl-jsse.jar        # wolfJSSE provider
│       └── filtered-providers.jar  # Custom filtered Sun provider wrappers
├── usr/local/openjdk-19/
│   └── conf/security/
│       └── java.security           # FIPS Java security configuration
├── opt/
│   └── wolfssl-fips/
│       ├── bin/                    # Compiled Java classes
│       │   ├── FipsInitCheck.class
│       │   └── com/                # Filtered provider classes
│       └── checksums/              # FIPS integrity verification
│           ├── wolfssl.sha256      # Native library checksums
│           └── providers.sha256    # JAR file checksums
├── usr/local/bin/
│   └── integrity-check.sh          # FIPS integrity verification script
└── docker-entrypoint.sh            # Container entrypoint
```

## Custom Filtered Security Providers

wolfJCE and wolfJSSE consume several non-cryptographic services from a few
of the default Sun providers. This dependency exists so wolfJCE and wolfJSSE
do not need to re-implement stable working functionality from base providers.
In order to protect Java applications from accidentally using non-FIPS compliant
cryptographic services from these Sun providers, this container implements
custom filtered provider wrappers that only expose non-cryptographic
services from these providers. The primary providers are then removed
from java.security and unregistered. The filtered providers use reflection
to look up original providers, get appropriate service and alias information,
then use that to create the delegating services.

The following list includes the services that are left exposed/available:

**SunEC** (FilteredSunEC.java):
- AlgorithmParameters (EC)
- KeyFactory (EC)

**SunRsaSign** (FilteredSunRsaSign.java):
- KeyFactory (RSA)
- KeyFactory (RSASSA-PSS)

**SUN** (FilteredSun.java):
- CertPathBuilder (PKIX)
- CertStore (Collection)
- CertStore (com.sun.security.IndexedCollection)
- CertificateFactory (X.509)
- Configuration (JavaLoginConfig)
- Policy (JavaPolicy)

### JVM Module Requirements
The filtered providers require specific JVM flags (set in `JAVA_TOOL_OPTIONS`)
for module access and reflection to work correctly. These flags are set in
the Dockerfile and are required for the filtered providers to function
properly:

- `--add-modules=jdk.crypto.ec` - EC cryptography module loading
- `--add-exports=jdk.crypto.ec/sun.security.ec=ALL-UNNAMED` - Export SunEC provider classes
- `--add-opens=jdk.crypto.ec/sun.security.ec=ALL-UNNAMED` - SunEC provider classes reflection access
- `--add-opens=java.base/java.security=ALL-UNNAMED` - Provider.Service field access
- `--add-opens=java.base/sun.security.provider=ALL-UNNAMED` - Sun provider classes
- `--add-opens=java.base/sun.security.util=ALL-UNNAMED` - UString class for attributes
- `--add-opens=java.base/sun.security.rsa=ALL-UNNAMED` - SunRsaSign provider classes
- `-Djava.library.path=/usr/lib/jni:/usr/local/lib` - JNI library path configuration

## Build Process

### Prerequisites

- Docker installed and running
- wolfSSL commercial FIPS package password (required for build)
    + Commercial wolfCrypt packages are provided directly via wolfSSL
    + This package has been tested with Certificate #4718 / FIPS 140-3 (v5.2.3)
    + Password must be supplied at image build time to extract .7z

### Build Options

The build script supports several options for customizing the build. If no
custom repo or branch are specified, and no local path is specified, the build
will default to cloning the master branch from wolfcrypt-jni and wolfssljni
repositories to pull in the latest JCE/JSSE provider code.

**Repository Configuration:**
- `--wolfcrypt-jni-repo URL` - Custom wolfcrypt-jni repository URL
- `--wolfcrypt-jni-branch BRANCH` - Custom wolfcrypt-jni branch
- `--wolfssl-jni-repo URL` - Custom wolfssljni repository URL
- `--wolfssl-jni-branch BRANCH` - Custom wolfssljni branch

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

# With verbose output and cache
./build.sh -p your_wolfssl_password -c -v

# Using custom repository and branch
./build.sh -p your_wolfssl_password --wolfcrypt-jni-repo https://github.com/myuser/wolfcrypt-jni.git --wolfcrypt-jni-branch feature-branch

# Using local development directories
./build.sh -p your_wolfssl_password --wolfcrypt-jni ../wolfcrypt-jni-dev --wolfssl-jni ../wolfssljni-dev
```

### Run the Container

```bash
# Basic run (shows Java version info)
docker run -it wolfssl-openjdk-fips-root:latest

# With debug logging
docker run -e WOLFJCE_DEBUG=true \
           -e WOLFJSSE_DEBUG=true \
           wolfssl-openjdk-fips-root:latest

# Skip FIPS validation on startup (not recommended for production)
docker run -e FIPS_CHECK=false wolfssl-openjdk-fips-root:latest

# Run a Java application
docker run -v /path/to/your/app:/app \
           wolfssl-openjdk-fips-root:latest \
           -cp /app MyApplication
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `JAVA_OPTS` | JVM configuration options | `-Xmx512m` |
| `JAVA_TOOL_OPTIONS` | JVM module access flags for filtered providers | See Dockerfile |
| `CLASSPATH` | Application classpath including provider JARs (for ServiceLoader) | `/usr/share/java/*.jar` |
| `WOLFJCE_DEBUG` | Enable wolfJCE debug logging | `false` |
| `WOLFJSSE_DEBUG` | Enable wolfJSSE debug logging | `false` |
| `WOLFJSSE_ENGINE_DEBUG` | Enable wolfJSSE SSLEngine debug logging | `false` |
| `FIPS_CHECK` | Run FIPS validation on startup | `true` |

## Test and Example Application Images

A simple test application image is available under the
`./test-images/basic-test-image/` directory that runs basic JCA and SSL/TLS
tests on top of this base imags, and demonstrates simple example usage. This
test application image extends this base image.

### Building and Running

```bash
# Build the base image first
./build.sh -p YOUR_WOLFSSL_PASSWORD

# Build the test application
cd test-images/basic-test-image
./build.sh

# Run complete test suite
docker run --rm wolfssl-fips-basic-test-image:latest
```

For detailed information on the test application, see [`./test-images/basic-test-image/README.md`](./test-images/basic-test-image/README.md).

## FIPS Compliance

### Cryptographic Operations

All cryptographic operations are handled exclusively by wolfSSL's FIPS
validated wolfCrypt module via wolfJCE (cryptography) and wolfJSSE (SSL/TLS).
wolfJSSE does not call down through the JCE level, and instead operates
directly on native wolfSSL SSL/TLS APIs, which use native wolfCrypt
internally.

See wolfJCE's [README\_JCE.md](https://github.com/wolfSSL/wolfcrypt-jni/blob/master/README_JCE.md)
file for supported cryptographic services and algorithms. Reference wolfCrypt's
[FIPS 140-3 Security Policy](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4718)
for underlying module validation details.

## Operational Environment

For complete and proper FIPS validation compliance, the Operating Environment
that this container runs on must be added to the Security Policy for
wolfCrypt FIPS Certificate #4718. wolfSSL regularly adds OEs to existing
FIPS certificates. Contact fips@wolfssl.com for more information.

## Random Entropy

Native wolfSSL and wolfCrypt default to using /dev/urandom and /dev/random
for seeding the higher-level PRNG (Hash\_DRBG) implementation.

Native wolfCrypt uses the internal `wc_GenerateSeed()` function to call down
to the system entropy source. This native function behavior can be changed
at native wolfSSL build time, depending on Operating Environment validation.

For questions on native entropy sources, contact support@wolfssl.com or
fips@wolfssl.com.

## Security Configuration

The container modifies the base image and Java security configuration with
the following changes:

1. Set wolfJCE as the primary security provider
2. Set wolfJSSE as the secondary security provider
3. Install filtered Sun provider wrappers (FilteredSun, FilteredSunRsaSign, FilteredSunEC):
   - Expose only non-cryptographic services
   - Use delegating service pattern to maintain compatibility with wolfJCE/JSSE
   - Block/remove access to non-FIPS cryptographic operations
4. Disable original Sun crypto providers (SunJCE, SunJSSE, etc.) by removing
them from java.security.
5. Set JVM module access flags for filtered provider reflection
6. Convert system cacerts from JKS to WKS format for FIPS compliance
7. Set default KeyStore type to WKS for FIPS compliance
8. Configure Kerberos (krb5) to use only FIPS-compliant encryption types

### Kerberos Configuration

The container includes a FIPS-compliant Kerberos configuration file
(`/etc/krb5.conf`) that restricts Kerberos to use only AES-based encryption
types. This is necessary because the default Java Kerberos implementation
attempts to generate keys for all encryption types including DES, 3DES, and
RC4, which are not within the wolfCrypt FIPS boundary.

**Permitted Encryption Types:**
- `aes256-cts-hmac-sha1-96` (etype 18)
- `aes128-cts-hmac-sha1-96` (etype 17)

**Disabled Encryption Types:**
- DES-CBC-CRC (etype 1)
- DES-CBC-MD5 (etype 3)
- DES3-CBC-SHA1 (etype 16)
- RC4-HMAC (etype 23)
- All other non-AES encryption types

The configuration also sets `allow_weak_crypto = false` to prevent fallback
to weak encryption algorithms. Applications using Kerberos will automatically
inherit these restrictions.

**Note:** Applications that override the system krb5.conf with their own
configuration should ensure they only permit AES-based encryption types to
maintain FIPS compliance.

### Provider Discovery and ServiceLoader

The wolfSSL security providers (wolfJCE, wolfJSSE, and filtered Sun providers)
are configured to be discoverable through both Java's Security framework and
the ServiceLoader mechanism. This dual-path approach ensures maximum
compatibility with Java applications and frameworks.

**Dual Classpath Configuration:**

Provider JAR files are available on both the boot classpath and application
classpath:

- **Boot Classpath** (`-Xbootclasspath/a` via `JAVA_TOOL_OPTIONS`):
  - Required for early provider registration in the Security framework
  - Ensures providers are available before application code loads
  - Used by the `java.security` configuration file

- **Application Classpath** (`CLASSPATH` environment variable):
  - Required for ServiceLoader to discover providers
  - Enables `ServiceLoader.load(Provider.class)` to find providers
  - Allows frameworks (Spring Boot, etc.) to discover providers
  - Set by default to: `/usr/share/java/wolfcrypt-jni.jar:/usr/share/java/wolfssl-jsse.jar:/usr/share/java/filtered-providers.jar`

**ServiceLoader Support:**

All providers include `META-INF/services/java.security.Provider` files for
ServiceLoader discovery:
- `com.wolfssl.provider.jce.WolfCryptProvider`
- `com.wolfssl.provider.jsse.WolfSSLProvider`
- `com.wolfssl.security.providers.FilteredSun`
- `com.wolfssl.security.providers.FilteredSunRsaSign`
- `com.wolfssl.security.providers.FilteredSunEC`

**Important Notes for Application Developers:**

The container's entrypoint script automatically ensures provider JARs are
included in the `CLASSPATH`, even if you set a custom classpath. This means:

**You can set custom CLASSPATH values without breaking ServiceLoader:**

```bash
# Example 1: Using docker run with custom CLASSPATH
docker run -e CLASSPATH=/app/myapp.jar wolfssl-openjdk-fips-root:latest java MyApp

# Example 2: Using -cp flag (note: this overrides CLASSPATH environment variable)
docker run wolfssl-openjdk-fips-root:latest java -cp /app/myapp.jar MyApp
```

In both cases, the entrypoint script detects your custom classpath and
automatically appends the provider JARs to ensure ServiceLoader compatibility.

**Exception - Direct java -cp usage:**
If you use `java -cp` directly (not through the container entrypoint), you must
manually include the provider JARs:

```bash
# When bypassing the entrypoint
java -cp /app/myapp.jar:/usr/share/java/wolfcrypt-jni.jar:/usr/share/java/wolfssl-jsse.jar:/usr/share/java/filtered-providers.jar \
     com.example.MyApplication
```

**How it works:**
The entrypoint script (in `docker-entrypoint.sh`) checks the `CLASSPATH`
environment variable at container startup:
1. If `CLASSPATH` is not set, it sets it to provider JARs only
2. If `CLASSPATH` is set but missing provider JARs, it appends provider JARs
3. If `CLASSPATH` already contains provider JARs, no change

This ensures providers are always discoverable via ServiceLoader regardless of
how users configure their applications.

### WolfSSLKeyStore (WKS) Format

For FIPS 140-3 compliance, wolfJCE requires the use of WolfSSLKeyStore (WKS)
format for all KeyStore objects and files. The container automatically converts
the Java system cacerts file from JKS to WKS format during build.

**WKS Format Features:**
- Custom KeyStore implementation designed for FIPS 140-2/140-3 compatibility
- Uses AES-CBC-256 with HMAC-SHA512 in Encrypt-then-MAC mode for key protection
- PBKDF2-HMAC-SHA512 with 210,000 iterations (default) for key derivation
- 16-byte random salt per key storage operation
- Stores PrivateKey, Certificate, and SecretKey objects securely

**FIPS Requirement:**
WKS format is required when using wolfJCE in FIPS mode. Standard Java KeyStore
formats (JKS, PKCS12) are not compatible with FIPS-validated cryptographic
operations and must be converted to WKS format prior to use with this
container. For more details on WKS format, see the wolfJCE documentation:

[WolfSSLKeyStore Implementation Details and Usage](https://github.com/wolfSSL/wolfcrypt-jni/blob/master/README_JCE.md#wolfsslkeystore-wks-implementation-details-and-usage)

[wolfSSL KeyStore Design Notes](https://github.com/wolfSSL/wolfcrypt-jni/blob/master/docs/design/WolfSSLKeyStore.md)

**System-wide WKS Configuration:**
The container configures the Java security policy to use WKS as the default
KeyStore type (`keystore.type=WKS` in java.security). This ensures that
applications creating KeyStore instances without explicitly specifying a type
will automatically use FIPS-compliant WKS format instead of JKS.

**Protection Against Overwrites:**
The container automatically protects the WKS cacerts file using read-only
permissions (444) to prevent accidental overwrites by package managers or
other applications. This is in place to help prevent containers sitting
on top of this image from accidentally overwriting `cacerts` with a standard
JKS format file, which would cause runtime issues since JKS format is not
available for use in this image.

## FIPS Container Verification Tests / Docker Entrypoint

The container includes verification tests of the FIPS container that run
when the container is started via the Docker entrypoint script
(docker-entrypoint.sh). This script performs the following:

1. Configures debug logging based on environment variables:
    - `WOLFJCE_DEBUG`
    - `WOLFJSSE_DEBUG`
    - `WOLFJSSE_ENGINE_DEBUG`
2. Sets library paths for JNI libraries in standard Debian locations.
3. Verifies integrity of FIPS libraries before loading them:
    - Checksums of wolfSSL native libraries (.so files)
    - Checksums of provider JAR files (wolfJCE, wolfJSSE)
4. Conducts FIPS container sanity checks (FipsInitCheck.java)
    - List out all currently installed Java Security providers (Informational)
    - Verify wolfJCE is installed as provider at priority 1
    - Verify wolfJSSE is installed as provider at priority 2
    - Verify Java /lib/security/cacerts file is WKS format
    - Forces run of wolfCrypt FIPS POST by calling one service (MessageDigest)
    - Sanity check java.security providers, ensure no non-compliant providers are present
    - Verify all JCA algorithms/services use wolfSSL providers

### Running FIPS Container Verification Tests Manually

The FIPS container verification tests run automatically unless disabled.
They can be run manually with:

```bash
# Run FIPS Container Verification Tests
docker run wolfssl-openjdk-fips-root:latest java -cp "/opt/wolfssl-fips/bin:/usr/share/java/*" FipsInitCheck
```

The integrity check script can be run manually with:

```bash
docker run -it wolfssl-openjdk-fips-root:latest /usr/local/bin/integrity-check.sh
```

## Troubleshooting

### Container Fails to Start

If the container exits with FIPS POST failure:

1. Check the wolfSSL password is correct
2. Verify the wolfSSL commercial FIPS package is valid
3. Enable debug logging: `WOLFJCE\_DEBUG=true` and `WOLFJSSE\_DEBUG=true`

### WKS cacerts File Issues

If you encounter cacerts-related errors in derived images:

1. **"Permission denied" when modifying cacerts**: The file is protected with read-only permissions
   - `chmod 644 $JAVA_HOME/lib/security/cacerts` to make cacerts writable
   - Make your changes (ensure WKS format is maintained)
   - `chmod 444 $JAVA_HOME/lib/security/cacerts` to re-protect

2. **"Invalid magic number" or "KeyStore not of type WKS"**: The cacerts file was overwritten
   - Avoid installing `ca-certificates` package in derived images
   - Use the base image's WKS format cacerts file instead
   - If you must install ca-certificates, backup and restore the WKS file

3. **Derived images breaking FIPS compliance**:
   - Do not install packages that modify `/usr/local/openjdk-19/lib/security/cacerts`
   - Common culprits: `ca-certificates`, `ca-certificates-java`

### Algorithms Unavailable

wolfCrypt FIPS 140-3 certificates are validated with a specific set of
algorithms defined inside the cryptographic boundary. If Java applications
try to use non-FIPS validated algorithms, these will not be available from
the wolfJCE or wolfJSSE providers, and Java application code may need to
be changed to use compliant algorithms or KeyStore types.

### Debug Logging

Enable debug logging by setting the `WOLFJCE\_DEBUG`, `WOLFJSSE\_DEBUG`, or
`WOLFJSSE_ENGINE_DEBUG` environment variables to `true. `WOLFJCE\_DEBUG` will
enable wolfJCE debug logs. `WOLFJSSE\_DEBUG` will enable wolfJSSE debug logs.
`WOLFJSSE\_ENGINE\_DEBUG` will enable SSLEngine logs.

```bash
docker run -e WOLFJCE_DEBUG=true \
           -e WOLFJSSE_DEBUG=true \
           wolfssl-openjdk-fips-root:latest
```

### Known Issues

**ASN parsing error, invalid input (-140)** - This error has been observed
when testing connections to `www.github.com:443`. This is an ASN decoding
issue that exists in the wolfSSL 5.8.0 release, but is fixed in the 5.8.2
release. There is not yet a FIPS 140-3 v5.2.3 release for wolfSSL 5.8.2, but
will be soon.

## Version Information

- **wolfSSL**: 5.8.0 Commercial FIPS v5.2.3
- **Base Image**: Root.io OpenJDK 19 (Debian Bookworm Slim)
- **wolfcrypt-jni**: Master branch (GitHub)
- **wolfssljni**: Master branch (GitHub)
- **FIPS Certificate**: #4718

## Documentation

In addition to his README, the wolfJCE and wolfJSSE User Manuals can be
found online here:

[wolfCrypt JNI/JCE Manual](https://www.wolfssl.com/documentation/manuals/wolfcryptjni/)
[wolfSSL JNI/JSSE Manual](https://www.wolfssl.com/documentation/manuals/wolfssljni/)

## Support

For issues specific to this container implementation, please check:

1. Container logs for FIPS error messages
2. wolfSSL documentation for FIPS module requirements
3. Java security provider documentation

Email support@wolfssl.com for wolfSSL-specific issues or questions.


