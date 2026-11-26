# wolfSSL FIPS Java Test Application

A test application for the `wolfssl-openjdk-fips-zulu25-debian13` image. It
extends the base image and runs JCA cryptographic operations and SSL/TLS
connections with FIPS 140-3 validated algorithms. It is both a basic check of
the FIPS crypto services and an example of how to use them.

## Features

### JCA Cryptographic Operations
- **Message Digest**: SHA-256, SHA-384, SHA-512, SHA3 variants
- **Symmetric Encryption**: AES-GCM, AES-CBC with multiple key sizes
- **Asymmetric Encryption**: raw RSA (`RSA/ECB/NoPadding`). Padded RSA
  encryption names should be unavailable and are verified to be so.
- **MAC Operations**: HMAC-SHA variants, AES-CMAC
- **Digital Signatures**: RSA-PSS, ECDSA with various hash algorithms
- **Key Generation**: AES keys, RSA/EC key pairs
- **Secure Random**: FIPS-validated entropy generation

### TLS/SSL Operations
- **SSLContext**: Creation and configuration with multiple protocols
- **TLS Connections**: Real HTTPS connections to public endpoints
- **Certificate Validation**: TrustManager and certificate chain verification
- **Protocol Support**: TLS 1.2, TLS 1.3 testing
- **Cipher Suites**: FIPS-approved cipher suite verification

### Real-World Scenarios
- **File Encryption**: Simple file encryption/decryption workflow
- **Data Signing**: Digital signature creation and verification
- **Password Hashing**: Salted SHA-256 hash and check
- **HTTPS Client**: GET request with `HttpsURLConnection`

## Directory Structure

```
basic-test-image/
├── README.md                    # This doc
├── Dockerfile                   # Container def, extending wolfssl-openjdk-fips-zulu25-debian13
├── build.sh                     # Build script for test image
└── src/main/
    ├── FipsUserApplication.java # Main application
    ├── CryptoTestSuite.java     # JCA cryptographic tests
    └── TlsTestSuite.java        # SSL/TLS connectivity tests
```

## Building the Test Application

### Prerequisites

Build the `wolfssl-openjdk-fips-zulu25-debian13:latest` base image first:
   ```bash
   cd ../..
   ./build.sh -p YOUR_WOLFSSL_PASSWORD
   ```

### Build Commands

```bash
# Basic build
./build.sh

# Custom image name and tag
./build.sh -n mytest -t v1.0

# Use custom base image with verbose output
./build.sh -b wolfssl-openjdk-fips-zulu25-debian13:custom -v

# Build without cache
./build.sh -c

# Show help
./build.sh -h
```

## Running the Test Application

### Complete Test Suite

Run the JCA and TLS test suites and the example scenarios:

```bash
docker run --rm wolfssl-fips-zulu25-basic-test-image:latest
```

### Individual Test Suites

**JCA Cryptographic Operations Only:**
```bash
docker run --rm wolfssl-fips-zulu25-basic-test-image:latest \
  java CryptoTestSuite
```

**SSL/TLS Operations Only:**
```bash
docker run --rm wolfssl-fips-zulu25-basic-test-image:latest \
  java TlsTestSuite
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `JAVA_OPTS` | JVM configuration options | `-Xmx512m` |
| `JAVA_TOOL_OPTIONS` | JVM module access flags | See base image |
| `WOLFJCE_DEBUG` | Enable wolfJCE debug logging | `false` |
| `WOLFJSSE_DEBUG` | Enable wolfJSSE debug logging | `false` |
| `FIPS_CHECK` | Run FIPS validation on startup | `true` |

## Troubleshooting

### Common Issues

1. **Base Image Not Found**
   ```
   Error: Base image 'wolfssl-openjdk-fips-zulu25-debian13:latest' not found!
   ```
   Solution: Build the base image first with `cd ../.. && ./build.sh -p YOUR_PASSWORD`

2. **Provider Not Found**
   ```
   SecurityException: wolfJCE provider not found
   ```
   Solution: Check that the base image was built correctly and FIPS libraries
   are intact.

### Debug Mode

Enable debug logging:

```bash
docker run --rm \
  -e WOLFJCE_DEBUG=true \
  -e WOLFJSSE_DEBUG=true \
  -e WOLFJSSE_ENGINE_DEBUG=true \
  wolfssl-fips-zulu25-basic-test-image:latest
```

