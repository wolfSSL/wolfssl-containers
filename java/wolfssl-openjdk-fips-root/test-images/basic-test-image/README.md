# wolfSSL FIPS Java Test Application

A test application that demonstrates usage of the wolfSSL FIPS-compliant Java
container accross cryptographic services and SSL/TLS protocol versions. This
Docker image extends the base `wolfssl-openjdk-fips-root` image and provides examples
of JCA cryptographic operations and SSL/TLS connectivity using FIPS 140-3
validated algorithms.

## Overview

This test application serves dual purposes:
1. **Verification Tool**: Basic testing of FIPS-compliant crypto services
2. **Integration Example**: Practical demonstration of basic usage

## Features

### JCA Cryptographic Operations
- **Message Digest**: SHA-256, SHA-384, SHA-512, SHA3 variants
- **Symmetric Encryption**: AES-GCM, AES-CBC with multiple key sizes
- **Asymmetric Encryption**: RSA encryption/decryption
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
- **Password Hashing**: Secure password storage patterns
- **HTTPS Client**: HTTPS client implementation

## Directory Structure

```
basic-test-image/
├── README.md                    # This doc
├── Dockerfile                   # Container def, extending wolfssl-openjdk-fips-root
├── build.sh                     # Build script for test image
└── src/main/
    ├── FipsUserApplication.java # Main application
    ├── CryptoTestSuite.java     # JCA cryptographic tests
    └── TlsTestSuite.java        # SSL/TLS connectivity tests
```

## Building the Test Application

### Prerequisites

1. **Base Image**: The `wolfssl-openjdk-fips-root:latest` image must be built first
   ```bash
   cd ../..
   ./build.sh -p YOUR_WOLFSSL_PASSWORD
   ```

2. **Docker**: Docker must be installed and running

### Build Commands

```bash
# Basic build
./build.sh

# Custom image name and tag
./build.sh -n mytest -t v1.0

# Use custom base image with verbose output
./build.sh -b wolfssl-openjdk-fips-root:custom -v

# Build without cache
./build.sh -c

# Show help
./build.sh -h
```

## Running the Test Application

### Complete Test Suite

Run all tests including cryptographic operations, TLS connectivity,
and usage scenarios:

```bash
docker run --rm wolfssl-fips-basic-test-image:latest
```

### Individual Test Suites

**JCA Cryptographic Operations Only:**
```bash
docker run --rm wolfssl-fips-basic-test-image:latest \
  java CryptoTestSuite
```

**SSL/TLS Operations Only:**
```bash
docker run --rm wolfssl-fips-basic-test-image:latest \
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
   Error: Base image 'wolfssl-fips-java:latest' not found!
   ```
   Solution: Build the base image first with `cd ../.. && ./build.sh -p YOUR_PASSWORD`

3. **Provider Not Found**
   ```
   SecurityException: wolfJCE provider not found
   ```
   Solution: Check that the base image was built correctly and FIPS libraries
   are intact.

### Debug Mode

Enable verbose logging to diagnose issues:

```bash
docker run --rm \
  -e WOLFJCE_DEBUG=true \
  -e WOLFJSSE_DEBUG=true \
  -e WOLFJSSE_ENGINE_DEBUG=true \
  wolfssl-fips-basic-test-image:latest
```

