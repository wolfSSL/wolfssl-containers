# Netty wolfJSSE FIPS Test Image

Runs upstream Netty SSL tests under wolfJSSE in FIPS mode.

## Build & Run

```bash
# Build base image first (from wolfssl-openjdk-fips-root/)
./build.sh -p <password> --wolfcrypt-jni ./wolfcrypt-jni --wolfssl-jni ./wolfssljni

# Build and run netty tests
cd test-images/netty-tests
./build.sh
docker run --rm netty-wolfjsse:latest
```

## Run Single Test

```bash
docker run --rm -it netty-wolfjsse:latest bash
./mvnw -o test -pl handler -Dtest=JdkSslClientContextTest \
  -Dcheckstyle.skip=true -Danimal.sniffer.skip=true
```

## Patch Summary

`apply_netty_fips_fixes.sh` patches Netty to skip OpenSSL-specific tests, use wolfSSL certs, and disable FIPS-incompatible algorithms (MD5, 3DES).
