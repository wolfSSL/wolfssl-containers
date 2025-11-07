# syntax=docker/dockerfile:1.7

# Multi-stage Dockerfile for FIPS-compliant Java container with wolfSSL
# Base image: Root.io OpenJDK 19 on Debian Bookworm Slim

# BuildKit secret used for wolfSSL commercial FIPS package password
# Note: This is passed via --secret and does not appear in build history
# The password is not persisted in the final image or build logs

# Optional local directories for wolfcrypt-jni and wolfssljni development
# If specified, these will be copied instead of cloning from GitHub
ARG WOLFCRYPT_JNI_LOCAL=""
ARG WOLFSSL_JNI_LOCAL=""

# Repository and branch configuration for wolfcrypt-jni and wolfssljni
# These allow building from custom repositories or branches
ARG WOLFCRYPT_JNI_REPO="https://github.com/wolfSSL/wolfcrypt-jni.git"
ARG WOLFCRYPT_JNI_BRANCH="master"
ARG WOLFSSL_JNI_REPO="https://github.com/wolfSSL/wolfssljni.git"
ARG WOLFSSL_JNI_BRANCH="master"

# ------------------------------------------------------------------------------
# Stage 1: Build Environment
# ------------------------------------------------------------------------------
FROM rootpublic/openjdk:19-jdk-bookworm-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    automake \
    autoconf \
    libtool \
    git \
    ant \
    curl \
    p7zip-full \
    && rm -rf /var/lib/apt/lists/*

# Set up environment
ENV JAVA_HOME=/usr/local/openjdk-19
ENV PATH=$JAVA_HOME/bin:$PATH

# Create build directory
WORKDIR /build

# Download JUnit and Hamcrest for JUnit4 tests (ant test)
# wolfssljni and wolfcrypt-jni currently require these specific versions
RUN mkdir -p /build/junit \
    && curl -L -o /build/junit/junit-4.13.2.jar https://repo1.maven.org/maven2/junit/junit/4.13.2/junit-4.13.2.jar \
    && curl -L -o /build/junit/hamcrest-core-1.3.jar https://repo1.maven.org/maven2/org/hamcrest/hamcrest-core/1.3/hamcrest-core-1.3.jar

# Set up JUnit environment, JUNIT_HOME is required for wolfssljni and
# wolfcrypt-jni ant test to find JUnit JARS
ENV JUNIT_HOME=/build/junit
ENV CLASSPATH=$JUNIT_HOME/junit-4.13.2.jar:$JUNIT_HOME/hamcrest-core-1.3.jar

# ------------------------------------------------------------------------------
# Stage 2: Build Native wolfSSL FIPS 140-3 library
# ------------------------------------------------------------------------------
FROM builder AS wolfssl-builder

# Download and extract wolfSSL commercial FIPS source using BuildKit secret.
# This bundle name can change depending on wolfCrypt FIPS OE
RUN --mount=type=secret,id=wolfssl_pw \
    PW="$(cat /run/secrets/wolfssl_pw)" \
    && curl -fLso /tmp/wolfssl-commercial.7z "https://www.wolfssl.com/comm/wolfssl/wolfssl-5.8.0-commercial-fips-v5.2.3.7z" \
    && 7z x /tmp/wolfssl-commercial.7z -p"$PW" -o/build \
    && rm -f /tmp/wolfssl-commercial.7z \
    && ls -la /build/ \
    && find /build -maxdepth 1 -type d -name "*wolfssl*" -exec mv {} /build/wolfssl \;

# Build wolfSSL v5.2.3 (cert 4718) with JNI support enabled.
# Running ./fips-hash.sh sets the in-core integrity check hash, after which
# make needs to be run again to incorporate the updated hash value.
# We run the wolfCrypt test app to verify native crypto is working after
# library build.
# Disabling MD5 since is not a FIPS validated algorithm in cert 4718.
# Manually adding HAVE_CTS to CFLAGS to enable AES-CTS. wolfSSL versions
# > 5.8.2 will automatically have this enabled with --enable-jni.
# Manually adding WOLFSSL_PUBLIC_MP for RSA KeyFactory support. <= 5.8.2
# did not add this into --enable-jni yet.
WORKDIR /build/wolfssl
RUN ./configure \
        --enable-fips=v5 \
        --enable-jni \
        --disable-md5 \
        --prefix=/usr/local CFLAGS="-DHAVE_CTS -DWOLFSSL_PUBLIC_MP" \
    && make -j$(nproc) \
    && echo "Updating FIPS in-core integrity check hash..." \
    && ./fips-hash.sh \
    && if [ $? -ne 0 ]; then echo "ERROR: fips-hash.sh failed!"; exit 1; fi \
    && echo "FIPS hash update completed successfully" \
    && echo "Rebuilding with updated FIPS hash..." \
    && make -j$(nproc) \
    && ./wolfcrypt/test/testwolfcrypt \
    && if [ $? -ne 0 ]; then echo "ERROR: wolfcrypt tests failed!"; exit 1; fi \
    && make install

# ------------------------------------------------------------------------------
# Stage 3: Build wolfCrypt JNI (JCE Provider)
# ------------------------------------------------------------------------------
FROM builder AS wolfjce-builder

# Copy wolfSSL libraries from previous stage
COPY --from=wolfssl-builder /usr/local /usr/local

# Update library cache
RUN ldconfig

# Get build args for repository configuration
ARG WOLFCRYPT_JNI_LOCAL
ARG WOLFCRYPT_JNI_REPO
ARG WOLFCRYPT_JNI_BRANCH

# Setup wolfcrypt-jni source
RUN if [ -n "$WOLFCRYPT_JNI_LOCAL" ]; then \
        echo "Local wolfcrypt-jni will be copied from build context"; \
        mkdir -p /build/wolfcrypt-jni; \
    else \
        echo "Cloning wolfcrypt-jni from $WOLFCRYPT_JNI_REPO (branch: $WOLFCRYPT_JNI_BRANCH)"; \
        git clone --branch $WOLFCRYPT_JNI_BRANCH $WOLFCRYPT_JNI_REPO /build/wolfcrypt-jni; \
    fi

# Copy local wolfcrypt-jni if provided
COPY wolfcrypt-jni-local/ /build/wolfcrypt-jni-temp/
RUN if [ -n "$WOLFCRYPT_JNI_LOCAL" ] && [ -d /build/wolfcrypt-jni-temp ]; then \
        echo "Copying local wolfcrypt-jni source"; \
        cp -r /build/wolfcrypt-jni-temp/* /build/wolfcrypt-jni/ 2>/dev/null || true; \
        cp -r /build/wolfcrypt-jni-temp/.* /build/wolfcrypt-jni/ 2>/dev/null || true; \
    fi && \
    rm -rf /build/wolfcrypt-jni-temp

WORKDIR /build/wolfcrypt-jni

# Build native JNI library and Java JAR
RUN cp makefile.linux makefile \
    && make \
    && ant build-jce-release

# Run Junit tests as build sanity check
RUN echo "Running wolfcrypt-jni tests..." \
    && export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH \
    && ant test

# Convert system CA certificates from JKS to WKS format for FIPS compliance
# Use the official wolfcrypt-jni script, running from the wolfcrypt-jni directory
# JKS (and PKCS12) KeyStore formats from Sun uses non-validated cryptography.
RUN echo "Converting system CA certificates from JKS to WKS format using wolfcrypt-jni script..." \
    && export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH \
    && chmod +x examples/certs/systemcerts/system-cacerts-to-wks.sh \
    && cd examples/certs/systemcerts \
    && ./system-cacerts-to-wks.sh ../../../lib/wolfcrypt-jni.jar \
    && if [ ! -f cacerts.wks ]; then echo "ERROR: Failed to convert cacerts to WKS format"; exit 1; fi \
    && cp cacerts.wks /build/cacerts.wks \
    && echo "Successfully converted system CA certificates to WKS format"

# Copy artifacts
RUN mkdir -p /build/artifacts/lib /build/artifacts/jar /build/artifacts/certs \
    && cp lib/libwolfcryptjni.so /build/artifacts/lib/ \
    && cp lib/wolfcrypt-jni.jar /build/artifacts/jar/wolfcrypt-jni.jar \
    && cp /build/cacerts.wks /build/artifacts/certs/cacerts.wks

# ------------------------------------------------------------------------------
# Stage 4: Build wolfSSL JNI (JSSE Provider)
# ------------------------------------------------------------------------------
FROM builder AS wolfjsse-builder

# Copy wolfSSL libraries from previous stage
COPY --from=wolfssl-builder /usr/local /usr/local

# Update library cache
RUN ldconfig

# Get build args for repository configuration
ARG WOLFSSL_JNI_LOCAL
ARG WOLFSSL_JNI_REPO
ARG WOLFSSL_JNI_BRANCH

# Setup wolfssljni source
RUN if [ -n "$WOLFSSL_JNI_LOCAL" ]; then \
        echo "Local wolfssljni will be copied from build context"; \
        mkdir -p /build/wolfssljni; \
    else \
        echo "Cloning wolfssljni from $WOLFSSL_JNI_REPO (branch: $WOLFSSL_JNI_BRANCH)"; \
        git clone --branch $WOLFSSL_JNI_BRANCH $WOLFSSL_JNI_REPO /build/wolfssljni; \
    fi

# Copy local wolfssljni if provided
COPY wolfssl-jni-local/ /build/wolfssljni-temp/
RUN if [ -n "$WOLFSSL_JNI_LOCAL" ] && [ -d /build/wolfssljni-temp ]; then \
        echo "Copying local wolfssljni source"; \
        cp -r /build/wolfssljni-temp/* /build/wolfssljni/ 2>/dev/null || true; \
        cp -r /build/wolfssljni-temp/.* /build/wolfssljni/ 2>/dev/null || true; \
    fi && \
    rm -rf /build/wolfssljni-temp

WORKDIR /build/wolfssljni

# Build native JNI library and Java JAR
RUN ./java.sh /usr/local \
    && ant

# Run JUnit tests as build sanity check
RUN echo "Running wolfssljni tests..." \
    && export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH \
    && ant test

# Copy artifacts
RUN mkdir -p /build/artifacts/lib /build/artifacts/jar \
    && cp lib/libwolfssljni.so /build/artifacts/lib/ \
    && cp lib/wolfssl-jsse.jar /build/artifacts/jar/wolfssl-jsse.jar

# ------------------------------------------------------------------------------
# Stage 5: Java Compilation
# ------------------------------------------------------------------------------
FROM builder AS java-compiler

# Copy JAR files for compilation
COPY --from=wolfjce-builder /build/artifacts/jar/wolfcrypt-jni.jar /usr/share/java/
COPY --from=wolfjsse-builder /build/artifacts/jar/wolfssl-jsse.jar /usr/share/java/

# Copy and compile Java source files
COPY src/main/FipsInitCheck.java /build/src/main/
COPY src/providers/*.java /build/src/providers/
COPY src/META-INF /build/META-INF

# Compile main application and filtered providers
RUN mkdir -p /build/classes \
    && javac -cp "/usr/share/java/*" -d /build/classes /build/src/main/FipsInitCheck.java \
    && javac -cp "/usr/share/java/*" -d /build/classes /build/src/providers/*.java \
    && jar cvf /build/filtered-providers.jar -C /build/classes com -C /build META-INF

# ------------------------------------------------------------------------------
# Stage 6: Runtime Image
# ------------------------------------------------------------------------------
FROM rootpublic/openjdk:19-jdk-bookworm-slim

# No additional runtime dependencies needed

# Copy native wolfSSL library from wolfssl-builder stage
COPY --from=wolfssl-builder /usr/local/lib/libwolfssl.so* /usr/local/lib/

# Copy native JNI libraries to temporary location from builder stages
COPY --from=wolfjce-builder /build/artifacts/lib/libwolfcryptjni.so /usr/lib/jni/
COPY --from=wolfjsse-builder /build/artifacts/lib/libwolfssljni.so /usr/lib/jni/

# Copy JAR files to /usr/share/java
RUN mkdir -p /usr/share/java
COPY --from=wolfjce-builder /build/artifacts/jar/wolfcrypt-jni.jar /usr/share/java/
COPY --from=wolfjsse-builder /build/artifacts/jar/wolfssl-jsse.jar /usr/share/java/
COPY --from=java-compiler /build/filtered-providers.jar /usr/share/java/

# Set up environment
ENV JAVA_HOME=/usr/local/openjdk-19
ENV PATH=$JAVA_HOME/bin:$PATH
ENV LD_LIBRARY_PATH=/usr/local/lib:/usr/lib/jni
ENV JAVA_LIBRARY_PATH=/usr/lib/jni:/usr/local/lib

# Copy converted WKS CA certificates file for FIPS compliance
# Replace the default JKS cacerts with WKS format required by wolfJSSE
COPY --from=wolfjce-builder /build/artifacts/certs/cacerts.wks $JAVA_HOME/lib/security/cacerts
RUN ldconfig \
    && chmod 644 /usr/local/lib/libwolfssl.so* \
    && find /usr/lib -name "libwolf*.so" -exec chmod 644 {} \; \
    && chmod 644 /usr/share/java/wolfcrypt-jni.jar \
    && chmod 644 /usr/share/java/wolfssl-jsse.jar \
    && chmod 644 /usr/share/java/filtered-providers.jar \
    && chmod 444 $JAVA_HOME/lib/security/cacerts \
    && echo "WKS cacerts file set to read-only"

# Create directory structure and generate integrity checksums for all
# library files.
RUN mkdir -p /opt/wolfssl-fips/bin \
    && mkdir -p /opt/wolfssl-fips/checksums \
    && { \
        sha256sum /usr/local/lib/libwolfssl.so*; \
        sha256sum /usr/lib/libwolfcryptjni.so; \
        sha256sum /usr/lib/libwolfssljni.so; \
        sha256sum /usr/share/java/wolfcrypt-jni.jar; \
        sha256sum /usr/share/java/wolfssl-jsse.jar; \
        sha256sum /usr/share/java/filtered-providers.jar; \
    } > /opt/wolfssl-fips/checksums/libraries.sha256 \
    && chmod 644 /opt/wolfssl-fips/checksums/*.sha256

# Copy pre-compiled Java classes to /opt/wolfssl-fips/bin.
COPY --from=java-compiler /build/classes /opt/wolfssl-fips/bin/

# Copy pre-defined FIPS 140-3 compliant java.security configuration.
# This replaces the base image java.security with our FIPS-compliant version.
# Save original file backup in image for inspection if needed.
RUN cp $JAVA_HOME/conf/security/java.security $JAVA_HOME/conf/security/java.security.backup
COPY java.security $JAVA_HOME/conf/security/java.security
RUN chmod 644 $JAVA_HOME/conf/security/java.security

# Copy FIPS 140-3 compliant Kerberos configuration.
# This restricts Kerberos to use only AES encryption types (aes256-cts,
# aes128-cts) which are supported by wolfCrypt FIPS Certificate #4718.
# DES, 3DES, and RC4 are excluded as they are not within the FIPS boundary.
COPY krb5.conf /etc/krb5.conf
RUN chmod 644 /etc/krb5.conf

# Copy scripts and set permissions
COPY docker-entrypoint.sh /docker-entrypoint.sh
COPY scripts/integrity-check.sh /usr/local/bin/integrity-check.sh
RUN chmod 755 /docker-entrypoint.sh \
    && chmod 700 /usr/local/bin/integrity-check.sh \
    && find /opt/wolfssl-fips/bin -name "*.class" -exec chmod 644 {} \;

# Environment variables with defaults
ENV JAVA_OPTS="-Xmx512m"
ENV WOLFJCE_DEBUG=false
ENV WOLFJSSE_DEBUG=false
ENV WOLFJSSE_ENGINE_DEBUG=false
ENV FIPS_CHECK=true

# Set CLASSPATH to include provider JARs for ServiceLoader compatibility
# ServiceLoader only scans the application classpath, not bootclasspath
# NOTE: The entrypoint script (docker-entrypoint.sh) will automatically
# append these JARs to any user-provided CLASSPATH to ensure ServiceLoader
# support even when users set custom classpaths
ENV CLASSPATH="/usr/share/java/wolfcrypt-jni.jar:/usr/share/java/wolfssl-jsse.jar:/usr/share/java/filtered-providers.jar"

# JVM flags for the filtered providerw which wrap Sun providers for non-crypto
# services. These flags are required because FilteredSun* providers use
# reflection to access internal Sun provider classes and copy some service
# definitions.
#
# --add-modules=jdk.crypto.ec
#       Required for: Loading the EC crypto module containing SunEC provider
#       Used by: FilteredSunEC.java - ClassLoader.getPlatformClassLoader()
#           to load sun.security.ec.SunEC class
#
# --add-exports=jdk.crypto.ec/sun.security.ec=ALL-UNNAMED
#       Required for: Exporting sun.security.ec package classes for access
#       Used by: FilteredSunEC.java - Class.forName("sun.security.ec.SunEC")
#           to instantiate the original SunEC provider
#
# --add-opens=jdk.crypto.ec/sun.security.ec=ALL-UNNAMED
#       Required for: Reflection access to SunEC provider internals
#       Used by: FilteredSunEC.java - originalService.newInstance()
#           delegation for EC KeyFactory and AlgorithmParameters
#
# --add-opens=java.base/java.security=ALL-UNNAMED
#       Required for: Reflection access to Provider.Service private fields
#       Used by: All FilteredSun*.java - accessing private fields:
#           className, aliases, attributes via getDeclaredField()
#
# --add-opens=java.base/sun.security.provider=ALL-UNNAMED
#       Required for: Access to internal Sun provider classes
#       Used by: FilteredSun.java - Class.forName("sun.security.provider.Sun")
#           to load and instantiate original SUN provider
#
# --add-opens=java.base/sun.security.util=ALL-UNNAMED
#       Required for: Access to UString class used in service attribute keys
#       Used by: All FilteredSun*.java - stringField.get(key)
#           to extract string values from UString attribute keys
#
# --add-opens=java.base/sun.security.rsa=ALL-UNNAMED
#       Required for: Access to internal SunRsaSign provider classes
#       Used by: FilteredSunRsaSign.java - Class.forName("sun.security.rsa.SunRsaSign")
#                to load and instantiate original SunRsaSign provider
ENV JAVA_TOOL_OPTIONS="\
--add-modules=jdk.crypto.ec \
--add-exports=jdk.crypto.ec/sun.security.ec=ALL-UNNAMED \
--add-opens=jdk.crypto.ec/sun.security.ec=ALL-UNNAMED \
--add-opens=java.base/java.security=ALL-UNNAMED \
--add-opens=java.base/sun.security.provider=ALL-UNNAMED \
--add-opens=java.base/sun.security.util=ALL-UNNAMED \
--add-opens=java.base/sun.security.rsa=ALL-UNNAMED \
-Djava.library.path=/usr/lib/jni:/usr/local/lib"

# Set entrypoint
ENTRYPOINT ["/docker-entrypoint.sh"]

# Default command for testing
CMD ["java", "-version"]

