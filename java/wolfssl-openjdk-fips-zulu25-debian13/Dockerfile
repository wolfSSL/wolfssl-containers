# syntax=docker/dockerfile:1.7

# wolfSSL FIPS 140-3 Java container. Base image: Azul Zulu OpenJDK 25
# (25.0.4.1) on Debian 13 (trixie), Docker Official Image
# azul-zulu:25.36-25.0.4.1-jdk-debian13

# The wolfSSL commercial FIPS bundle password is passed as a BuildKit secret
# (--secret id=wolfssl_pw). It does not appear in the build history, the build
# logs or the final image.

# Optional local wolfcrypt-jni and wolfssljni directories, copied instead of
# cloning from GitHub
ARG WOLFCRYPT_JNI_LOCAL=""
ARG WOLFSSL_JNI_LOCAL=""

# wolfcrypt-jni and wolfssljni repositories and branches to clone
ARG WOLFCRYPT_JNI_REPO="https://github.com/wolfSSL/wolfcrypt-jni.git"
ARG WOLFCRYPT_JNI_BRANCH="master"
ARG WOLFSSL_JNI_REPO="https://github.com/wolfSSL/wolfssljni.git"
ARG WOLFSSL_JNI_BRANCH="master"

# Base image for the builder and runtime stages, pinned by the digest of its
# multi-arch index (amd64, arm64). java.security is based on this Zulu
# version's stock file.
ARG BASE_IMAGE_NAME="azul-zulu:25.36-25.0.4.1-jdk-debian13"
ARG BASE_IMAGE_DIGEST="sha256:ad2e832df7277f5bce8f4a162d8317a300c61e0bb0b665f80534d1a9bca0e552"

# ------------------------------------------------------------------------------
# Stage 1: Build Environment
# ------------------------------------------------------------------------------
FROM ${BASE_IMAGE_NAME}@${BASE_IMAGE_DIGEST} AS builder

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
ENV JAVA_HOME=/usr/lib/jvm/zulu25
ENV PATH=$JAVA_HOME/bin:$PATH

# JDK 24+ (JEP 472) warns when the wolfJCE/wolfJSSE JNI libraries are loaded
# from the classpath without native access enabled. Enable it for the build
# stages so ant test and the keytool WKS conversion run without warnings.
ENV JAVA_TOOL_OPTIONS="--enable-native-access=ALL-UNNAMED"

# Create build directory
WORKDIR /build

# JUnit 4 and Hamcrest for the wolfcrypt-jni and wolfssljni tests (ant test),
# which require these versions
RUN mkdir -p /build/junit \
    && curl -fL -o /build/junit/junit-4.13.2.jar https://repo1.maven.org/maven2/junit/junit/4.13.2/junit-4.13.2.jar \
    && curl -fL -o /build/junit/hamcrest-core-1.3.jar https://repo1.maven.org/maven2/org/hamcrest/hamcrest-core/1.3/hamcrest-core-1.3.jar \
    && cd /build/junit \
    && printf '%s\n' \
        "8e495b634469d64fb8acfa3495a065cbacc8a0fff55ce1e31007be4c16dc57d3  junit-4.13.2.jar" \
        "66fdef91e9739348df7a096aa384a5685f4e875584cce89386a7a47251c4d8e9  hamcrest-core-1.3.jar" \
        | sha256sum -c -

# ant test finds the JUnit JARs through JUNIT_HOME
ENV JUNIT_HOME=/build/junit
ENV CLASSPATH=$JUNIT_HOME/junit-4.13.2.jar:$JUNIT_HOME/hamcrest-core-1.3.jar

# ------------------------------------------------------------------------------
# Stage 2: Build Native wolfSSL FIPS 140-3 library
# ------------------------------------------------------------------------------
# Download and extract the commercial wolfSSL FIPS v5.2.3 bundle, using the
# BuildKit secret for its password. The bundle name can differ by wolfCrypt
# FIPS operating environment. The bundle name and SHA-256 are recorded for
# /opt/wolfssl-fips/BUILD_INFO.
FROM builder AS wolfssl-builder
RUN --mount=type=secret,id=wolfssl_pw,required=true \
    PW="$(cat /run/secrets/wolfssl_pw)" \
    && BUNDLE="wolfssl-5.9.4-commercial-fips-v5.2.3.7z" \
    && SHA256="e47fe9926dbc4eec1518b4e9dac74d0bca1d447608a98ba35628da674fc28dac" \
    && curl -fLso /tmp/wolfssl-commercial.7z "https://www.wolfssl.com/comm/wolfssl/$BUNDLE" \
    && echo "$SHA256  /tmp/wolfssl-commercial.7z" | sha256sum -c - \
    && 7z x /tmp/wolfssl-commercial.7z -p"$PW" -o/build \
    && rm -f /tmp/wolfssl-commercial.7z \
    && ls -la /build/ \
    && find /build -maxdepth 1 -type d -name "*wolfssl*" -exec mv {} /build/wolfssl \; \
    && printf 'WOLFSSL_BUNDLE=%s\nWOLFSSL_BUNDLE_SHA256=%s\n' "$BUNDLE" "$SHA256" \
        > /build/wolfssl-bundle.info

# Build wolfSSL in FIPS v5.2.3 mode (cert #5548) with JNI support. MD5 is
# disabled because it is not approved. ./fips-hash.sh sets the in-core
# integrity check hash, so make runs again to build it in. testwolfcrypt then
# checks the native crypto.
WORKDIR /build/wolfssl
RUN ./configure \
        --enable-fips=v5.2.3 \
        --enable-jni \
        --disable-md5 \
        --prefix=/usr/local \
    && make -j$(nproc) \
    && echo "Updating FIPS in-core integrity check hash..." \
    && ./fips-hash.sh \
    && echo "FIPS hash update completed successfully" \
    && echo "Rebuilding with updated FIPS hash..." \
    && make -j$(nproc) \
    && ./wolfcrypt/test/testwolfcrypt \
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

# Set up the wolfcrypt-jni source
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

# Record the wolfcrypt-jni source for /opt/wolfssl-fips/BUILD_INFO. A local
# source that includes its .git directory also records its commit, with -dirty
# if tracked files have uncommitted changes.
RUN if [ -n "$WOLFCRYPT_JNI_LOCAL" ]; then \
        echo "WOLFCRYPT_JNI_SOURCE=local"; \
        if c=$(git -C /build/wolfcrypt-jni rev-parse HEAD 2>/dev/null); then \
            git -C /build/wolfcrypt-jni diff --quiet HEAD -- || c="$c-dirty"; \
            echo "WOLFCRYPT_JNI_COMMIT=$c"; \
        fi; \
    else \
        echo "WOLFCRYPT_JNI_SOURCE=$WOLFCRYPT_JNI_REPO $WOLFCRYPT_JNI_BRANCH"; \
        echo "WOLFCRYPT_JNI_COMMIT=$(git -C /build/wolfcrypt-jni rev-parse HEAD)"; \
    fi > /build/wolfcrypt-jni.info

WORKDIR /build/wolfcrypt-jni

# Build native JNI library and Java JAR
RUN cp makefile.linux makefile \
    && make \
    && ant build-jce-release

# Run the JUnit tests as a build check
RUN echo "Running wolfcrypt-jni tests..." \
    && export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH \
    && ant test

# Convert the system CA certificates from JKS to WKS with the wolfcrypt-jni
# script. Sun's JKS and PKCS12 KeyStores use cryptography that is not FIPS
# validated.
RUN echo "Converting system CA certificates from JKS to WKS format using wolfcrypt-jni script..." \
    && export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH \
    && chmod +x examples/certs/systemcerts/system-cacerts-to-wks.sh \
    && cd examples/certs/systemcerts \
    && ./system-cacerts-to-wks.sh ../../../lib/wolfcrypt-jni.jar \
    && if [ ! -f cacerts.wks ]; then echo "ERROR: Failed to convert cacerts to WKS format"; exit 1; fi \
    && cp cacerts.wks /build/cacerts.wks \
    && echo "Successfully converted system CA certificates to WKS format"

# Copy artifacts. The filtered Sun provider JAR (FilteredSun, FilteredSunEC,
# FilteredSunRsaSign) is built by the wolfcrypt-jni 'build-jce-release' target
# from examples/filtered-providers and placed in lib/filtered-providers/.
RUN mkdir -p /build/artifacts/lib /build/artifacts/jar /build/artifacts/certs \
    && cp lib/libwolfcryptjni.so /build/artifacts/lib/ \
    && cp lib/wolfcrypt-jni.jar /build/artifacts/jar/wolfcrypt-jni.jar \
    && cp lib/filtered-providers/filtered-providers.jar /build/artifacts/jar/filtered-providers.jar \
    && cp /build/cacerts.wks /build/artifacts/certs/cacerts.wks

# Pin and verify the JPMS module names of the provider JARs. The runtime image
# loads the providers from the module path and names these modules in
# JAVA_TOOL_OPTIONS (--add-modules, --add-opens), so a name change must fail
# the build here instead of producing a JVM that cannot start.
#
# wolfcrypt-jni versions that include
# examples/filtered-providers/java9/module-info.java build
# filtered-providers.jar as module com.wolfssl.security.providers. Older
# versions build a plain JAR, whose automatic module name would otherwise come
# from its file name ("filtered.providers"), so give it the same name via
# Automatic-Module-Name. This runs in the builder stage because the jar tool
# needs the stock JDK providers.
RUN cd /build/artifacts/jar \
    && if ! jar --describe-module --file=filtered-providers.jar \
            | grep -qE '^com\.wolfssl\.security\.providers[ @]'; then \
           echo "Setting Automatic-Module-Name: com.wolfssl.security.providers" \
           && printf 'Automatic-Module-Name: com.wolfssl.security.providers\n' > /tmp/amn.mf \
           && jar --update --file=filtered-providers.jar --manifest=/tmp/amn.mf \
           && rm -f /tmp/amn.mf; \
       fi \
    && jar --describe-module --file=filtered-providers.jar \
        | grep -E '^com\.wolfssl\.security\.providers[ @]' \
    && jar --describe-module --file=wolfcrypt-jni.jar \
        | grep -E '^com\.wolfssl\.wolfcrypt[ @]' \
    || { echo "ERROR: unexpected wolfJCE / filtered-providers JAR module name"; exit 1; }

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

# Set up the wolfssljni source
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

# Record the wolfssljni source for /opt/wolfssl-fips/BUILD_INFO. A local source
# that includes its .git directory also records its commit, with -dirty if
# tracked files have uncommitted changes.
RUN if [ -n "$WOLFSSL_JNI_LOCAL" ]; then \
        echo "WOLFSSL_JNI_SOURCE=local"; \
        if c=$(git -C /build/wolfssljni rev-parse HEAD 2>/dev/null); then \
            git -C /build/wolfssljni diff --quiet HEAD -- || c="$c-dirty"; \
            echo "WOLFSSL_JNI_COMMIT=$c"; \
        fi; \
    else \
        echo "WOLFSSL_JNI_SOURCE=$WOLFSSL_JNI_REPO $WOLFSSL_JNI_BRANCH"; \
        echo "WOLFSSL_JNI_COMMIT=$(git -C /build/wolfssljni rev-parse HEAD)"; \
    fi > /build/wolfssljni.info

WORKDIR /build/wolfssljni

# Build native JNI library and Java JAR
RUN ./java.sh /usr/local \
    && ant

# Run the JUnit tests as a build check
RUN echo "Running wolfssljni tests..." \
    && export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH \
    && ant test

# Copy artifacts
RUN mkdir -p /build/artifacts/lib /build/artifacts/jar \
    && cp lib/libwolfssljni.so /build/artifacts/lib/ \
    && cp lib/wolfssl-jsse.jar /build/artifacts/jar/wolfssl-jsse.jar

# Verify the wolfJSSE JAR module name used in the runtime JAVA_TOOL_OPTIONS
# (see the wolfjce-builder stage)
RUN jar --describe-module --file=/build/artifacts/jar/wolfssl-jsse.jar \
        | grep -E '^com\.wolfssl[ @]' \
    || { echo "ERROR: unexpected wolfJSSE JAR module name"; exit 1; }

# ------------------------------------------------------------------------------
# Stage 5: Java Compilation
# ------------------------------------------------------------------------------
FROM builder AS java-compiler

# Copy JAR files for compilation
COPY --from=wolfjce-builder /build/artifacts/jar/wolfcrypt-jni.jar /usr/share/java/
COPY --from=wolfjsse-builder /build/artifacts/jar/wolfssl-jsse.jar /usr/share/java/

# Compile FipsInitCheck
COPY src/main/FipsInitCheck.java /build/src/main/
RUN mkdir -p /build/classes \
    && javac -cp "/usr/share/java/*" -d /build/classes /build/src/main/FipsInitCheck.java

# ------------------------------------------------------------------------------
# Stage 6: Runtime Image
# ------------------------------------------------------------------------------
FROM ${BASE_IMAGE_NAME}@${BASE_IMAGE_DIGEST}

# OCI image labels, including the pinned base image
ARG BASE_IMAGE_NAME
ARG BASE_IMAGE_DIGEST
LABEL org.opencontainers.image.title="wolfssl-openjdk-fips-zulu25-debian13" \
      org.opencontainers.image.description="Azul Zulu OpenJDK 25 with the wolfCrypt FIPS 140-3" \
      org.opencontainers.image.vendor="wolfSSL Inc." \
      org.opencontainers.image.base.name="docker.io/library/${BASE_IMAGE_NAME}" \
      org.opencontainers.image.base.digest="${BASE_IMAGE_DIGEST}"

# Copy the native wolfSSL library
COPY --from=wolfssl-builder /usr/local/lib/libwolfssl.so* /usr/local/lib/

# Copy the JNI libraries
COPY --from=wolfjce-builder /build/artifacts/lib/libwolfcryptjni.so /usr/lib/jni/
COPY --from=wolfjsse-builder /build/artifacts/lib/libwolfssljni.so /usr/lib/jni/

# Copy JAR files to /usr/share/java
RUN mkdir -p /usr/share/java
COPY --from=wolfjce-builder /build/artifacts/jar/wolfcrypt-jni.jar /usr/share/java/
COPY --from=wolfjsse-builder /build/artifacts/jar/wolfssl-jsse.jar /usr/share/java/
COPY --from=wolfjce-builder /build/artifacts/jar/filtered-providers.jar /usr/share/java/

# Set up environment
ENV JAVA_HOME=/usr/lib/jvm/zulu25
ENV PATH=$JAVA_HOME/bin:$PATH
ENV LD_LIBRARY_PATH=/usr/local/lib:/usr/lib/jni
ENV JAVA_LIBRARY_PATH=/usr/lib/jni:/usr/local/lib

# Replace the default JKS cacerts with the converted WKS file
COPY --from=wolfjce-builder /build/artifacts/certs/cacerts.wks $JAVA_HOME/lib/security/cacerts
RUN ldconfig \
    && chmod 644 /usr/local/lib/libwolfssl.so* \
    && find /usr/lib -name "libwolf*.so" -exec chmod 644 {} \; \
    && chmod 644 /usr/share/java/wolfcrypt-jni.jar \
    && chmod 644 /usr/share/java/wolfssl-jsse.jar \
    && chmod 644 /usr/share/java/filtered-providers.jar \
    && chmod 444 $JAVA_HOME/lib/security/cacerts \
    && echo "WKS cacerts file set to read-only"

# Create directory structure. Integrity checksums are generated further below,
# once all protected files are in place.
RUN mkdir -p /opt/wolfssl-fips/bin /opt/wolfssl-fips/checksums

# Record the sources this image was built from in /opt/wolfssl-fips/BUILD_INFO
# (informational): the base image, the wolfSSL bundle and SHA-256, and the
# wolfcrypt-jni and wolfssljni repository, branch and commit ("local" for a
# local source directory).
COPY --from=wolfssl-builder /build/wolfssl-bundle.info /tmp/build-info/
COPY --from=wolfjce-builder /build/wolfcrypt-jni.info /tmp/build-info/
COPY --from=wolfjsse-builder /build/wolfssljni.info /tmp/build-info/
RUN { echo "BASE_IMAGE=${BASE_IMAGE_NAME}@${BASE_IMAGE_DIGEST}"; \
      cat /tmp/build-info/wolfssl-bundle.info \
          /tmp/build-info/wolfcrypt-jni.info \
          /tmp/build-info/wolfssljni.info; \
    } > /opt/wolfssl-fips/BUILD_INFO \
    && chmod 444 /opt/wolfssl-fips/BUILD_INFO \
    && rm -rf /tmp/build-info \
    && cat /opt/wolfssl-fips/BUILD_INFO

# Copy FipsInitCheck.class to /opt/wolfssl-fips/bin
COPY --from=java-compiler /build/classes /opt/wolfssl-fips/bin/

# Replace the base image java.security, keeping the original as
# java.security.backup
RUN cp $JAVA_HOME/conf/security/java.security $JAVA_HOME/conf/security/java.security.backup
COPY java.security $JAVA_HOME/conf/security/java.security
RUN chmod 444 $JAVA_HOME/conf/security/java.security

# Kerberos configuration: AES encryption types only (see krb5.conf)
COPY krb5.conf /etc/krb5.conf
RUN chmod 444 /etc/krb5.conf

# Copy scripts and set permissions. The integrity check script is executable
# by the non-root image user (see USER below).
COPY docker-entrypoint.sh /docker-entrypoint.sh
COPY scripts/integrity-check.sh /usr/local/bin/integrity-check.sh
COPY scripts/update-integrity-checksums.sh /usr/local/bin/update-integrity-checksums.sh
RUN chmod 755 /docker-entrypoint.sh \
    && chmod 755 /usr/local/bin/integrity-check.sh \
    && chmod 755 /usr/local/bin/update-integrity-checksums.sh \
    && find /opt/wolfssl-fips/bin -name "*.class" -exec chmod 644 {} \;

# Generate the checksums of the wolfSSL native libraries, JNI libraries,
# provider JARs, security configuration files (java.security, cacerts,
# krb5.conf) and FipsInitCheck.class, which integrity-check.sh verifies at
# container startup. The build fails if a file is missing. The checksum file
# is root-owned and read-only, and the image runs as a non-root user, so
# applications cannot change the protected files or their checksums. Derived
# images that change a protected file run update-integrity-checksums.sh again
# as root.
RUN /usr/local/bin/update-integrity-checksums.sh

# Environment variables with defaults
ENV JAVA_OPTS="-Xmx512m"
ENV WOLFJCE_DEBUG=false
ENV WOLFJSSE_DEBUG=false
ENV WOLFJSSE_ENGINE_DEBUG=false
ENV FIPS_CHECK=true

# Provider registration: the wolfJCE, wolfJSSE and filtered provider JARs load
# from the JVM module path set in JAVA_TOOL_OPTIONS below. The JVM reads
# JAVA_TOOL_OPTIONS for every launcher, so without application changes the
# providers are available to:
#   - java -cp / java -jar / CLASSPATH applications (the class path no longer
#     has to list the provider JARs)
#   - JDK tools that ignore CLASSPATH, such as keytool, jar, jarsigner and
#     jshell
# Applications that pass their own --module-path must include these three
# JARs, since the last --module-path wins. Append to JAVA_TOOL_OPTIONS instead
# of replacing it.
#
# --module-path / --add-modules: the provider modules are com.wolfssl.wolfcrypt
# (wolfcrypt-jni.jar, wolfJCE), com.wolfssl (wolfssl-jsse.jar, wolfJSSE) and
# com.wolfssl.security.providers (filtered-providers.jar). The builder stages
# verify these names.
#
# --add-exports / --add-opens: the filtered providers wrap the Sun providers for
# non-crypto services and use reflection into JDK internals to copy some
# service definitions. These flags grant that access to the filtered providers
# module only, not to application code (ALL-UNNAMED). The filtered providers
# are in the wolfcrypt-jni repository under examples/filtered-providers, and
# examples/filtered-providers/docs/add-opens.md explains each flag. SunEC moved
# from the jdk.crypto.ec module into java.base in JDK 22, so the EC flags
# target java.base/sun.security.ec.
#
# --enable-native-access: JDK 24+ (JEP 472) warns when code calls
# System.loadLibrary() without native access, and future JDK releases will
# block it. Granted to the wolfJCE and wolfJSSE modules, which load the JNI
# libraries, and to ALL-UNNAMED for applications with their own JNI code.
#
# -Djdk.tls.allowLegacyMasterSecret=false: require the TLS Extended Master
# Secret (RFC 7627), which the Security Policy requires for the TLS 1.2 KDF in
# approved mode. TLS 1.2 handshakes with peers that do not support it fail.
# A -D on the java command line overrides it. Needs wolfJSSE support
# (WolfSSLSession.requireExtendedMasterSecret), checked by FipsInitCheck.
ENV JAVA_TOOL_OPTIONS="\
--module-path=/usr/share/java/wolfcrypt-jni.jar:/usr/share/java/wolfssl-jsse.jar:/usr/share/java/filtered-providers.jar \
--add-modules=com.wolfssl.wolfcrypt,com.wolfssl,com.wolfssl.security.providers \
--enable-native-access=com.wolfssl.wolfcrypt,com.wolfssl,ALL-UNNAMED \
--add-exports=java.base/sun.security.ec=com.wolfssl.security.providers \
--add-opens=java.base/sun.security.ec=com.wolfssl.security.providers \
--add-opens=java.base/java.security=com.wolfssl.security.providers \
--add-opens=java.base/sun.security.provider=com.wolfssl.security.providers \
--add-opens=java.base/sun.security.util=com.wolfssl.security.providers \
--add-opens=java.base/sun.security.rsa=com.wolfssl.security.providers \
-Djdk.tls.allowLegacyMasterSecret=false \
-Djava.library.path=/usr/lib/jni:/usr/local/lib"

# Run as a non-root user by default. The provider JARs, native libraries,
# FIPS configuration files (java.security, cacerts, krb5.conf), checksum file
# and startup check scripts are root-owned, so applications in the container
# cannot modify them. USER is numeric so Kubernetes runAsNonRoot can verify
# it. Derived images that install packages switch to USER root for those
# steps and back to USER 10001:10001 afterwards.
RUN groupadd --gid 10001 wolfssl \
    && useradd --uid 10001 --gid 10001 --create-home --home-dir /home/wolfssl \
        --shell /usr/sbin/nologin wolfssl
USER 10001:10001
WORKDIR /home/wolfssl

# Set entrypoint
ENTRYPOINT ["/docker-entrypoint.sh"]

# Default command: jshell, the same as the base image. Declaring ENTRYPOINT
# resets the inherited CMD, so it is set again here. The entrypoint runs the
# startup checks first, then starts jshell.
CMD ["jshell"]

