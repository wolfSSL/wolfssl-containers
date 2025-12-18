# ==============================================================================
# Netty SSL Test Image with wolfJSSE - FIPS Mode
# ==============================================================================
# Runs Netty SSL tests with wolfJSSE in FIPS mode, OpenSSL disabled.
#
# Test Modules:
# - handler: All SSL handler tests (OpenSSL tests patched to skip)
# - handler-proxy: Proxy handler tests (including HTTPS proxy)
# - testsuite: Integration tests (SSL transport tests)
#
# Build: docker build -t netty-wolfjsse:latest .
# ==============================================================================

ARG FIPS_BASE_IMAGE=wolfssl-openjdk-fips-root:latest
ARG NETTY_REPO=https://github.com/netty/netty.git
# Pin to a specific Netty release tag for reproducible builds
ARG NETTY_TAG=netty-4.1.115.Final

# ------------------------------------------------------------------------------
# Stage 1: Build Netty with patches
# ------------------------------------------------------------------------------
FROM rootpublic/openjdk:19-jdk-bookworm-slim AS netty-builder

RUN apt-get update && apt-get install -y build-essential maven git perl && rm -rf /var/lib/apt/lists/*

ENV MAVEN_OPTS="-Xmx2048m"
ENV JAVA_HOME=/usr/local/openjdk-19
ENV PATH=$JAVA_HOME/bin:$PATH

WORKDIR /app/netty
ARG NETTY_REPO
ARG NETTY_TAG
# Clone specific release tag (shallow clone for speed)
RUN git clone --depth 1 --branch ${NETTY_TAG} ${NETTY_REPO} .

# Copy patching script
COPY apply_netty_fips_fixes.sh /tmp/apply_netty_fips_fixes.sh

# Apply FIPS compatibility fixes
RUN chmod +x /tmp/apply_netty_fips_fixes.sh && /tmp/apply_netty_fips_fixes.sh /app/netty

# Build handler, handler-proxy, and testsuite with all dependencies
RUN ./mvnw clean install -DskipTests -Dcheckstyle.skip=true -Djapicmp.skip=true -Danimal.sniffer.skip=true \
  -pl handler,handler-proxy,transport-sctp,transport-udt,testsuite -am -T 1C

# Resolve all test dependencies
RUN ./mvnw dependency:resolve -DincludeScope=test -pl handler,handler-proxy,transport-sctp,transport-udt,testsuite -am
RUN ./mvnw dependency:resolve-plugins -pl handler,handler-proxy,transport-sctp,transport-udt,testsuite
RUN ./mvnw dependency:get -Dartifact=org.apache.maven.surefire:surefire-junit-platform:3.5.3
RUN ./mvnw dependency:get -Dartifact=org.apache.maven.surefire:surefire-junit-platform:2.22.2
RUN ./mvnw dependency:get -Dartifact=org.apache.maven.surefire:surefire-api:2.22.2
RUN ./mvnw dependency:get -Dartifact=org.junit.platform:junit-platform-launcher:1.10.2
RUN ./mvnw test-compile -Dcheckstyle.skip=true -Danimal.sniffer.skip=true -pl handler,handler-proxy,transport-sctp,transport-udt,testsuite -am

# ------------------------------------------------------------------------------
# Stage 2: Runtime Image (FIPS base)
# ------------------------------------------------------------------------------
FROM ${FIPS_BASE_IMAGE}

RUN apt-get update && apt-get install -y maven git && rm -rf /var/lib/apt/lists/*

COPY --from=netty-builder /app/netty /app/netty
COPY --from=netty-builder /root/.m2 /root/.m2

# Clone wolfSSL example certs directly from repo (sparse checkout)
RUN git clone --depth 1 --filter=blob:none --sparse https://github.com/wolfSSL/wolfssl.git /tmp/wolfssl && \
  cd /tmp/wolfssl && \
  git sparse-checkout set certs && \
  cp -r certs /app/certs && \
  rm -rf /tmp/wolfssl

# Fix wolfSSL cert files: they contain text dump THEN PEM data, but Java needs pure PEM
# Extract only the PEM portion (from -----BEGIN to -----END) for each cert/key file
RUN for f in /app/certs/*.pem; do \
  if grep -q "BEGIN" "$f" 2>/dev/null; then \
    sed -n '/-----BEGIN/,/-----END/p' "$f" > "$f.tmp"; \
    if [ -s "$f.tmp" ]; then mv "$f.tmp" "$f"; else rm -f "$f.tmp"; fi; \
  fi; \
  done

WORKDIR /app/netty

# FIPS environment
# Ensure the base image performs its FIPS verification check on container start.
ENV FIPS_CHECK=true
ENV MAVEN_OPTS="-Xmx4g -XX:MaxMetaspaceSize=512m -Djava.security.egd=file:/dev/urandom -Dio.netty.handler.ssl.noOpenSsl=true"

ENV JAVA_TOOL_OPTIONS="-Xbootclasspath/a:/usr/share/java/wolfcrypt-jni.jar:/usr/share/java/wolfssl-jsse.jar:/usr/share/java/filtered-providers.jar \
  -Djava.library.path=/usr/lib/jni:/usr/local/lib \
  -Dio.netty.handler.ssl.noOpenSsl=true \
  --add-modules=jdk.crypto.ec \
  --add-exports=jdk.crypto.ec/sun.security.ec=ALL-UNNAMED \
  --add-opens=jdk.crypto.ec/sun.security.ec=ALL-UNNAMED \
  --add-opens=java.base/java.security=ALL-UNNAMED \
  --add-opens=java.base/sun.security.provider=ALL-UNNAMED \
  --add-opens=java.base/sun.security.util=ALL-UNNAMED \
  --add-opens=java.base/sun.security.rsa=ALL-UNNAMED \
  --add-exports=java.base/sun.security.provider=ALL-UNNAMED \
  --add-exports=java.base/sun.security.rsa=ALL-UNNAMED \
  --add-exports=jdk.crypto.ec/sun.security.ec=ALL-UNNAMED"

# Symlink native libs
RUN ln -sf /usr/lib/jni/libwolfssljni.so /usr/local/openjdk-19/lib/libwolfssljni.so && \
  ln -sf /usr/lib/jni/libwolfcryptjni.so /usr/local/openjdk-19/lib/libwolfcryptjni.so && \
  ln -sf /usr/local/lib/libwolfssl.so /usr/local/openjdk-19/lib/libwolfssl.so

# Create test runner script
# Runs handler, handler-proxy, and testsuite modules with aggregate summary
RUN cat > /app/run-tests.sh <<'EOF' && chmod +x /app/run-tests.sh
#!/bin/bash
cd /app/netty

HANDLER_RESULT=0
PROXY_RESULT=0
TESTSUITE_RESULT=0

RUNS=()

run_mvn() {
  local name="$1"
  shift
  RUNS+=("$name")

  echo ""
  echo "============================================================"
  echo "=== Running: ${name}"
  echo "============================================================"

  set -o pipefail
  "$@" 2>&1 | tee "/tmp/${name}.log"
  local rc=${PIPESTATUS[0]}
  set +o pipefail
  return $rc
}

extract_summary_line() {
  local name="$1"
  # surefire sometimes logs with [INFO] or [WARNING]
  grep -E 'Tests run: [0-9]+, Failures: [0-9]+, Errors: [0-9]+, Skipped: [0-9]+' "/tmp/${name}.log" | tail -n 1 || true
}

add_totals_from_line() {
  local line="$1"
  if [[ "$line" =~ Tests\ run:\ ([0-9]+),\ Failures:\ ([0-9]+),\ Errors:\ ([0-9]+),\ Skipped:\ ([0-9]+) ]]; then
    TOTAL_RUN=$((TOTAL_RUN + BASH_REMATCH[1]))
    TOTAL_FAIL=$((TOTAL_FAIL + BASH_REMATCH[2]))
    TOTAL_ERR=$((TOTAL_ERR + BASH_REMATCH[3]))
    TOTAL_SKIP=$((TOTAL_SKIP + BASH_REMATCH[4]))
  fi
}

# Memory for forked Surefire JVM (MAVEN_OPTS only affects Maven itself, not the forked test JVM)
SUREFIRE_MEM='-DargLine=-Xmx2g'

# Handler module - all SSL tests (OpenSSL tests are patched to skip)
run_mvn "handler" ./mvnw -o test -pl handler -Dcheckstyle.skip=true -Danimal.sniffer.skip=true -Dsurefire.timeout=600 -DfailIfNoTests=false $SUREFIRE_MEM "$@" || HANDLER_RESULT=1

# Handler-Proxy tests (TLS via ProxyHandlerTest)
run_mvn "handler-proxy" ./mvnw -o test -pl handler-proxy -Dcheckstyle.skip=true -Danimal.sniffer.skip=true -Dsurefire.timeout=120 -DfailIfNoTests=false $SUREFIRE_MEM "$@" || PROXY_RESULT=1

# Testsuite (must stay JDK/wolfJSSE-only; no tcnative/OpenSSL)
run_mvn "testsuite" ./mvnw -o test -pl testsuite -Dcheckstyle.skip=true -Danimal.sniffer.skip=true -Dsurefire.timeout=900 -DfailIfNoTests=false $SUREFIRE_MEM "$@" || TESTSUITE_RESULT=1

echo ""
echo "============================================================"
echo "=== AGGREGATE TEST SUMMARY (all mvn runs) ==="
echo "============================================================"

TOTAL_RUN=0
TOTAL_FAIL=0
TOTAL_ERR=0
TOTAL_SKIP=0

for name in "${RUNS[@]}"; do
  line="$(extract_summary_line "$name")"
  if [ -z "$line" ]; then
    echo "- ${name}: (no surefire summary line found)"
  else
    echo "- ${name}: ${line}"
    add_totals_from_line "$line"
  fi
done

echo ""
echo "TOTAL: Tests run: ${TOTAL_RUN}, Failures: ${TOTAL_FAIL}, Errors: ${TOTAL_ERR}, Skipped: ${TOTAL_SKIP}"

echo ""
echo "========================================"
echo "=== ALL TESTS COMPLETE ==="
echo "========================================"

if [ $HANDLER_RESULT -ne 0 ] || [ $PROXY_RESULT -ne 0 ] || [ $TESTSUITE_RESULT -ne 0 ]; then
  echo "Some tests failed. Check logs above."
  exit 1
fi
EOF


# Default: run all tests
CMD ["/app/run-tests.sh"]
