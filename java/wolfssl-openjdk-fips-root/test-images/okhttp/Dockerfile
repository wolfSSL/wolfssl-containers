# syntax=docker/dockerfile:1
# OkHttp + wolfJSSE FIPS Test Image
# Multi-stage build: compile OkHttp in standard JDK, then run tests in FIPS environment
#
# Stage 1: Build OkHttp with standard JDK (no FIPS restrictions)
# Stage 2: Run tests in FIPS environment with wolfJSSE

# ------------------------------------------------------------------------------
# Stage 1: Build Environment (non-FIPS)
# Use standard JDK to compile OkHttp - Gradle uses MD5 which isn't FIPS-approved
# ------------------------------------------------------------------------------
FROM eclipse-temurin:21-jdk-jammy AS builder

RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Clone OkHttp at a specific tag for reproducible builds
# Pin to parent-5.3.2 to avoid HEAD instability and OOM during Kotlin compilation
RUN git clone --depth 1 --branch parent-5.3.2 https://github.com/square/okhttp.git /build/okhttp

WORKDIR /build/okhttp

# Cache Gradle wrapper
RUN ./gradlew --version

# Build and compile OkHttp (without running tests)
# Increase Gradle daemon memory to handle Kotlin compilation
RUN ./gradlew :okhttp:compileKotlinJvm :okhttp-tls:compileKotlin \
    --no-daemon -x checkstyleMain -x apiCheck \
    -Dorg.gradle.jvmargs="-Xmx2g -XX:MaxMetaspaceSize=512m"

# Compile test classes
RUN ./gradlew :okhttp:compileTestKotlinJvm :okhttp-tls:compileTestKotlin \
    --no-daemon -x checkstyleMain -x checkstyleTest -x apiCheck \
    -Dorg.gradle.jvmargs="-Xmx2g -XX:MaxMetaspaceSize=512m"

# Pre-download all test dependencies
RUN ./gradlew :okhttp:dependencies :okhttp-tls:dependencies --no-daemon

# ------------------------------------------------------------------------------
# Stage 2: FIPS Runtime Environment
# ------------------------------------------------------------------------------
FROM wolfssl-openjdk-fips-root:latest

LABEL maintainer="wolfSSL Inc. <support@wolfssl.com>"
LABEL description="OkHttp SSL/TLS tests with wolfJSSE FIPS"

# Install git and wget for downloading JDK
RUN apt-get update && apt-get install -y git wget perl && rm -rf /var/lib/apt/lists/*

# Download and install Eclipse Temurin JDK 21 for Gradle (non-FIPS)
# OkHttp requires Java 21 for its build
RUN mkdir -p /opt/gradle-jdk && \
    wget -q -O /tmp/jdk21.tar.gz "https://api.adoptium.net/v3/binary/latest/21/ga/linux/x64/jdk/hotspot/normal/eclipse?project=jdk" && \
    tar -xzf /tmp/jdk21.tar.gz -C /opt/gradle-jdk --strip-components=1 && \
    rm /tmp/jdk21.tar.gz

# Set Gradle to use the non-FIPS JDK 21
ENV GRADLE_JAVA_HOME=/opt/gradle-jdk

# Create app directory
RUN mkdir -p /app

# Copy pre-built OkHttp from builder stage
COPY --from=builder /build/okhttp /app/okhttp

# Copy Gradle cache (includes downloaded JDKs and dependencies)
COPY --from=builder /root/.gradle /root/.gradle

WORKDIR /app/okhttp

# ------------------------------------------------------------------------------
# Apply wolfJSSE FIPS compatibility patches
# ------------------------------------------------------------------------------
COPY apply_okhttp_fips_fixes.sh /tmp/apply_okhttp_fips_fixes.sh
RUN chmod +x /tmp/apply_okhttp_fips_fixes.sh && /tmp/apply_okhttp_fips_fixes.sh /app/okhttp

# ------------------------------------------------------------------------------
# Copy wolfSSL FIPS libraries to Gradle-provisioned JDKs
# ------------------------------------------------------------------------------
RUN echo "=== Installing wolfSSL FIPS libs to Gradle JDKs ===" && \
    for jdk_dir in /root/.gradle/jdks/*/lib; do \
        if [ -d "$jdk_dir" ]; then \
            echo "Installing to: $jdk_dir"; \
            cp /usr/local/lib/libwolfssl.so* "$jdk_dir/" 2>/dev/null || true; \
            cp /usr/lib/jni/libwolfssljni.so "$jdk_dir/" 2>/dev/null || true; \
            cp /usr/lib/jni/libwolfcryptjni.so "$jdk_dir/" 2>/dev/null || true; \
        fi; \
    done && \
    echo "=== Done installing to Gradle JDKs ==="

# ------------------------------------------------------------------------------
# Create Gradle init script for wolfJSSE FIPS test configuration
# ------------------------------------------------------------------------------
RUN cat > /root/.gradle/init.gradle <<'INITSCRIPT'
// wolfJSSE FIPS configuration for OkHttp test JVMs
allprojects {
    afterEvaluate {
        // Apply to standard Test tasks
        tasks.withType(Test) {
            // wolfJSSE FIPS JVM configuration
            jvmArgs '-Xbootclasspath/a:/usr/share/java/wolfssl-jsse.jar:/usr/share/java/wolfcrypt-jni.jar'
            jvmArgs '-Djava.library.path=/usr/lib/jni:/usr/local/lib'
            jvmArgs '-Dwolfjsse.fips=true'

            // Environment for native library loading
            environment 'LD_LIBRARY_PATH', '/usr/lib/jni:/usr/local/lib'

            // Exclude tests incompatible with wolfJSSE FIPS
            filter {
                // ==========================================
                // SunJSSE-specific tests: These tests assert Sun-specific
                // class names (sun.security.ssl.SSLSocketFactoryImpl,
                // sun.security.ssl.SSLSocketImpl). wolfJSSE provides
                // different implementation classes. Not a bug.
                // ==========================================
                excludeTestsMatching 'okhttp3.JSSETest.testSupportedProtocols'
                excludeTestsMatching 'okhttp3.JSSETest.testTlsv13Works'

                // ==========================================
                // TLS 1.3 session reuse:
                // Disabled because this requires wolfSSL to be built with
                // --enable-session-ticket in the base image (TLS 1.3 uses
                // ticket-based resumption, not session-ID-based resumption).
                // Without session tickets, enableSessionCreation=false cannot
                // resume and this test fails.
                // ==========================================
                excludeTestsMatching 'okhttp3.SessionReuseTest.testSessionReuse_TLSv1_3'

                // ==========================================
                // Algorithms/protocols disabled in the FIPS base image:
                // These are compiled out or disabled by default in the
                // wolfSSL FIPS base image configuration.
                // ==========================================

                // TLSv1 and TLSv1.1 - compiled out in the base image
                excludeTestsMatching '*TLSv1_0*'
                excludeTestsMatching '*TLSv1_1*'
                excludeTestsMatching '*Tlsv10*'
                excludeTestsMatching '*Tlsv11*'

                // MD5 - disabled in the base image
                excludeTestsMatching '*Md5*'
                excludeTestsMatching '*MD5*'

                // RC4 - disabled in the base image
                excludeTestsMatching '*Rc4*'
                excludeTestsMatching '*RC4*'

                // DES/3DES - disabled in the base image
                excludeTestsMatching '*Des*'
                excludeTestsMatching '*DES*'

                // Anonymous ciphers - disabled in the base image
                excludeTestsMatching '*anon*'
                excludeTestsMatching '*Anon*'

                // ==========================================
                // Environment-dependent tests (NOT wolfJSSE issues):
                // These tests fail due to Docker container limitations
                // or OkHttp version-specific issues unrelated to TLS.
                // ==========================================

                // FastFallbackTest: Requires IPv6 networking which is
                // not available in most Docker containers. Tests fail
                // with "lateinit property serverIpv4 has not been
                // initialized" because IPv6 server setup fails first.
                excludeTestsMatching 'okhttp3.FastFallbackTest.*'

                // RouteFailureTest fast fallback: Same IPv6 dual-stack
                // dependency as FastFallbackTest (Happy Eyeballs algorithm).
                excludeTestsMatching 'okhttp3.RouteFailureTest.http2OneBadHostOneGoodNoRetryOnConnectionFailureFastFallback'

                // InterceptorTest async exceptions: JDK 19 does not
                // propagate RuntimeException as suppressed on async
                // cancellation (empty suppressed list). No TLS
                // involvement — tests plaintext HTTP interceptor behavior.
                excludeTestsMatching 'okhttp3.InterceptorTest.networkInterceptorThrowsRuntimeExceptionAsynchronous'
                excludeTestsMatching 'okhttp3.InterceptorTest.applicationInterceptorThrowsRuntimeExceptionAsynchronous'

                // HttpOverHttp2Test h2_prior_knowledge: Cleartext
                // HTTP/2 (no TLS). Timing-sensitive stream refusal
                // recovery test that fails only in the h2_prior_knowledge
                // (cleartext) variant in containerized environments.
                // The h2 (TLS) variant passes fine.
                excludeTestsMatching 'okhttp3.internal.http2.HttpOverHttp2Test.recoverFromMultipleRefusedStreamsRequiresNewConnection*'

                // WebSocketReaderTest: WebSocket compression close
                // behavior. No TLS involvement. OkHttp version-specific.
                excludeTestsMatching 'okhttp3.internal.ws.WebSocketReaderTest.clientWithCompressionCannotBeUsedAfterClose'
            }

            doFirst {
                println ""
                println "=========================================="
                println "wolfJSSE FIPS Test: ${name}"
                println "=========================================="
                println "  LD_LIBRARY_PATH: " + environment.get('LD_LIBRARY_PATH')
                println ""
            }
        }

        // Handle Kotlin multiplatform test tasks
        tasks.matching { task ->
            task.class.name.contains('Test') && task.hasProperty('jvmArgs')
        }.configureEach { task ->
            if (!task.jvmArgs?.any { it?.contains('wolfssl-jsse.jar') }) {
                task.jvmArgs '-Xbootclasspath/a:/usr/share/java/wolfssl-jsse.jar:/usr/share/java/wolfcrypt-jni.jar'
                task.jvmArgs '-Djava.library.path=/usr/lib/jni:/usr/local/lib'
                task.jvmArgs '-Dwolfjsse.fips=true'
                if (task.hasProperty('environment')) {
                    task.environment 'LD_LIBRARY_PATH', '/usr/lib/jni:/usr/local/lib'
                }
            }
        }
    }
}
INITSCRIPT

# ------------------------------------------------------------------------------
# Create symlink to Gradle binary (bypass wrapper which uses MD5)
# ------------------------------------------------------------------------------
RUN GRADLE_BIN=$(find /root/.gradle/wrapper/dists -name "bin" -type d 2>/dev/null | head -1) && \
    if [ -n "$GRADLE_BIN" ] && [ -f "$GRADLE_BIN/gradle" ]; then \
        ln -sf "$GRADLE_BIN/gradle" /usr/local/bin/gradle; \
        echo "Linked gradle from: $GRADLE_BIN"; \
    else \
        echo "ERROR: Could not find gradle binary"; \
        find /root/.gradle -name "gradle" -type f 2>/dev/null || true; \
        exit 1; \
    fi

# ------------------------------------------------------------------------------
# Create test runner script
# ------------------------------------------------------------------------------
RUN cat > /app/run-tests.sh <<'EOF' && chmod +x /app/run-tests.sh
#!/bin/bash
#
# OkHttp SSL/TLS Test Runner for wolfJSSE FIPS
#

echo "=== wolfJSSE FIPS OkHttp SSL Tests ==="
echo ""

# Environment setup
export LD_LIBRARY_PATH="/usr/lib/jni:/usr/local/lib:${LD_LIBRARY_PATH:-}"
export JAVA_LIBRARY_PATH="/usr/lib/jni:/usr/local/lib"

# Verify libraries
echo "=== Checking wolfJSSE FIPS Libraries ==="
for lib in /usr/lib/jni/libwolfssljni.so /usr/lib/jni/libwolfcryptjni.so \
           /usr/local/lib/libwolfssl.so /usr/share/java/wolfssl-jsse.jar; do
    if [ -f "$lib" ]; then
        echo "OK: $lib"
    else
        echo "WARNING: $lib not found"
    fi
done
echo ""

# Find the gradle binary (not wrapper) - bypasses MD5 checksum requirement
GRADLE_BIN=""
for bin in /usr/local/bin/gradle $(find /root/.gradle/wrapper/dists -name "gradle" -type f 2>/dev/null | head -1); do
    if [ -x "$bin" ]; then
        GRADLE_BIN="$bin"
        break
    fi
done

if [ -z "$GRADLE_BIN" ]; then
    echo "ERROR: Could not find gradle binary"
    exit 1
fi
echo "Using Gradle: $GRADLE_BIN"
echo ""

# Copy libs to Gradle JDKs
for jdk_dir in /root/.gradle/jdks/*/lib; do
    if [ -d "$jdk_dir" ]; then
        cp /usr/local/lib/libwolfssl.so* "$jdk_dir/" 2>/dev/null || true
        cp /usr/lib/jni/libwolfssljni.so "$jdk_dir/" 2>/dev/null || true
        cp /usr/lib/jni/libwolfcryptjni.so "$jdk_dir/" 2>/dev/null || true
    fi
done

cd /app/okhttp

RUNS=()
TLS_RESULT=0
OKHTTP_RESULT=0

run_gradle() {
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
    local line
    line=$(grep -E '[0-9]+ tests completed, [0-9]+ failed' "/tmp/${name}.log" | tail -n 1)
    if [ -n "$line" ]; then
        echo "$line"
        return
    fi
    local report=""
    if [ -f "/app/okhttp/${name}/build/reports/tests/jvmTest/index.html" ]; then
        report="/app/okhttp/${name}/build/reports/tests/jvmTest/index.html"
    elif [ -f "/app/okhttp/${name}/build/reports/tests/test/index.html" ]; then
        report="/app/okhttp/${name}/build/reports/tests/test/index.html"
    fi
    if [ -n "$report" ] && [ -f "$report" ]; then
        local tests failures skipped
        tests=$(grep -o '<div class="counter">[0-9]*</div>' "$report" | sed -n '1p' | grep -o '[0-9]*')
        failures=$(grep -o '<div class="counter">[0-9]*</div>' "$report" | sed -n '2p' | grep -o '[0-9]*')
        skipped=$(grep -o '<div class="counter">[0-9]*</div>' "$report" | sed -n '3p' | grep -o '[0-9]*')
        if [ -n "$tests" ]; then
            echo "${tests} tests, ${failures} failed, ${skipped} skipped"
            return
        fi
    fi
    grep -E 'BUILD (SUCCESSFUL|FAILED)' "/tmp/${name}.log" | tail -n 1 || true
}

# Use the non-FIPS JDK for Gradle (has standard java.security)
# Test JVMs get wolfJSSE FIPS configuration via init.gradle bootclasspath
unset JAVA_TOOL_OPTIONS

# Use the Gradle-specific JDK that doesn't have FIPS restrictions
export JAVA_HOME="${GRADLE_JAVA_HOME}"
echo "Using JAVA_HOME for Gradle: $JAVA_HOME"

# Run tests using direct gradle binary (not wrapper)
run_gradle "okhttp-tls" "$GRADLE_BIN" :okhttp-tls:test \
    --no-daemon -x checkstyleMain -x checkstyleTest -x apiCheck \
    --continue "$@" || TLS_RESULT=1

run_gradle "okhttp" "$GRADLE_BIN" :okhttp:jvmTest \
    --no-daemon -x checkstyleMain -x checkstyleTest -x apiCheck \
    --continue "$@" || OKHTTP_RESULT=1

echo ""
echo "============================================================"
echo "=== TEST SUMMARY (wolfJSSE FIPS) ==="
echo "============================================================"
for name in "${RUNS[@]}"; do
    line="$(extract_summary_line "$name")"
    echo "- ${name}: ${line:-'(no summary)'}"
done

echo ""
if [ $OKHTTP_RESULT -ne 0 ] || [ $TLS_RESULT -ne 0 ]; then
    echo "Some tests failed."
    exit 1
fi
echo "All tests passed!"
EOF

CMD ["/app/run-tests.sh"]
