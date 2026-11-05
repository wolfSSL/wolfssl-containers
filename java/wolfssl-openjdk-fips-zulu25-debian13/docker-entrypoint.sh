#!/bin/bash
#
# Entrypoint for the wolfSSL FIPS 140-3 (Certificate #5548) Java container
# (wolfJCE and wolfJSSE on wolfCrypt FIPS). It:
#    1. Enables debug logging from WOLFJCE_DEBUG, WOLFJSSE_DEBUG and
#       WOLFJSSE_ENGINE_DEBUG.
#    2. Sets the JNI library paths.
#    3. Verifies the checksums of the native and JNI libraries, provider JARs,
#       security configuration files and FipsInitCheck.class
#       (integrity-check.sh).
#    4. Runs the FipsInitCheck startup checks (listed in the README).
#    5. Runs the command, passing JAVA_OPTS to java and jshell.
# FIPS_CHECK=false skips steps 3 and 4 (development only).
set -e

# Exit cleanly on SIGTERM and SIGINT
cleanup() {
    echo "Shutting down gracefully..."
    exit 0
}

trap cleanup SIGTERM SIGINT

# Debug logging from environment variables
if [ "$WOLFJCE_DEBUG" = "true" ]; then
    echo "Enabling wolfJCE debug logging"
    JAVA_OPTS="$JAVA_OPTS -Dwolfjce.debug=true"
fi

if [ "$WOLFJSSE_DEBUG" = "true" ]; then
    echo "Enabling wolfJSSE debug logging"
    JAVA_OPTS="$JAVA_OPTS -Dwolfjsse.debug=true"
fi

if [ "$WOLFJSSE_ENGINE_DEBUG" = "true" ]; then
    echo "Enabling wolfJSSE SSLEngine debug logging"
    JAVA_OPTS="$JAVA_OPTS -Dwolfsslengine.debug=true"
fi

# USER_JAVA_OPTS is appended to JAVA_OPTS
if [ -n "$USER_JAVA_OPTS" ]; then
    echo "Adding user-provided JAVA_OPTS: $USER_JAVA_OPTS"
    JAVA_OPTS="$JAVA_OPTS $USER_JAVA_OPTS"
fi

# The provider JARs load from the JVM module path set in the image's
# JAVA_TOOL_OPTIONS (see the Dockerfile), not from CLASSPATH. Warn if
# JAVA_TOOL_OPTIONS was replaced instead of appended to, since then no JVM in
# the container has the wolfSSL providers.
case "$JAVA_TOOL_OPTIONS" in
    *--add-modules=com.wolfssl.wolfcrypt,com.wolfssl,com.wolfssl.security.providers*) ;;
    *)
        echo "WARNING: JAVA_TOOL_OPTIONS does not contain this image's provider module"
        echo "         settings (--module-path / --add-modules). It was probably replaced"
        echo "         instead of appended to, so the wolfSSL FIPS providers will not load."
        echo "         Append options to the image default JAVA_TOOL_OPTIONS instead."
        ;;
esac

export LD_LIBRARY_PATH=/usr/lib/jni:/usr/local/lib:$LD_LIBRARY_PATH
export JAVA_LIBRARY_PATH=/usr/lib/jni:/usr/local/lib

# Add library path to Java options for all Java processes
JAVA_OPTS="$JAVA_OPTS -Djava.library.path=$JAVA_LIBRARY_PATH"

# Split JAVA_OPTS into words once, without glob expansion, for the java and
# jshell commands below. An unquoted $JAVA_OPTS would also expand wildcards
# such as "-cp /app/lib/*" against the file system.
read -r -a JAVA_OPTS_ARR <<< "$JAVA_OPTS"

# Run the FIPS checks unless FIPS_CHECK is "false" (any case). Any other
# value, including unset or mistyped, runs them.
if [ "${FIPS_CHECK,,}" != "false" ]; then
    # Verify file integrity before any library is loaded
    echo ""
    echo "================================================================================"
    echo "|                       Library Checksum Verification                          |"
    echo "================================================================================"
    echo ""
    if ! /usr/local/bin/integrity-check.sh; then
        echo ""
        echo "ERROR: FIPS library integrity verification failed! Container will terminate."
        exit 1
    fi

    echo ""
    echo "================================================================================"
    echo "|                        FIPS Container Verification                           |"
    echo "================================================================================"
    echo ""
    echo "JAVA_TOOL_OPTIONS: $JAVA_TOOL_OPTIONS"
    # No provider JARs on -cp. FipsInitCheck loads the providers from the
    # module path, as applications do. It exits with the requested code only
    # after all checks pass, so launcher options in JAVA_OPTS that exit
    # before main() (such as -version) cannot look like a pass.
    FIPS_CHECK_PASS_CODE=42
    rc=0
    java "${JAVA_OPTS_ARR[@]}" -cp "/opt/wolfssl-fips/bin" FipsInitCheck \
        --pass-exit-code=$FIPS_CHECK_PASS_CODE || rc=$?
    if [ "$rc" -ne "$FIPS_CHECK_PASS_CODE" ]; then
        echo ""
        echo "ERROR: FIPS startup checks failed! Container will terminate."
        exit 1
    fi

    echo ""
    echo "================================================================================"
    echo "|                         All Container Tests Passed                           |"
    echo "================================================================================"
    echo ""
else
    echo ""
    echo "================================================================================"
    echo "|                        FIPS Verification Disabled                            |"
    echo "================================================================================"
    echo ""
    echo "WARNING: FIPS_CHECK=false - Skipping FIPS verification tests"
    echo "This mode is intended for development/testing only and should not be used in production"
    echo ""
fi

# Run the command
echo "Executing command: $@"
echo "JAVA_OPTS: $JAVA_OPTS"

export JAVA_OPTS

# Add JAVA_OPTS to a java command (by name or full path)
if [ "$(basename "$1")" = "java" ] || [[ "$1" == */java ]]; then
    echo "Detected java command, merging JAVA_OPTS"
    JAVA_CMD="$1"
    shift
    echo "Final java command: $JAVA_CMD $JAVA_OPTS $*"
    exec "$JAVA_CMD" "${JAVA_OPTS_ARR[@]}" "$@"
elif [ "$(basename "$1")" = "jshell" ]; then
    # jshell runs snippets in a separate JVM. Pass each JAVA_OPTS option to
    # that JVM (-R), where user code runs. jshell's own JVM keeps its
    # defaults, so debug logs show only snippet activity, not jshell
    # internals. Add -J options on the command line to debug jshell itself.
    echo "Detected jshell command, passing JAVA_OPTS to the snippet JVM with -R"
    JSHELL_CMD="$1"
    shift
    JSHELL_OPTS=()
    for opt in "${JAVA_OPTS_ARR[@]}"; do
        JSHELL_OPTS+=("-R$opt")
    done
    echo "Final jshell command: $JSHELL_CMD ${JSHELL_OPTS[*]} $*"
    exec "$JSHELL_CMD" "${JSHELL_OPTS[@]}" "$@"
else
    echo "Non-java command, executing directly"
    exec "$@"
fi

