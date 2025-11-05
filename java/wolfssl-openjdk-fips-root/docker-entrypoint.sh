#!/bin/bash
#
# Docker entrypoint script for wolfSSL FIPS 140-3 (Certificate #4718)
# compliant Java container (using wolfJCE and wolfJSSE with wolfCrypt
# FIPS underneath)
#
# This entrypoint script performs the following tasks:
#    1. Configures debug logging based on environment variables:
#        - `WOLFJCE_DEBUG`
#        - `WOLFJSSE_DEBUG`
#        - `WOLFJSSE_ENGINE_DEBUG`
#    2. Sets library paths for JNI libraries.
#    3. Verifies integrity of FIPS libraries before loading them:
#        - Checksums of wolfSSL native libraries (.so files)
#        - Checksums of provider JNI native libraries (.so files)
#        - Checksums of provider JAR files (wolfJCE, wolfJSSE)
#    4. Conducts FIPS container sanity checks (FipsInitCheck.java)
#        - List out all currently installed Java Security providers
#        - Verify wolfJCE is installed as provider at priority 1
#        - Verify wolfJSSE is installed as provider at priority 2
#        - Verify Java /lib/security/cacerts file is WKS format
#        - Forces run of FIPS POST by calling wolfJCE via MessageDigest class
#        - Sanity check java.security providers, ensure no non-compliant
#          providers are present
#        - Verify all JCA algorithms/services use wolfSSL providers
set -e

# Function to handle signals for graceful shutdown
cleanup() {
    echo "Shutting down gracefully..."
    exit 0
}

trap cleanup SIGTERM SIGINT

# Configure debug logging based on environment variables
# Support both friendly environment variables and direct JAVA_OPTS
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

# Support direct JAVA_OPTS from user (appends to our base JAVA_OPTS)
if [ -n "$USER_JAVA_OPTS" ]; then
    echo "Adding user-provided JAVA_OPTS: $USER_JAVA_OPTS"
    JAVA_OPTS="$JAVA_OPTS $USER_JAVA_OPTS"
fi

# Ensure provider JARs are always on CLASSPATH for ServiceLoader support
# This handles cases where users set a custom CLASSPATH but forget to include
# the provider JARs
PROVIDER_JARS="/usr/share/java/wolfcrypt-jni.jar:/usr/share/java/wolfssl-jsse.jar:/usr/share/java/filtered-providers.jar"

if [ -z "$CLASSPATH" ]; then
    # CLASSPATH not set, use only provider JARs
    export CLASSPATH="$PROVIDER_JARS"
else
    # CLASSPATH is set, check if it already contains our provider JARs
    if [[ ! "$CLASSPATH" =~ "wolfcrypt-jni.jar" ]] || \
       [[ ! "$CLASSPATH" =~ "wolfssl-jsse.jar" ]] || \
       [[ ! "$CLASSPATH" =~ "filtered-providers.jar" ]]; then
        # Provider JARs not found, append them
        echo "Note: User CLASSPATH detected, appending wolfSSL provider JARs for ServiceLoader support"
        export CLASSPATH="${CLASSPATH}:${PROVIDER_JARS}"
    fi
fi

export LD_LIBRARY_PATH=/usr/lib/jni:/usr/local/lib:$LD_LIBRARY_PATH
export JAVA_LIBRARY_PATH=/usr/lib/jni:/usr/local/lib

# Add library path to Java options for all Java processes
JAVA_OPTS="$JAVA_OPTS -Djava.library.path=$JAVA_LIBRARY_PATH"

# Run FIPS verification checks if enabled (default: true)
if [ "${FIPS_CHECK:-true}" = "true" ]; then
    # Verify library integrity before loading/using any libraries
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

    # Run FIPS container verification
    echo ""
    echo "================================================================================"
    echo "|                        FIPS Container Verification                           |"
    echo "================================================================================"
    echo ""
    echo "JAVA_TOOL_OPTIONS: $JAVA_TOOL_OPTIONS"
    if ! java $JAVA_OPTS -cp "/opt/wolfssl-fips/bin:/usr/share/java/*" FipsInitCheck; then
        echo ""
        echo "ERROR: FIPS build checks failed! Container will terminate."
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

# Execute the provided command
echo "Executing command: $@"
echo "JAVA_OPTS: $JAVA_OPTS"

# Export JAVA_OPTS so it's available to Java processes
export JAVA_OPTS

# If the command starts with 'java' or uses full path to java,
# we need to add JAVA_OPTS
if [ "$(basename "$1")" = "java" ] || [[ "$1" == */java ]]; then
    echo "Detected java command, merging JAVA_OPTS"
    # Reconstruct the command with JAVA_OPTS inserted
    JAVA_CMD="$1"
    shift
    echo "Final java command: $JAVA_CMD $JAVA_OPTS $*"
    exec $JAVA_CMD $JAVA_OPTS "$@"
else
    echo "Non-java command, executing directly"
    exec "$@"
fi

