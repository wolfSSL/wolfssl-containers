# Simple FIPS Test Application Docker Image
# Extends the wolfssl-openjdk-fips-root base image to provide basic testing
# of JCA cryptographic operations and TLS functionality

FROM wolfssl-openjdk-fips-root:latest

LABEL maintainer="wolfSSL Inc. <support@wolfssl.com>"
LABEL description="FIPS-compliant wolfSSL Java test application demonstrating JCA and TLS usage"

# Create application directory
RUN mkdir -p /app/test

# Copy test application source files
COPY src/main/*.java /app/test/

# Compile the test application
WORKDIR /app/test
RUN javac -cp "/opt/wolfssl-fips/bin:/usr/share/java/*" \
    *.java

# Set the working directory back to /app
WORKDIR /app

# Add test application classes to CLASSPATH
# Base image already includes provider JARs in CLASSPATH, so we just prepend our app directory
ENV CLASSPATH="/app/test:${CLASSPATH}"

# Default command runs the comprehensive FIPS test suite
# Users can override this to run individual test classes
CMD ["java", "FipsUserApplication"]

# Alternative commands for running specific test suites:
# docker run wolfssl-fips-basic-test-image:latest java CryptoTestSuite
# docker run wolfssl-fips-basic-test-image:latest java TlsTestSuite
