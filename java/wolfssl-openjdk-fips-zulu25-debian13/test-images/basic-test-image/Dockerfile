# FIPS test application image. Extends the
# wolfssl-openjdk-fips-zulu25-debian13 base image to test JCA cryptographic
# operations and TLS.

# Base image to build on (build.sh -b/--base sets it)
ARG BASE_IMAGE=wolfssl-openjdk-fips-zulu25-debian13:latest
FROM ${BASE_IMAGE}

LABEL maintainer="wolfSSL Inc. <support@wolfssl.com>"
LABEL description="FIPS-compliant wolfSSL Java test application demonstrating JCA and TLS usage"

# The base image runs as non-root user 10001. Switch to root for the build
# steps, then back to the base image user below.
USER root

RUN mkdir -p /app/test

COPY src/main/*.java /app/test/

WORKDIR /app/test
RUN javac -cp "/opt/wolfssl-fips/bin:/usr/share/java/*" \
    *.java

WORKDIR /app

# Application classes on CLASSPATH. The base image loads the wolfSSL providers
# from the module path (JAVA_TOOL_OPTIONS), so they are not listed here.
ENV CLASSPATH="/app/test"

USER 10001:10001

# Runs all test suites. To run one:
#   docker run wolfssl-fips-zulu25-basic-test-image:latest java CryptoTestSuite
#   docker run wolfssl-fips-zulu25-basic-test-image:latest java TlsTestSuite
CMD ["java", "FipsUserApplication"]
