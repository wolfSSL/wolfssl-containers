
# wolfSSL Docker Containers

This repository contains Docker containers and image definitions which utilize
wolfSSL products.

## Java Containers (./java)

This directory contains Dockerfiles for building Java-based containers using
wolfSSL JCE and JSSE Java Security Providers (wolfJCE, wolfJSSE).

### Available Dockerfiles

**wolfssl-openjdk-fips-root**

This is an OpenJDK 19 Docker image based on [rootpublic/openjdk:19-jdk-bookworm-slim](https://hub.docker.com/r/rootpublic/openjdk)
that integrates wolfSSL's FIPS 140-3 validated cryptographic library
(Certificate #4718), replacing all non-FIPS compliant Java cryptography
providers with wolfJCE and wolfJSSE. Only Java-based cryptography is in
scope for FIPS compliance in this container.

An active wolfCrypt FIPS license is needed to use this container. The associated
.7z archive password will also be provided when the appropriate FIPS license
is acquired from wolfSSL Inc. Please contact fips@wolfssl.com for more
information.

## Python Containers (./python)

This directory contains Dockerfiles for building Python-based containers using
wolfSSL's cryptographic libraries.

### Available Dockerfiles

**wolfssl-python-3.12-alpine3.22**

This is a Python 3.12 container based on [alpine:3.22](https://hub.docker.com/_/alpine) with wolfSSL integrated, providing secure cryptographic functions for Python applications.

# Support

Technical Support: support@wolfssl.com
General Questions: facts@wolfssl.com
Licensing Questions: licensing@wolfssl.com
FIPS Questions: fips@wolfssl.com

# License

wolfSSL and wolfCrypt are either licensed for use under the GPLv3 (or at your
option any later version) or a standard commercial license. For our users who
cannot use wolfSSL under GPLv3 (or any later version), a commercial license to
wolfSSL and wolfCrypt is available.

