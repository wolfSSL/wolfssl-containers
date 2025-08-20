# WolfSSL Python Container

This project provides Docker images for Python with wolfSSL as the cryptographic library, offering two distinct approaches to integrate wolfSSL with Python. Both images are based on `alpine:3.22` and use FIPS-enabled wolfSSL.

---

## Overview

The container is designed to replace OpenSSL with [wolfSSL](https://www.wolfssl.com/), a lightweight, embedded-friendly TLS/SSL library. It supports FIPS 140-3 compliance and provides two methods to integrate with Python:

1. **`Dockerfile.provider`**: Uses `wolfProvider` to register wolfSSL as the default OpenSSL provider system-wide.
2. **`Dockerfile.osp`**: Applies patches from [wolfSSL/osp](https://github.com/wolfSSL/osp/tree/master/Python) to completely replace OpenSSL in Python.

Both approaches are based on the official [Docker Python image](https://github.com/docker-library/python/blob/093598a0190ba9074b899d6a0a21a00c859aac56/3.12/alpine3.22/Dockerfile) with minimal modifications.

---

## Approaches

### 1. `Dockerfile.provider` (wolfProvider)
- **Method**: Registers wolfSSL as the default OpenSSL provider using `wolfProvider`.
- **Behavior**: wolfSSL is used for cryptographic operations, and OpenSSL remains available but is not used for cryptographic operations. All cryptographic operations are performed by wolfCrypt FIPS.
- **Python Version**: 3.12.11
- **Use Case**: Ideal for environments where OpenSSL is still needed alongside wolfSSL.

### 2. `Dockerfile.osp` (OpenSSL Replacement Patch)
- **Method**: Applies patches from [wolfSSL/osp](https://github.com/wolfSSL/osp/tree/master/Python) to replace OpenSSL entirely in Python.
- **Behavior**: Deletes `libcrypto.so*` and `libssl.so*` to prevent OpenSSL usage. This breaks other applications relying on OpenSSL.
- **Python Version**: 3.12.6
- **Use Case**: Strict FIPS compliance scenarios where OpenSSL must be entirely excluded.

---

## Notes

- **FIPS Compliance**: Both images enable FIPS support in wolfSSL.
- **OpenSSL Removal (osp)**: The `osp` image deletes OpenSSL libraries, which may break other applications requiring OpenSSL.
- **Build**: Use `make build-provider` or `make build-osp` to build images.
- **Run**: Use `make run-provider` or `make run-osp` to test the containers.
- **Password**: A file named `password.txt` containing the password to decrypt the wolfSSL FIPS archive is required in the same directory as the Dockerfiles when building.

---

## Directory Structure

- `Dockerfile.provider`: Builds the wolfProvider-based image.
- `Dockerfile.osp`: Builds the OpenSSL-replaced image.
- `Makefile`: Contains targets for building, running, and cleaning images.
