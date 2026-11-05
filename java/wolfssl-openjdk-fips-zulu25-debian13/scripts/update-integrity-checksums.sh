#!/bin/bash
# Regenerate the checksum file that integrity-check.sh verifies at container
# startup.
#
# The image build runs this once. A derived image that changes a protected
# file (for example adding a CA certificate to cacerts, or editing
# java.security or /etc/krb5.conf) runs it again as root after the change, or
# the startup integrity check fails:
#
#     USER root
#     RUN <modify cacerts> && /usr/local/bin/update-integrity-checksums.sh
#     USER 10001:10001
#
# It must run as root, since the checksum file is root-owned and read-only.
set -e

CHECKSUM_FILE="/opt/wolfssl-fips/checksums/libraries.sha256"

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: $0 must run as root (for example in a derived image Dockerfile)" >&2
    exit 1
fi

mkdir -p "$(dirname "$CHECKSUM_FILE")"
TMP_FILE="$(mktemp "${CHECKSUM_FILE}.XXXXXX")"

# A single sha256sum call fails if any file is missing
sha256sum \
    /usr/local/lib/libwolfssl.so* \
    /usr/lib/jni/libwolfcryptjni.so \
    /usr/lib/jni/libwolfssljni.so \
    /usr/share/java/wolfcrypt-jni.jar \
    /usr/share/java/wolfssl-jsse.jar \
    /usr/share/java/filtered-providers.jar \
    /usr/lib/jvm/zulu25/conf/security/java.security \
    /usr/lib/jvm/zulu25/lib/security/cacerts \
    /etc/krb5.conf \
    /opt/wolfssl-fips/bin/FipsInitCheck.class \
    > "$TMP_FILE" || { rm -f "$TMP_FILE"; exit 1; }

chmod 444 "$TMP_FILE"
mv -f "$TMP_FILE" "$CHECKSUM_FILE"
cat "$CHECKSUM_FILE"
