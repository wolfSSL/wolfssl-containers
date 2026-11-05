#!/bin/bash
# Verify that the wolfSSL native libraries, JNI libraries, provider JARs,
# security configuration files (java.security, cacerts, krb5.conf) and
# FipsInitCheck.class match the checksums recorded at image build time.
#
# The script and checksum file are root-owned and read-only, and the image
# runs as a non-root user, so applications cannot change them.
set -e

CHECKSUM_DIR="/opt/wolfssl-fips/checksums"

# Files that libraries.sha256 must list, or verification fails. Keep in sync
# with the file list in update-integrity-checksums.sh.
REQUIRED_FILES=(
    "/usr/lib/jni/libwolfcryptjni.so"
    "/usr/lib/jni/libwolfssljni.so"
    "/usr/share/java/wolfcrypt-jni.jar"
    "/usr/share/java/wolfssl-jsse.jar"
    "/usr/share/java/filtered-providers.jar"
    "/usr/lib/jvm/zulu25/conf/security/java.security"
    "/usr/lib/jvm/zulu25/lib/security/cacerts"
    "/etc/krb5.conf"
    "/opt/wolfssl-fips/bin/FipsInitCheck.class"
)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

verify_checksum_file() {
    local checksum_file="$1"
    local description="$2"
    local checksum_path="$CHECKSUM_DIR/$checksum_file"
    local all_valid=true

    echo "Verifying $description:"

    if [ ! -f "$checksum_path" ]; then
        echo -e "  ${RED}[FAIL]${NC} Checksum file not found: $checksum_path"
        return 1
    fi

    # Every required file must be listed, and at least one libwolfssl.so
    for required in "${REQUIRED_FILES[@]}"; do
        if ! awk '{print $2}' "$checksum_path" | grep -qxF "$required"; then
            echo -e "  ${RED}[FAIL]${NC} Not listed in checksum file: $required"
            all_valid=false
        fi
    done
    if ! awk '{print $2}' "$checksum_path" | grep -q '^/usr/local/lib/libwolfssl\.so'; then
        echo -e "  ${RED}[FAIL]${NC} Not listed in checksum file: /usr/local/lib/libwolfssl.so*"
        all_valid=false
    fi

    while IFS= read -r line; do
        [ -z "$line" ] && continue

        expected_checksum=$(echo "$line" | awk '{print $1}')
        file_path=$(echo "$line" | awk '{print $2}')

        if [ -z "$expected_checksum" ] || [ -z "$file_path" ]; then
            echo -e "  ${RED}[FAIL]${NC} Invalid checksum format: $line"
            all_valid=false
            continue
        fi

        if [ ! -f "$file_path" ]; then
            echo -e "  ${RED}[FAIL]${NC} File not found: $file_path"
            all_valid=false
            continue
        fi

        actual_checksum=$(sha256sum "$file_path" | awk '{print $1}')

        if [ "$expected_checksum" = "$actual_checksum" ]; then
            echo -e "  ${GREEN}[OK]${NC} $(basename "$file_path")"
        else
            echo -e "  ${RED}[FAIL]${NC} $(basename "$file_path") - INTEGRITY FAILURE"
            echo -e "    Expected: $expected_checksum"
            echo -e "    Actual:   $actual_checksum"
            all_valid=false
        fi

    done < "$checksum_path"

    if [ "$all_valid" = true ]; then
        return 0
    else
        return 1
    fi
}

# Main verification
all_components_valid=true

if ! verify_checksum_file "libraries.sha256" "sensitive libraries and files"; then
    all_components_valid=false
fi

echo ""

# Final result
if [ "$all_components_valid" = true ]; then
    echo -e "${GREEN}ALL FIPS COMPONENTS INTEGRITY VERIFIED${NC}"
    exit 0
else
    echo -e "${RED}FIPS INTEGRITY VERIFICATION FAILED${NC}"
    exit 1
fi

