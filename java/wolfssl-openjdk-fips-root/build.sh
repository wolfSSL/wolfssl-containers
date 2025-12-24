#!/bin/bash
# Build script for wolfSSL OpenJDK FIPS Root container

set -e

# Default values
IMAGE_NAME="wolfssl-openjdk-fips-root"
IMAGE_TAG="latest"
WOLFSSL_PASSWORD=""
BUILD_ARGS=""
export DOCKER_BUILDKIT=1
: "${BUILDKIT_PROGRESS:=auto}"
VERBOSE_MODE=false
WOLFCRYPT_JNI_LOCAL=""
WOLFSSL_JNI_LOCAL=""
WOLFCRYPT_JNI_REPO="https://github.com/wolfSSL/wolfcrypt-jni.git"
WOLFCRYPT_JNI_BRANCH="master"
WOLFSSL_JNI_REPO="https://github.com/wolfSSL/wolfssljni.git"
WOLFSSL_JNI_BRANCH="master"
ARCH=$(uname -m)
TARGET_PLATFORM=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -p, --password PASSWORD   wolfSSL commercial FIPS package password (required)"
    echo "  -n, --name NAME           Docker image name (default: wolfssl-openjdk-fips-root)"
    echo "  -t, --tag TAG             Docker image tag (default: latest)"
    echo "  --no-cache                Disable Docker build cache (cache enabled by default)"
    echo "  --cache-from IMAGE        Use cache from existing image for faster builds"
    echo "  --wolfcrypt-jni PATH      Use local wolfcrypt-jni directory instead of cloning from GitHub"
    echo "  --wolfssl-jni PATH        Use local wolfssljni directory instead of cloning from GitHub"
    echo "  --wolfcrypt-jni-repo URL  Use custom wolfcrypt-jni repository URL (default: https://github.com/wolfSSL/wolfcrypt-jni.git)"
    echo "  --wolfcrypt-jni-branch BRANCH  Use custom wolfcrypt-jni branch (default: master)"
    echo "  --wolfssl-jni-repo URL    Use custom wolfssljni repository URL (default: https://github.com/wolfSSL/wolfssljni.git)"
    echo "  --wolfssl-jni-branch BRANCH    Use custom wolfssljni branch (default: master)"
    echo "  -v, --verbose             Verbose Docker build output and enable wolfSSL debug logging during test"
    echo "  -h, --help                Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 -p your_password                        # Basic build (with cache)"
    echo "  $0 -p your_password --no-cache             # Build without cache"
    echo "  $0 -p your_password --cache-from myimg     # Use cache from existing image"
    echo "  $0 -p your_password -v                     # Verbose build with wolfSSL debug logging"
    echo "  $0 -p pass --wolfcrypt-jni ../wolfcryptjni # Use local wolfcrypt-jni directory"
    echo "  $0 -p pass --wolfssl-jni ../wolfssljni     # Use local wolfssljni directory"
    echo "  $0 -p pass --wolfcrypt-jni-repo https://github.com/myuser/wolfcrypt-jni.git  # Use custom repo"
    echo "  $0 -p pass --wolfssl-jni-branch develop    # Use develop branch"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--password)
            WOLFSSL_PASSWORD="$2"
            shift 2
            ;;
        -n|--name)
            IMAGE_NAME="$2"
            shift 2
            ;;
        -t|--tag)
            IMAGE_TAG="$2"
            shift 2
            ;;
        --no-cache)
            BUILD_ARGS="$BUILD_ARGS --no-cache"
            shift
            ;;
        --cache-from)
            BUILD_ARGS="$BUILD_ARGS --cache-from=$2"
            shift 2
            ;;
        --wolfcrypt-jni)
            WOLFCRYPT_JNI_LOCAL="$2"
            shift 2
            ;;
        --wolfssl-jni)
            WOLFSSL_JNI_LOCAL="$2"
            shift 2
            ;;
        --wolfcrypt-jni-repo)
            WOLFCRYPT_JNI_REPO="$2"
            shift 2
            ;;
        --wolfcrypt-jni-branch)
            WOLFCRYPT_JNI_BRANCH="$2"
            shift 2
            ;;
        --wolfssl-jni-repo)
            WOLFSSL_JNI_REPO="$2"
            shift 2
            ;;
        --wolfssl-jni-branch)
            WOLFSSL_JNI_BRANCH="$2"
            shift 2
            ;;
        -v|--verbose)
            BUILD_ARGS="$BUILD_ARGS --progress=plain"
            export BUILDKIT_PROGRESS=plain
            VERBOSE_MODE=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo -e "${RED}Error: Unknown option $1${NC}"
            usage
            exit 1
            ;;
    esac
done

# Validate required arguments
if [ -z "$WOLFSSL_PASSWORD" ]; then
    echo -e "${RED}Error: wolfSSL password is required${NC}"
    echo "Use -p or --password to specify the password"
    exit 1
fi

# Validate local directories if specified
if [ -n "$WOLFCRYPT_JNI_LOCAL" ]; then
    if [ ! -d "$WOLFCRYPT_JNI_LOCAL" ]; then
        echo -e "${RED}Error: wolfcrypt-jni directory does not exist: $WOLFCRYPT_JNI_LOCAL${NC}"
        exit 1
    fi
    # Convert to absolute path
    WOLFCRYPT_JNI_LOCAL=$(cd "$WOLFCRYPT_JNI_LOCAL" && pwd)
    BUILD_ARGS="$BUILD_ARGS --build-arg WOLFCRYPT_JNI_LOCAL=$WOLFCRYPT_JNI_LOCAL"
    echo -e "${YELLOW}Using local wolfcrypt-jni: $WOLFCRYPT_JNI_LOCAL${NC}"
else
    BUILD_ARGS="$BUILD_ARGS --build-arg WOLFCRYPT_JNI_REPO=$WOLFCRYPT_JNI_REPO"
    BUILD_ARGS="$BUILD_ARGS --build-arg WOLFCRYPT_JNI_BRANCH=$WOLFCRYPT_JNI_BRANCH"
    echo -e "${YELLOW}Using wolfcrypt-jni repo: $WOLFCRYPT_JNI_REPO (branch: $WOLFCRYPT_JNI_BRANCH)${NC}"
fi

if [ -n "$WOLFSSL_JNI_LOCAL" ]; then
    if [ ! -d "$WOLFSSL_JNI_LOCAL" ]; then
        echo -e "${RED}Error: wolfssljni directory does not exist: $WOLFSSL_JNI_LOCAL${NC}"
        exit 1
    fi
    # Convert to absolute path
    WOLFSSL_JNI_LOCAL=$(cd "$WOLFSSL_JNI_LOCAL" && pwd)
    BUILD_ARGS="$BUILD_ARGS --build-arg WOLFSSL_JNI_LOCAL=$WOLFSSL_JNI_LOCAL"
    echo -e "${YELLOW}Using local wolfssljni: $WOLFSSL_JNI_LOCAL${NC}"
else
    BUILD_ARGS="$BUILD_ARGS --build-arg WOLFSSL_JNI_REPO=$WOLFSSL_JNI_REPO"
    BUILD_ARGS="$BUILD_ARGS --build-arg WOLFSSL_JNI_BRANCH=$WOLFSSL_JNI_BRANCH"
    echo -e "${YELLOW}Using wolfssljni repo: $WOLFSSL_JNI_REPO (branch: $WOLFSSL_JNI_BRANCH)${NC}"
fi

# Get architecture
if [ "$ARCH" == "x86_64" ] || [ "$ARCH" == "amd64" ]; then
    TARGET_PLATFORM="linux/amd64"
elif [ "$ARCH" == "arm64" ] || [ "$ARCH" == "aarch64" ]; then
    TARGET_PLATFORM="linux/arm64"
else
    echo -e "${RED}Error: Unsupported architecture '${ARCH}'. Supported values are: x86_64, arm64.${NC}"
        exit 1
fi

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}Error: Docker is not running${NC}"
    exit 1
fi

# Create full image name
FULL_IMAGE_NAME="${IMAGE_NAME}:${IMAGE_TAG}"

echo -e "${GREEN}Building FIPS-compliant wolfSSL OpenJDK container...${NC}"
echo -e "${YELLOW}Image name: $FULL_IMAGE_NAME${NC}"
echo ""

# Prepare build context with local directories if specified
cleanup_build_context() {
    echo -e "${YELLOW}Cleaning up build context...${NC}"
    [ -d "wolfcrypt-jni-local" ] && rm -rf wolfcrypt-jni-local
    [ -d "wolfssl-jni-local" ] && rm -rf wolfssl-jni-local
}

# Setup cleanup trap
trap cleanup_build_context EXIT

# Copy local directories into build context (Docker BuildKit doesn't handle symlinks well)
if [ -n "$WOLFCRYPT_JNI_LOCAL" ]; then
    echo -e "${YELLOW}Copying local wolfcrypt-jni: $WOLFCRYPT_JNI_LOCAL -> wolfcrypt-jni-local${NC}"
    rm -rf wolfcrypt-jni-local 2>/dev/null || true
    cp -r "$WOLFCRYPT_JNI_LOCAL" wolfcrypt-jni-local
    if [ ! -d wolfcrypt-jni-local ]; then
        echo -e "${RED}Error: Failed to copy wolfcrypt-jni directory${NC}"
        exit 1
    fi
else
    mkdir -p wolfcrypt-jni-local
fi

if [ -n "$WOLFSSL_JNI_LOCAL" ]; then
    echo -e "${YELLOW}Copying local wolfssljni: $WOLFSSL_JNI_LOCAL -> wolfssl-jni-local${NC}"
    rm -rf wolfssl-jni-local 2>/dev/null || true
    cp -r "$WOLFSSL_JNI_LOCAL" wolfssl-jni-local
    if [ ! -d wolfssl-jni-local ]; then
        echo -e "${RED}Error: Failed to copy wolfssljni directory${NC}"
        exit 1
    fi
else
    mkdir -p wolfssl-jni-local
fi

# Build the image
echo -e "${GREEN}Starting Docker build...${NC}"
export DOCKER_BUILDKIT=$DOCKER_BUILDKIT

# Prepare BuildKit secret
if [[ -n "${WOLFSSL_PASSWORD:-}" ]]; then
    export WOLFSSL_PASSWORD
    SECRET_FLAG=( --secret id=wolfssl_pw,env=WOLFSSL_PASSWORD )
else
    echo "ERROR: Missing wolfSSL commercial bundle password. Use -p/--password." >&2
    exit 2
fi

docker build \
    --platform "$TARGET_PLATFORM" \
    $BUILD_ARGS \
    "${SECRET_FLAG[@]}" \
    -t "$FULL_IMAGE_NAME" \
    -f Dockerfile \
    .

if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}Build completed successfully!${NC}"
    echo -e "${GREEN}Image: $FULL_IMAGE_NAME${NC}"
    echo ""

    # Show image size
    echo -e "${YELLOW}Image size:${NC}"
    docker images "$FULL_IMAGE_NAME" --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}"
    echo ""

    # Test the image
    echo -e "${GREEN}Testing the image...${NC}"
    if [ "$VERBOSE_MODE" = true ]; then
        echo -e "${YELLOW}Running container test with wolfSSL debug logging enabled...${NC}"
    else
        echo -e "${YELLOW}Running basic container test...${NC}"
    fi

    # Set debug environment variables if verbose mode is enabled
    DEBUG_ENV=""
    if [ "$VERBOSE_MODE" = true ]; then
        DEBUG_ENV="-e WOLFJCE_DEBUG=true -e WOLFJSSE_DEBUG=true"
    fi

    # Capture container test output for detailed error reporting
    if test_output=$(docker run --rm $DEBUG_ENV "$FULL_IMAGE_NAME" 2>&1); then
        echo -e "${GREEN}Container test passed${NC}"
    else
        echo -e "${RED}Container test failed${NC}"
        echo ""
        echo -e "${RED}=== Container Test Output ===${NC}"
        echo "$test_output"
        echo -e "${RED}=== End Container Test Output ===${NC}"
        echo ""
        exit 1
    fi

    echo ""
    echo -e "${GREEN}Build Summary:${NC}"
    echo -e "${GREEN}  Image: $FULL_IMAGE_NAME${NC}"
    echo -e "${GREEN}  Status: Ready for use${NC}"
    echo ""
    echo -e "${YELLOW}To run the container:${NC}"
    echo "  docker run -it $FULL_IMAGE_NAME"
    echo ""
    echo -e "${YELLOW}To run with debug logging:${NC}"
    echo "  docker run -e WOLFJCE_DEBUG=true -e WOLFJSSE_DEBUG=true $FULL_IMAGE_NAME"
    echo ""
    echo -e "${YELLOW}To disable FIPS validation on startup:${NC}"
    echo "  docker run -e FIPS_CHECK=false $FULL_IMAGE_NAME"
    echo ""

else
    echo -e "${RED}Build failed${NC}"
    exit 1
fi

