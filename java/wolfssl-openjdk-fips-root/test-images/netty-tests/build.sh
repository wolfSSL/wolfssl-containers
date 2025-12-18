#!/bin/bash

# Netty SSL Tests Docker Image Build Script
# Builds a Netty test container that runs SSL tests with wolfJSSE in FIPS mode

set -e

# Default values
IMAGE_NAME="netty-wolfjsse"
TAG="latest"
VERBOSE=false
NO_CACHE=false
BASE_IMAGE="wolfssl-openjdk-fips-root:latest"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print usage information
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Build the Netty SSL tests Docker image with wolfJSSE FIPS support"
    echo ""
    echo "OPTIONS:"
    echo "  -n, --name NAME      Set image name (default: netty-wolfjsse)"
    echo "  -t, --tag TAG        Set image tag (default: latest)"
    echo "  -b, --base BASE      Set base image (default: wolfssl-openjdk-fips-root:latest)"
    echo "  -c, --no-cache       Build without using Docker cache"
    echo "  -v, --verbose        Enable verbose output"
    echo "  -h, --help           Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Basic build"
    echo "  $0 -n mynetty -t v1.0                # Custom name and tag"
    echo "  $0 -b wolfssl-openjdk-fips-root:custom -v   # Use custom base image with verbose output"
    echo ""
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--name)
            IMAGE_NAME="$2"
            shift 2
            ;;
        -t|--tag)
            TAG="$2"
            shift 2
            ;;
        -b|--base)
            BASE_IMAGE="$2"
            shift 2
            ;;
        -c|--no-cache)
            NO_CACHE=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
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

# Print build configuration
echo -e "${GREEN}=== Netty SSL Tests Build (wolfJSSE FIPS) ===${NC}"
echo -e "${BLUE}Image Name:${NC} ${IMAGE_NAME}:${TAG}"
echo -e "${BLUE}Base Image:${NC} ${BASE_IMAGE}"
echo -e "${BLUE}Build Context:${NC} $(pwd)"
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}Error: Docker is not running or not accessible${NC}"
    exit 1
fi

# Check if base image exists
echo -e "${YELLOW}Checking base image availability...${NC}"
if ! docker image inspect "${BASE_IMAGE}" > /dev/null 2>&1; then
    echo -e "${RED}Error: Base image '${BASE_IMAGE}' not found!${NC}"
    echo -e "${YELLOW}Please build the base wolfSSL OpenJDK FIPS image first:${NC}"
    echo "  cd ../../"
    echo "  ./build.sh -p YOUR_WOLFSSL_PASSWORD --wolfcrypt-jni ./wolfcrypt-jni --wolfssl-jni ./wolfssljni"
    exit 1
fi
echo -e "${GREEN}Base image found${NC}"

# Verify required files exist
echo -e "${YELLOW}Verifying required files...${NC}"
REQUIRED_FILES=(
    "Dockerfile"
    "apply_netty_fips_fixes.sh"
)
MISSING_FILES=()
for file in "${REQUIRED_FILES[@]}"; do
    if [[ ! -e "$file" ]]; then
        MISSING_FILES+=("$file")
    fi
done

if [[ ${#MISSING_FILES[@]} -gt 0 ]]; then
    echo -e "${RED}Error: Missing required files:${NC}"
    for file in "${MISSING_FILES[@]}"; do
        echo "  - $file"
    done
    exit 1
fi
echo -e "${GREEN}All required files found${NC}"

# Build Docker arguments
DOCKER_ARGS=()
if [[ "${NO_CACHE}" == "true" ]]; then
    DOCKER_ARGS+=(--no-cache)
fi
if [[ "${VERBOSE}" == "true" ]]; then
    DOCKER_ARGS+=(--progress=plain)
fi

# Add build args
DOCKER_ARGS+=(--build-arg FIPS_BASE_IMAGE="${BASE_IMAGE}")

echo -e "${YELLOW}Starting Docker build...${NC}"
echo ""

# Build the Docker image
if docker build "${DOCKER_ARGS[@]}" -t "${IMAGE_NAME}:${TAG}" .; then
    echo ""
    echo -e "${GREEN}=== Build Successful ===${NC}"
    echo -e "${GREEN}Image:${NC} ${IMAGE_NAME}:${TAG}"

    # Show image details
    echo ""
    echo -e "${BLUE}Image Details:${NC}"
    docker image inspect "${IMAGE_NAME}:${TAG}" --format "Size: {{.Size}} bytes" 2>/dev/null || true
    docker image inspect "${IMAGE_NAME}:${TAG}" --format "Created: {{.Created}}" 2>/dev/null || true

    echo ""
    echo -e "${YELLOW}=== Usage ===${NC}"
    echo ""
    echo -e "${BLUE}Run all tests:${NC}"
    echo "  docker run --rm ${IMAGE_NAME}:${TAG}"
    echo ""
    echo -e "${BLUE}Test modules:${NC}"
    echo "  - handler: SSL handler tests"
    echo "  - handler-proxy: Proxy handler tests"
    echo "  - testsuite: Integration tests"
    echo ""
    echo -e "${BLUE}Run specific test class:${NC}"
    echo "  docker run --rm ${IMAGE_NAME}:${TAG} ./mvnw -o test -pl handler -Dtest=JdkSslClientContextTest -Dcheckstyle.skip=true -Danimal.sniffer.skip=true"
    echo ""
    echo -e "${BLUE}Run specific module:${NC}"
    echo "  docker run --rm ${IMAGE_NAME}:${TAG} ./mvnw -o test -pl handler -Dcheckstyle.skip=true -Danimal.sniffer.skip=true"
    echo ""
    echo -e "${BLUE}Interactive shell:${NC}"
    echo "  docker run --rm -it ${IMAGE_NAME}:${TAG} bash"
    echo ""

else
    echo ""
    echo -e "${RED}=== Build Failed ===${NC}"
    exit 1
fi