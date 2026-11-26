#!/bin/bash

# Builds the FIPS test application image, which extends the
# wolfssl-openjdk-fips-zulu25-debian13 base image.

set -e

# Default values
IMAGE_NAME="wolfssl-fips-zulu25-basic-test-image"
TAG="latest"
VERBOSE=false
NO_CACHE=false
BASE_IMAGE="wolfssl-openjdk-fips-zulu25-debian13:latest"

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
    echo "Build the wolfSSL OpenJDK FIPS test application Docker image"
    echo ""
    echo "OPTIONS:"
    echo "  -n, --name NAME      Set image name (default: wolfssl-fips-zulu25-basic-test-image)"
    echo "  -t, --tag TAG        Set image tag (default: latest)"
    echo "  -b, --base BASE      Set base image (default: wolfssl-openjdk-fips-zulu25-debian13:latest)"
    echo "  -c, --no-cache       Build without using Docker cache"
    echo "  -v, --verbose        Enable verbose output"
    echo "  -h, --help           Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Basic build"
    echo "  $0 -n mytest -t v1.0                # Custom name and tag"
    echo "  $0 -b wolfssl-openjdk-fips-zulu25-debian13:custom -v   # Use custom base image with verbose output"
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

echo -e "${GREEN}=== wolfSSL OpenJDK FIPS Test Application Build ===${NC}"
echo -e "${BLUE}Image Name:${NC} ${IMAGE_NAME}:${TAG}"
echo -e "${BLUE}Base Image:${NC} ${BASE_IMAGE}"
echo -e "${BLUE}Build Context:${NC} $(pwd)"
echo ""

# Check if base image exists
echo -e "${YELLOW}Checking base image availability...${NC}"
if ! docker image inspect "${BASE_IMAGE}" > /dev/null 2>&1; then
    echo -e "${RED}Error: Base image '${BASE_IMAGE}' not found!${NC}"
    echo -e "${YELLOW}Please build the base wolfSSL OpenJDK FIPS image first:${NC}"
    echo "  cd ../.."
    echo "  ./build.sh -p YOUR_WOLFSSL_PASSWORD"
    exit 1
fi
echo -e "${GREEN}Base image found${NC}"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}Error: Docker is not running or not accessible${NC}"
    exit 1
fi

# Verify source files exist
echo -e "${YELLOW}Verifying source files...${NC}"
if [[ ! -f "src/main/FipsUserApplication.java" ]]; then
    echo -e "${RED}Error: FipsUserApplication.java not found${NC}"
    exit 1
fi
if [[ ! -f "src/main/CryptoTestSuite.java" ]]; then
    echo -e "${RED}Error: CryptoTestSuite.java not found${NC}"
    exit 1
fi
if [[ ! -f "src/main/TlsTestSuite.java" ]]; then
    echo -e "${RED}Error: TlsTestSuite.java not found${NC}"
    exit 1
fi
echo -e "${GREEN}All source files found${NC}"

# Build Docker arguments
DOCKER_ARGS=()
if [[ "${NO_CACHE}" == "true" ]]; then
    DOCKER_ARGS+=(--no-cache)
fi
if [[ "${VERBOSE}" == "true" ]]; then
    DOCKER_ARGS+=(--progress=plain)
fi

DOCKER_ARGS+=(--build-arg BASE_IMAGE="${BASE_IMAGE}")

echo -e "${YELLOW}Starting Docker build...${NC}"
echo ""

if docker build "${DOCKER_ARGS[@]}" -t "${IMAGE_NAME}:${TAG}" .; then
    echo ""
    echo -e "${GREEN}=== Build Successful ===${NC}"
    echo -e "${GREEN}Image:${NC} ${IMAGE_NAME}:${TAG}"

    echo ""
    echo -e "${BLUE}Image Details:${NC}"
    docker image inspect "${IMAGE_NAME}:${TAG}" --format "Size: {{.Size}} bytes"
    docker image inspect "${IMAGE_NAME}:${TAG}" --format "Created: {{.Created}}"

    echo ""
    echo -e "${YELLOW}Test the image with:${NC}"
    echo "  docker run --rm ${IMAGE_NAME}:${TAG}"
    echo ""
    echo -e "${YELLOW}Run individual test suites:${NC}"
    echo "  docker run --rm ${IMAGE_NAME}:${TAG} java CryptoTestSuite"
    echo "  docker run --rm ${IMAGE_NAME}:${TAG} java TlsTestSuite"
    echo ""
    echo -e "${YELLOW}Run with debug logging:${NC}"
    echo "  docker run --rm -e WOLFJCE_DEBUG=true -e WOLFJSSE_DEBUG=true ${IMAGE_NAME}:${TAG}"

else
    echo ""
    echo -e "${RED}=== Build Failed ===${NC}"
    exit 1
fi
