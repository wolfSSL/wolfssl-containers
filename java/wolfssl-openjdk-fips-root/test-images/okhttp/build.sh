#!/bin/bash
#
# Build the OkHttp wolfJSSE FIPS test image
#
# Prerequisites:
#   - wolfssl-openjdk-fips-root:latest base image must be built first
#
# Usage:
#   ./build.sh [--no-cache]
#
# Options:
#   --no-cache    Build without using Docker cache (clean build)
#

set -e

# Enable BuildKit (required for heredoc syntax in Dockerfile)
export DOCKER_BUILDKIT=1

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

IMAGE_NAME="okhttp-wolfjsse-fips"
IMAGE_TAG="latest"

# Parse command line arguments
NO_CACHE=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --no-cache)
            NO_CACHE="--no-cache"
            echo "Note: Building without cache"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--no-cache]"
            exit 1
            ;;
    esac
done

echo "=== Building OkHttp wolfJSSE FIPS Test Image ==="
echo ""

# Check if Docker is available
if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: Docker is not installed or not in PATH"
    exit 1
fi

# Check if Dockerfile exists
if [ ! -f "Dockerfile" ]; then
    echo "ERROR: Dockerfile not found in current directory"
    exit 1
fi

# Check if base image exists
if ! docker image inspect wolfssl-openjdk-fips-root:latest >/dev/null 2>&1; then
    echo "ERROR: Base image wolfssl-openjdk-fips-root:latest not found"
    echo ""
    echo "Please build the base image first:"
    echo "  cd ../../"  # Relative path to wolfssl-openjdk-fips-root
    echo "  ./build.sh (or appropriate build command)"
    exit 1
fi

echo "Base image found: wolfssl-openjdk-fips-root:latest"
echo ""

# Build the image
echo "Building Docker image..."
docker build \
    ${NO_CACHE} \
    -t "${IMAGE_NAME}:${IMAGE_TAG}" \
    -f Dockerfile \
    . || {
    echo ""
    echo "ERROR: Docker build failed"
    exit 1
}

echo ""
echo "=============================================="
echo "  Build Complete!"
echo "=============================================="
echo ""
echo "Run SSL tests:"
echo "  docker run --rm ${IMAGE_NAME}:${IMAGE_TAG}"
echo ""
echo "Run with reports volume:"
echo "  docker run --rm -v \$(pwd)/reports:/reports ${IMAGE_NAME}:${IMAGE_TAG}"
echo ""
echo "Interactive shell:"
echo "  docker run --rm -it ${IMAGE_NAME}:${IMAGE_TAG} bash"
echo ""