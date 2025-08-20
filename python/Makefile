# root-io-python/Makefile

IMAGE_NAME := root-io-python
TAG := latest
DOCKERFILE_PROVIDER := Dockerfile.provider
DOCKERFILE_OSP := Dockerfile.osp

build-provider:
	@echo "Building Docker image using $(DOCKERFILE_PROVIDER)..."
	export DOCKER_BUILDKIT=1; docker build --secret id=wolfssl_password,src=password.txt -t $(IMAGE_NAME)-provider:$(TAG) -f $(DOCKERFILE_PROVIDER) .

build-osp:
	@echo "Building Docker image using $(DOCKERFILE_OSP)..."
	export DOCKER_BUILDKIT=1; docker build --secret id=wolfssl_password,src=password.txt -t $(IMAGE_NAME)-osp:$(TAG) -f $(DOCKERFILE_OSP) .

run-provider: build-provider
	@echo "Running Docker container..."
	docker run --rm -it $(IMAGE_NAME)-provider:$(TAG) sh

run-osp: build-osp
	@echo "Running Docker container..."
	docker run --rm -it $(IMAGE_NAME)-osp:$(TAG) sh

clean:
	@echo "Cleaning up Docker images..."
	docker rmi $(IMAGE_NAME)-provider:$(TAG) 2>/dev/null || true
	docker rmi $(IMAGE_NAME)-osp:$(TAG) 2>/dev/null || true
