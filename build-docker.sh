#!/bin/bash

# Get the latest git tag (e.g., v1.0)
LATEST_TAG=$(git describe --tags --abbrev=0)

# Check if we found a tag
if [ -z "$LATEST_TAG" ]; then
    echo "Error: No git tags found."
    exit 1
fi

# Extract "v1.0" part
BASE_VERSION=$(echo "$LATEST_TAG" | sed 's/^v//')

# Get current date in YYYYMMDD format
BUILD_DATE=$(date +%Y%m%d)

# Construct the full version string: v1.0.20231027
APP_VERSION="${BASE_VERSION}.${BUILD_DATE}"

# Define Docker image tag
IMAGE_TAG="${APP_VERSION}"
IMAGE_NAME="static-webserver-with-auth"

echo "Building image: ${IMAGE_NAME}:${IMAGE_TAG}"

# Build and push (comment out 'docker push' if you don't need to push yet)
docker build --build-arg APP_VERSION="${APP_VERSION}" -t "${IMAGE_NAME}:${IMAGE_TAG}" .
# docker push "${IMAGE_NAME}:${IMAGE_TAG}"