#!/bin/bash

# File: test-docker-local.sh
# Location: /KeiroGenesis.API/test-docker-local.sh
# Purpose: Test Docker build and run locally before pushing to Azure

set -e

echo "🐳 KeiroGenesis API - Docker Build & Test Script"
echo "=================================================="
echo ""

# Configuration
IMAGE_NAME="keirogenesis-api"
CONTAINER_NAME="keirogenesis-api-test"
PORT="5000"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    print_error "Docker is not running. Please start Docker Desktop."
    exit 1
fi
print_success "Docker is running"

# Clean up any existing container
if [ "$(docker ps -aq -f name=$CONTAINER_NAME)" ]; then
    print_info "Removing existing container..."
    docker rm -f $CONTAINER_NAME > /dev/null 2>&1
    print_success "Old container removed"
fi

# Remove old image if exists
if [ "$(docker images -q $IMAGE_NAME:test)" ]; then
    print_info "Removing old image..."
    docker rmi -f $IMAGE_NAME:test > /dev/null 2>&1
    print_success "Old image removed"
fi

# Build the Docker image
echo ""
print_info "Building Docker image..."
if docker build -t $IMAGE_NAME:test -f Dockerfile .; then
    print_success "Docker image built successfully"
else
    print_error "Docker build failed"
    exit 1
fi

# Get image size
IMAGE_SIZE=$(docker images $IMAGE_NAME:test --format "{{.Size}}")
print_info "Image size: $IMAGE_SIZE"

# Run the container
echo ""
print_info "Starting container on port $PORT..."

docker run -d \
    --name $CONTAINER_NAME \
    -p $PORT:8080 \
    -e ASPNETCORE_ENVIRONMENT=Development \
    -e DatabaseSettings__Host=host.docker.internal \
    -e DatabaseSettings__Port=1433 \
    -e DatabaseSettings__Database=kg-dev-db \
    -e DatabaseSettings__Username=app_keiro \
    -e DatabaseSettings__Password=100Strong\(\!\)P@ssword \
    -e DatabaseSettings__TrustServerCertificate=true \
    -e DatabaseSettings__Encrypt=true \
    -e ConnectionStrings__Redis=host.docker.internal:6379 \
    -e Auth__Issuer=KeiroGenesis \
    -e Auth__Audience=KeiroGenesisClients \
    -e Auth__AccessTokenMinutes=15 \
    -e Auth__RefreshTokenDays=7 \
    -e AllowedOrigins__0=http://localhost:3000 \
    -e AllowedOrigins__1=http://localhost:5173 \
    $IMAGE_NAME:test

if [ $? -eq 0 ]; then
    print_success "Container started"
else
    print_error "Failed to start container"
    exit 1
fi

# Wait for container to be healthy
echo ""
print_info "Waiting for container to be healthy..."
sleep 5

# Check container status
CONTAINER_STATUS=$(docker inspect -f '{{.State.Status}}' $CONTAINER_NAME)
if [ "$CONTAINER_STATUS" != "running" ]; then
    print_error "Container is not running. Status: $CONTAINER_STATUS"
    echo ""
    echo "Container logs:"
    docker logs $CONTAINER_NAME
    exit 1
fi
print_success "Container is running"

# Test health endpoint
echo ""
print_info "Testing health endpoint..."
sleep 3

if curl -f -s http://localhost:$PORT/health > /dev/null; then
    print_success "Health check passed!"
    echo ""
    echo "Health response:"
    curl -s http://localhost:$PORT/health | jq '.' 2>/dev/null || curl -s http://localhost:$PORT/health
else
    print_error "Health check failed"
    echo ""
    echo "Container logs:"
    docker logs $CONTAINER_NAME
    exit 1
fi

# Test root endpoint
echo ""
print_info "Testing root endpoint..."
if curl -f -s http://localhost:$PORT/ > /dev/null; then
    print_success "Root endpoint responded"
    echo ""
    echo "Root response:"
    curl -s http://localhost:$PORT/ | jq '.' 2>/dev/null || curl -s http://localhost:$PORT/
else
    print_error "Root endpoint failed"
fi

# Show container info
echo ""
echo "=================================================="
print_success "Docker container is running successfully!"
echo "=================================================="
echo ""
echo "Container Details:"
echo "  Name:        $CONTAINER_NAME"
echo "  Image:       $IMAGE_NAME:test"
echo "  Port:        http://localhost:$PORT"
echo "  Status:      $(docker inspect -f '{{.State.Status}}' $CONTAINER_NAME)"
echo ""
echo "Useful Commands:"
echo "  View logs:        docker logs $CONTAINER_NAME"
echo "  Follow logs:      docker logs -f $CONTAINER_NAME"
echo "  Stop container:   docker stop $CONTAINER_NAME"
echo "  Remove container: docker rm -f $CONTAINER_NAME"
echo "  Enter container:  docker exec -it $CONTAINER_NAME /bin/bash"
echo ""
echo "Test Endpoints:"
echo "  Health:      curl http://localhost:$PORT/health"
echo "  Root:        curl http://localhost:$PORT/"
echo "  Swagger:     http://localhost:$PORT/swagger (if enabled)"
echo ""
echo "When ready to deploy to Azure DevOps, push your code:"
echo "  git add ."
echo "  git commit -m 'Docker configuration ready'"
echo "  git push azure main"
echo ""

# Ask if user wants to keep container running
read -p "Keep container running? (y/n) [y]: " KEEP_RUNNING
KEEP_RUNNING=${KEEP_RUNNING:-y}

if [[ ! $KEEP_RUNNING =~ ^[Yy]$ ]]; then
    print_info "Stopping and removing container..."
    docker stop $CONTAINER_NAME > /dev/null 2>&1
    docker rm $CONTAINER_NAME > /dev/null 2>&1
    print_success "Container cleaned up"
else
    print_success "Container is still running at http://localhost:$PORT"
fi

echo ""
print_success "Docker test completed!"