#!/bin/bash

# Wazuh MCP Server - Quick Docker Deployment Script
# This script will start both Wazuh MCP servers using Docker Compose

set -e

echo "🚀 Starting Wazuh MCP Server Docker Deployment..."
echo "=================================================="

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "📁 Project Root: $PROJECT_ROOT"

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed or not in PATH"
    echo "Please install Docker and Docker Compose first"
    exit 1
fi

# Check if Docker Compose is available
if ! docker compose version &> /dev/null; then
    echo "❌ Docker Compose is not available"
    echo "Please install Docker Compose"
    exit 1
fi

# Navigate to deployment directory
DOCKER_DIR="$PROJECT_ROOT/deployment/docker"

if [ ! -f "$DOCKER_DIR/docker-compose.yml" ]; then
    echo "❌ Docker Compose file not found at: $DOCKER_DIR/docker-compose.yml"
    exit 1
fi

echo "📦 Docker Compose file found"
echo "🔧 Starting containers..."

# Change to docker directory
cd "$DOCKER_DIR"

# Stop any existing containers
echo "🛑 Stopping existing containers..."
docker compose down --remove-orphans || true

# Start containers
echo "▶️  Starting Wazuh MCP servers..."
docker compose up -d

# Wait for containers to be ready
echo "⏳ Waiting for containers to start..."
sleep 5

# Check container status
echo "📊 Container Status:"
docker compose ps

# Show logs
echo ""
echo "📝 Recent logs:"
echo "==============="
docker compose logs --tail=10

echo ""
echo "✅ Deployment completed!"
echo ""
echo "🌐 MCP Server Endpoints:"
echo "  - Wazuh Indexer HTTP: http://localhost:8001/mcp"
echo "  - Wazuh Manager HTTP: http://localhost:8002/mcp"
echo "  - Wazuh Indexer SSE:  http://localhost:8001/sse"
echo "  - Wazuh Manager SSE:  http://localhost:8002/sse"
echo ""
echo "🔍 To view logs: docker compose -f $DOCKER_DIR/docker-compose.yml logs -f"
echo "🛑 To stop: docker compose -f $DOCKER_DIR/docker-compose.yml down"
echo ""
echo "📋 Copy the following to your Cursor/Claude Desktop MCP config:"
echo ""
echo '{
  "mcpServers": {
    "wazuh_indexer": {
      "url": "http://localhost:8001/mcp"
    },
    "wazuh_manager": {
      "url": "http://localhost:8002/mcp"
    }
  }
}'
