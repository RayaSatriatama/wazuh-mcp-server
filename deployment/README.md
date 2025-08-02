# Wazuh MCP Server Deployment

This folder contains all deployment-related files and configurations for the Wazuh MCP servers.

## Structure

```text
deployment/
├── .env.docker.example     # Docker environment template
├── .env.production.example # Production environment template
├── docker/                 # Docker containers and orchestration
│   ├── Dockerfile          # Production Docker image
│   ├── docker-compose.yml  # Docker Compose for server setup
│   └── nginx.conf         # Nginx reverse proxy configuration
├── requirements-mcp.txt   # Lightweight MCP-specific dependencies
├── start-docker.sh        # Docker startup script (Linux/macOS)
├── start-docker.bat       # Docker startup script (Windows)
└── README.md              # This file
```

## Quick Start

### Development
```bash
# Run individual servers
cd ../wazuh_manager && python server.py
cd ../wazuh_indexer && python server.py
```

### Production with Docker
```bash
# Build and run with Docker Compose
cd docker/
docker-compose up --build
```

### Production Deployment
```bash
# Use the deployment script
./deploy-production.sh
```

## Configuration

1. Copy `.env.production.example` to `.env`
2. Update environment variables for your setup
3. Adjust Docker Compose ports and resource limits as needed
4. Configure Nginx reverse proxy for production load balancing

## Services

- **Wazuh Manager MCP**: Port 8002 (108 tools)
  - FastMCP SSE Endpoint: `http://localhost:8002/mcp`
  - Messages Endpoint: `http://localhost:8002/messages`
- **Wazuh Indexer MCP**: Port 8001 (35 tools)
  - FastMCP SSE Endpoint: `http://localhost:8001/mcp`
  - Messages Endpoint: `http://localhost:8001/messages`
- **Nginx Proxy**: Port 80 (load balancing)

## FastMCP SSE Transport

The MCP servers use FastMCP's Server-Sent Events (SSE) transport, which provides:

### Endpoints
- **FastMCP SSE Endpoint** (`/mcp`): Main endpoint for SSE connections when using `path="/mcp"`
- **Messages Endpoint** (`/messages`): HTTP POST endpoint for client-to-server messages

### Health Checks
The Docker health checks use `curl -f http://localhost:PORT/mcp` to verify FastMCP SSE endpoint availability.

### Client Connection
To connect to the FastMCP SSE servers:
```javascript
// Use SSE transport for remote connections with FastMCP
const transport = new SSEClientTransport(new URL("http://localhost:8001/mcp"));
await client.connect(transport);
```

### Testing Endpoints
Use the provided test script to verify endpoints:
```bash
# Test SSE and messages endpoints
python test_sse_endpoints.py
```

## Troubleshooting

### 307 Temporary Redirect / 404 Not Found
If you see `307 Temporary Redirect` or `404 Not Found` errors in health checks:
- Verify FastMCP SSE endpoint is available at `/mcp` (when using `path="/mcp"`)
- Check that the server is running in SSE mode
- Ensure correct port mapping in docker-compose
- For FastMCP servers, the main SSE endpoint uses the configured path, not `/sse/`

### Connection Refused
For Wazuh connection errors:
- Update `WAZUH_MANAGER_URL` and `WAZUH_INDEXER_URL` in `.env`
- Configure Wazuh credentials properly
- Ensure Wazuh services are running and accessible

## Dependencies

The `requirements-mcp.txt` contains only essential packages for MCP servers:
- FastMCP framework
- Wazuh API clients
- HTTP/auth libraries
- Logging and monitoring

This is much lighter than the main `requirements.txt` for faster container builds. 