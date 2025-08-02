# Transport Modes Guide

The Wazuh MCP Server supports three transport modes to accommodate different use cases and integration scenarios.

## 🚀 Overview

| Transport | Port | Use Case | Protocol | Client Type |
|-----------|------|----------|----------|-------------|
| **HTTP** | 8001/8002 | Production APIs | HTTP/REST | Web apps, scripts |
| **SSE** | 8003/8004 | Real-time events | Server-Sent Events | Dashboards, monitoring |
| **STDIO** | - | MCP integration | Standard I/O | Cursor, Claude Desktop |

## 🌐 HTTP Mode

### Description
RESTful API endpoints for standard HTTP communication. Best for production integrations and web applications.

### Features
- REST API endpoints
- JSON request/response
- HTTP status codes
- Standard authentication
- OpenAPI documentation

### Usage

**Start HTTP servers:**
```bash
docker compose --profile http up -d
```

**Available endpoints:**
- **Indexer**: `http://localhost:8001`
- **Manager**: `http://localhost:8002`

**Example API call:**
```bash
curl -X POST http://localhost:8002/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "get_agents",
    "arguments": {"limit": 10}
  }'
```

**Health check:**
```bash
curl http://localhost:8001/health
curl http://localhost:8002/health
```

### Integration Examples

**Python requests:**
```python
import requests

response = requests.post(
    "http://localhost:8002/tools/call",
    json={
        "name": "get_agents",
        "arguments": {}
    }
)
print(response.json())
```

**JavaScript fetch:**
```javascript
const response = await fetch('http://localhost:8002/tools/call', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
    },
    body: JSON.stringify({
        name: 'get_agents',
        arguments: {}
    })
});
const data = await response.json();
console.log(data);
```

## ⚡ SSE Mode (Server-Sent Events)

### Description
Real-time event streaming using Server-Sent Events protocol. Ideal for live dashboards and monitoring applications.

### Features
- Real-time data streaming
- Automatic reconnection
- Event-based communication
- Low latency updates
- Browser-compatible

### Usage

**Start SSE servers:**
```bash
docker compose --profile sse up -d
```

**Available endpoints:**
- **Indexer SSE**: `http://localhost:8003/sse/`
- **Manager SSE**: `http://localhost:8004/sse/`

**Test SSE connection:**
```bash
curl -N http://localhost:8003/sse/
```

### Integration Examples

**JavaScript EventSource:**
```javascript
const eventSource = new EventSource('http://localhost:8003/sse/');

eventSource.onmessage = function(event) {
    const data = JSON.parse(event.data);
    console.log('Received:', data);
};

eventSource.onerror = function(event) {
    console.error('SSE error:', event);
};
```

**Python SSE client:**
```python
import sseclient
import requests

def handle_events():
    response = requests.get('http://localhost:8003/sse/', stream=True)
    client = sseclient.SSEClient(response)
    
    for event in client.events():
        print(f"Event: {event.event}")
        print(f"Data: {event.data}")
```

## 📡 STDIO Mode

### Description
Standard Input/Output communication for MCP (Model Context Protocol) clients like Cursor and Claude Desktop.

### Features
- MCP protocol compatibility
- Process-based communication
- Direct integration with AI assistants
- No network ports required
- Secure local communication

### Usage

**Start STDIO servers:**
```bash
docker compose --profile stdio up --no-deps
```

**Test STDIO manually:**
```bash
# Test indexer
docker exec -i wazuh-indexer-mcp-stdio python -m wazuh_indexer.server

# Test manager
docker exec -i wazuh-manager-mcp-stdio python -m wazuh_manager.server
```

### MCP Client Configuration

**Cursor Configuration (`mcp_config.json`):**
```json
{
  "mcpServers": {
    "wazuh-indexer": {
      "command": "docker",
      "args": ["exec", "-i", "wazuh-indexer-mcp-stdio", "python", "-m", "wazuh_indexer.server"]
    },
    "wazuh-manager": {
      "command": "docker",
      "args": ["exec", "-i", "wazuh-manager-mcp-stdio", "python", "-m", "wazuh_manager.server"]
    }
  }
}
```

**Claude Desktop Configuration:**
```json
{
  "mcpServers": {
    "wazuh": {
      "command": "docker",
      "args": ["exec", "-i", "wazuh-manager-mcp-stdio", "python", "-m", "wazuh_manager.server"]
    }
  }
}
```

## 🔄 Multi-Mode Deployment

### Running All Modes Simultaneously

```bash
# Start all transport modes
docker compose --profile http --profile sse --profile stdio up -d
```

This provides:
- HTTP APIs on ports 8001/8002
- SSE streams on ports 8003/8004
- STDIO containers for MCP integration

### Use Case Examples

**Development Environment:**
```bash
# HTTP for testing, STDIO for development
docker compose --profile http --profile stdio up -d
```

**Production Environment:**
```bash
# HTTP for API, SSE for monitoring
docker compose --profile http --profile sse up -d
```

**Full Deployment:**
```bash
# All modes for maximum flexibility
docker compose --profile http --profile sse --profile stdio up -d
```

## 🔧 Transport-Specific Configuration

### HTTP Mode Configuration

```yaml
environment:
  - MCP_TRANSPORT=http
  - HTTP_HOST=0.0.0.0
  - HTTP_PORT=8001
  - CORS_ALLOWED_ORIGINS=*
```

### SSE Mode Configuration

```yaml
environment:
  - MCP_TRANSPORT=sse
  - SSE_HOST=0.0.0.0
  - SSE_PORT=8003
  - SSE_RECONNECT_INTERVAL=5
```

### STDIO Mode Configuration

```yaml
environment:
  - MCP_TRANSPORT=stdio
  - STDIO_TIMEOUT=30
```

## 📊 Performance Comparison

| Transport | Latency | Throughput | Resource Usage | Complexity |
|-----------|---------|------------|----------------|------------|
| HTTP | Medium | High | Medium | Low |
| SSE | Low | Medium | Medium | Medium |
| STDIO | Very Low | Low | Low | High |

## 🔒 Security Considerations

### HTTP Mode Security

- Use HTTPS in production
- Implement API authentication
- Rate limiting and CORS
- Input validation

```yaml
environment:
  - HTTPS_ENABLED=true
  - SSL_CERT_PATH=/certs/cert.pem
  - SSL_KEY_PATH=/certs/key.pem
```

### SSE Mode Security

- WebSocket security headers
- Origin validation
- Connection limits

```yaml
environment:
  - SSE_ALLOWED_ORIGINS=https://your-dashboard.com
  - SSE_MAX_CONNECTIONS=100
```

### STDIO Mode Security

- Process isolation
- Local-only access
- No network exposure

## 🚨 Troubleshooting

### HTTP Mode Issues

**Port conflicts:**
```bash
# Check port usage
netstat -tulpn | grep :8001

# Use different port
WAZUH_INDEXER_MCP_PORT=8011 docker compose --profile http up -d
```

**CORS errors:**
```yaml
environment:
  - CORS_ALLOWED_ORIGINS=http://localhost:3000,https://your-app.com
```

### SSE Mode Issues

**Connection drops:**
```yaml
environment:
  - SSE_KEEPALIVE_INTERVAL=30
  - SSE_CONNECTION_TIMEOUT=300
```

**Browser compatibility:**
```javascript
// Check EventSource support
if (typeof EventSource !== 'undefined') {
    // Use SSE
} else {
    // Fallback to polling
}
```

### STDIO Mode Issues

**Container not responding:**
```bash
# Check container status
docker ps --filter "name=stdio"

# Test manually
docker exec -it wazuh-indexer-mcp-stdio python -m wazuh_indexer.server
```

**MCP client configuration:**
```bash
# Verify Docker access
docker exec -i wazuh-indexer-mcp-stdio echo "test"

# Check Python module
docker exec -i wazuh-indexer-mcp-stdio python -c "import wazuh_indexer.server"
```

## 🎯 Best Practices

### Choosing the Right Transport

**Use HTTP when:**
- Building web applications
- Need REST API integration
- Synchronous request/response patterns
- Standard HTTP tooling

**Use SSE when:**
- Need real-time updates
- Building dashboards
- Streaming data requirements
- Event-driven architecture

**Use STDIO when:**
- Integrating with MCP clients
- Using Cursor or Claude Desktop
- Need direct AI assistant integration
- Local development workflow

### Resource Management

```yaml
# Production resource limits
services:
  wazuh-indexer-mcp:
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '0.5'
        reservations:
          memory: 256M
          cpus: '0.25'
```

This completes the transport modes guide. Each mode serves different purposes and can be used independently or together based on your requirements.
