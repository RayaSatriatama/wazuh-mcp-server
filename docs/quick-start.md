# Quick Start Guide

Get your Wazuh MCP Server up and running in 5 minutes!

## 🚀 Prerequisites

Before starting, ensure you have:

- **Wazuh Platform** running (Manager + Indexer)
- **Docker** installed (recommended approach)
- **Network access** to Wazuh services
- **5 minutes** of your time

## 📋 Step 1: Clone the Repository

```bash
git clone https://github.com/RayaSatriatama/wazuh-mcp-server.git
cd wazuh-mcp-server
```

## ⚙️ Step 2: Configure Environment

Copy the example environment file and customize it:

```bash
cd deployment/docker
cp .env.example .env
```

Edit the `.env` file with your Wazuh credentials:

```env
# Wazuh Indexer Configuration
WAZUH_INDEXER_HOST=your-wazuh-indexer-host
WAZUH_INDEXER_PORT=9200
WAZUH_INDEXER_USERNAME=admin
WAZUH_INDEXER_PASSWORD=your-password

# Wazuh Manager Configuration
WAZUH_MANAGER_HOST=your-wazuh-manager-host
WAZUH_MANAGER_PORT=55000
WAZUH_MANAGER_USERNAME=wazuh
WAZUH_MANAGER_PASSWORD=your-password

# MCP Server Ports
WAZUH_INDEXER_MCP_PORT=8001
WAZUH_MANAGER_MCP_PORT=8002
```

## 🐳 Step 3: Deploy with Docker

Start the MCP servers in HTTP mode:

```bash
docker compose --profile http up -d
```

This will start:
- **Wazuh Indexer MCP Server** on port `8001`
- **Wazuh Manager MCP Server** on port `8002`

## ✅ Step 4: Verify Deployment

Test that both servers are healthy:

```bash
# Test Indexer MCP Server
curl http://localhost:8001/health

# Test Manager MCP Server
curl http://localhost:8002/health
```

Expected response:
```json
{
  "status": "healthy",
  "server_name": "Wazuh Indexer MCP Server",
  "cluster_status": "green"
}
```

## 🎯 Step 5: Test Basic Functionality

Try a simple API call to list Wazuh agents:

```bash
curl -X POST http://localhost:8002/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "get_agents",
    "arguments": {}
  }'
```

## 🔧 Alternative: Development Setup

If you prefer to run without Docker:

```bash
# Install dependencies
pip install -r deployment/requirements-mcp.txt

# Set environment variables
export WAZUH_INDEXER_HOST=your-host
export WAZUH_MANAGER_HOST=your-host
# ... other variables

# Option 1: Use server manager (recommended)
python -m src.wazuh_mcp_server.server_manager start-all

# Option 2: Run servers individually
python -m src.wazuh_mcp_server.wazuh_indexer.server --port 8001 &
python -m src.wazuh_mcp_server.wazuh_manager.server --port 8002 &

# Check server status
python -m src.wazuh_mcp_server.server_manager status

# Stop all servers
python -m src.wazuh_mcp_server.server_manager stop-all
```

## 🎉 Success!

Your Wazuh MCP Server is now running! You can:

- **Use HTTP API**: Access REST endpoints on ports 8001/8002
- **Integrate with MCP clients**: Configure Cursor, Claude Desktop, etc.
- **Monitor security data**: Query alerts, agents, and events

## 🔗 Next Steps

- [Configure MCP Clients](./mcp-client-integration.md)
- [Explore API Reference](./api-reference.md)
- [Learn about Transport Modes](./transport-modes.md)
- [Troubleshoot Issues](./troubleshooting.md)

## 🆘 Need Help?

If something isn't working:

1. Check [Troubleshooting Guide](./troubleshooting.md)
2. Verify your Wazuh credentials
3. Ensure network connectivity to Wazuh services
4. Check container logs: `docker compose logs`

Happy monitoring! 🛡️
