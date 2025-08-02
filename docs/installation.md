# Installation Guide

Complete installation instructions for the Wazuh MCP Server.

## 📋 Prerequisites

Before installing the Wazuh MCP Server, ensure you have the following components properly configured:

### System Requirements

- **Operating System**: Linux (Ubuntu 20.04+, CentOS 8+, RHEL 8+) or macOS
- **Memory**: Minimum 4GB RAM (8GB+ recommended)
- **Storage**: 10GB+ free disk space
- **Network**: Internet connectivity for downloading dependencies

### Required Software

#### Docker Environment (Recommended)

```bash
# Docker Engine 20.10+ and Docker Compose 2.0+
sudo apt update
sudo apt install docker.io docker-compose-v2

# Verify installation
docker --version
docker compose version
```

#### Python Environment (Alternative)

```bash
# Python 3.9+ with pip
sudo apt update
sudo apt install python3 python3-pip python3-venv

# Verify installation
python3 --version
pip3 --version
```

### Wazuh Infrastructure

The MCP Server requires access to existing Wazuh components:

#### Wazuh Manager

- **Version**: 4.3.0 or later
- **API Access**: REST API enabled on port 55000
- **Authentication**: Valid API credentials
- **Network**: Accessible from MCP server host

```bash
# Test Wazuh Manager connectivity
curl -k -X GET "https://wazuh-manager:55000/" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

#### Wazuh Indexer (OpenSearch)

- **Version**: Compatible with Wazuh 4.3.0+
- **API Access**: REST API enabled (default port 9200)
- **Authentication**: Valid credentials
- **Indices**: Wazuh data indices present

```bash
# Test Wazuh Indexer connectivity
curl -k -X GET "https://wazuh-indexer:9200/_cluster/health" \
  -u "admin:admin"
```

## 🚀 Installation Methods

### Method 1: Docker Installation (Recommended)

This is the easiest and most reliable installation method.

#### Step 1: Clone Repository

```bash
git clone https://github.com/your-org/wazuh-mcp-server.git
cd wazuh-mcp-server
```

#### Step 2: Configure Environment

```bash
# Copy configuration templates
cp wazuh_indexer/config.env.example wazuh_indexer/.env
cp wazuh_manager/config/.env.example wazuh_manager/.env

# Edit configuration files
nano wazuh_indexer/.env
nano wazuh_manager/.env
```

**Wazuh Indexer Configuration (`wazuh_indexer/.env`):**

```env
# Wazuh Indexer Connection
INDEXER_HOST=your-wazuh-indexer.domain.com
INDEXER_PORT=9200
INDEXER_USERNAME=admin
INDEXER_PASSWORD=your-secure-password
INDEXER_USE_SSL=true
INDEXER_VERIFY_CERTS=false

# MCP Server Configuration
MCP_SERVER_NAME=Wazuh Indexer MCP Server
MCP_SERVER_VERSION=1.0.0
LOG_LEVEL=INFO
```

**Wazuh Manager Configuration (`wazuh_manager/.env`):**

```env
# Wazuh Manager Connection
MANAGER_HOST=your-wazuh-manager.domain.com
MANAGER_PORT=55000
MANAGER_USERNAME=wazuh
MANAGER_PASSWORD=your-api-password
MANAGER_USE_SSL=true
MANAGER_VERIFY_CERTS=false

# MCP Server Configuration
MCP_SERVER_NAME=Wazuh Manager MCP Server
MCP_SERVER_VERSION=1.0.0
LOG_LEVEL=INFO
```

#### Step 3: Deploy with Docker Compose

```bash
# Deploy all services (HTTP + SSE + STDIO)
docker compose up -d

# Deploy specific transport mode
docker compose --profile http up -d
docker compose --profile sse up -d
docker compose --profile stdio up -d

# Verify deployment
docker compose ps
```

#### Step 4: Verify Installation

```bash
# Check service health
curl http://localhost:8001/health
curl http://localhost:8002/health

# Test tool execution
curl -X POST http://localhost:8001/tools/call \
  -H "Content-Type: application/json" \
  -d '{"name": "get_cluster_health", "arguments": {}}'
```

### Method 2: Python Virtual Environment

For development or custom deployments without Docker.

#### Step 1: Setup Python Environment

```bash
# Clone repository
git clone https://github.com/your-org/wazuh-mcp-server.git
cd wazuh-mcp-server

# Create virtual environment
python3 -m venv mcp-venv
source mcp-venv/bin/activate

# Upgrade pip
pip install --upgrade pip
```

#### Step 2: Install Dependencies

```bash
# Install FastMCP and dependencies
pip install fastmcp==2.11.0
pip install requests elasticsearch python-dotenv
pip install uvicorn[standard] fastapi

# Verify installation
pip list | grep fastmcp
```

#### Step 3: Configure Services

```bash
# Setup configuration files
cp wazuh_indexer/config.env.example wazuh_indexer/.env
cp wazuh_manager/config/.env.example wazuh_manager/.env

# Edit configurations as shown in Docker method
```

#### Step 4: Run Services

```bash
# Terminal 1: Run Wazuh Indexer MCP Server
cd wazuh_indexer
python run_server.py

# Terminal 2: Run Wazuh Manager MCP Server  
cd wazuh_manager
python run_server.py
```

#### Step 5: Verify Installation

```bash
# Check if servers are running
curl http://localhost:8001/health
curl http://localhost:8002/health

# Test basic functionality
curl -X POST http://localhost:8001/tools/call \
  -H "Content-Type: application/json" \
  -d '{"name": "list_indices", "arguments": {}}'
```

### Method 3: System Service Installation

For production deployments with systemd.

#### Step 1: Install as System Service

```bash
# Create service user
sudo useradd -r -s /bin/false wazuh-mcp

# Install to system location
sudo mkdir -p /opt/wazuh-mcp-server
sudo cp -r . /opt/wazuh-mcp-server/
sudo chown -R wazuh-mcp:wazuh-mcp /opt/wazuh-mcp-server
```

#### Step 2: Create Systemd Services

**Indexer Service (`/etc/systemd/system/wazuh-mcp-indexer.service`):**

```ini
[Unit]
Description=Wazuh MCP Indexer Server
After=network.target
Requires=network.target

[Service]
Type=simple
User=wazuh-mcp
Group=wazuh-mcp
WorkingDirectory=/opt/wazuh-mcp-server/wazuh_indexer
ExecStart=/usr/bin/python3 run_server.py
Restart=always
RestartSec=10
Environment=PYTHONPATH=/opt/wazuh-mcp-server

[Install]
WantedBy=multi-user.target
```

**Manager Service (`/etc/systemd/system/wazuh-mcp-manager.service`):**

```ini
[Unit]
Description=Wazuh MCP Manager Server
After=network.target
Requires=network.target

[Service]
Type=simple
User=wazuh-mcp
Group=wazuh-mcp
WorkingDirectory=/opt/wazuh-mcp-server/wazuh_manager
ExecStart=/usr/bin/python3 run_server.py
Restart=always
RestartSec=10
Environment=PYTHONPATH=/opt/wazuh-mcp-server

[Install]
WantedBy=multi-user.target
```

#### Step 3: Enable and Start Services

```bash
# Reload systemd configuration
sudo systemctl daemon-reload

# Enable services
sudo systemctl enable wazuh-mcp-indexer
sudo systemctl enable wazuh-mcp-manager

# Start services
sudo systemctl start wazuh-mcp-indexer
sudo systemctl start wazuh-mcp-manager

# Check status
sudo systemctl status wazuh-mcp-indexer
sudo systemctl status wazuh-mcp-manager
```

## 🔧 Configuration Details

### Environment Variables

**Common Variables:**

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `LOG_LEVEL` | Logging level | `INFO` | No |
| `MCP_SERVER_NAME` | Server identifier | Service name | No |
| `MCP_SERVER_VERSION` | Server version | `1.0.0` | No |

**Indexer-Specific Variables:**

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `INDEXER_HOST` | Indexer hostname/IP | `localhost` | Yes |
| `INDEXER_PORT` | Indexer port | `9200` | No |
| `INDEXER_USERNAME` | Authentication username | `admin` | Yes |
| `INDEXER_PASSWORD` | Authentication password | - | Yes |
| `INDEXER_USE_SSL` | Enable SSL/TLS | `true` | No |
| `INDEXER_VERIFY_CERTS` | Verify SSL certificates | `false` | No |

**Manager-Specific Variables:**

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `MANAGER_HOST` | Manager hostname/IP | `localhost` | Yes |
| `MANAGER_PORT` | Manager API port | `55000` | No |
| `MANAGER_USERNAME` | API username | `wazuh` | Yes |
| `MANAGER_PASSWORD` | API password | - | Yes |
| `MANAGER_USE_SSL` | Enable SSL/TLS | `true` | No |
| `MANAGER_VERIFY_CERTS` | Verify SSL certificates | `false` | No |

### Port Configuration

**Default Ports:**

| Service | HTTP | SSE | STDIO |
|---------|------|-----|-------|
| Indexer | 8001 | 8003 | N/A |
| Manager | 8002 | 8004 | N/A |

**Custom Ports:**

```env
# Custom port configuration
HTTP_PORT=9001
SSE_PORT=9003
```

### SSL/TLS Configuration

For production deployments, enable SSL/TLS:

```env
# Enable SSL
USE_SSL=true
SSL_CERT_PATH=/path/to/certificate.pem
SSL_KEY_PATH=/path/to/private-key.pem
SSL_CA_PATH=/path/to/ca-bundle.pem
```

## 🔍 Post-Installation Verification

### Health Checks

```bash
# Basic health check
curl http://localhost:8001/health
curl http://localhost:8002/health

# Detailed health with cluster info
curl "http://localhost:8001/tools/call" \
  -H "Content-Type: application/json" \
  -d '{"name": "get_cluster_health", "arguments": {}}'
```

### Tool Verification

```bash
# List available tools
curl http://localhost:8001/tools/list
curl http://localhost:8002/tools/list

# Test indexer tools
curl -X POST http://localhost:8001/tools/call \
  -H "Content-Type: application/json" \
  -d '{"name": "list_indices", "arguments": {}}'

# Test manager tools
curl -X POST http://localhost:8002/tools/call \
  -H "Content-Type: application/json" \
  -d '{"name": "get_agents", "arguments": {"limit": 5}}'
```

### Log Verification

```bash
# Check Docker logs
docker compose logs wazuh-indexer-http
docker compose logs wazuh-manager-http

# Check system service logs
sudo journalctl -u wazuh-mcp-indexer -f
sudo journalctl -u wazuh-mcp-manager -f

# Check application logs
tail -f wazuh_indexer/logs/mcp_server.log
tail -f wazuh_manager/logs/mcp_server.log
```

## 🔄 Updating

### Docker Update

```bash
# Pull latest images
docker compose pull

# Restart services
docker compose down
docker compose up -d
```

### Manual Update

```bash
# Backup configuration
cp wazuh_indexer/.env wazuh_indexer/.env.backup
cp wazuh_manager/.env wazuh_manager/.env.backup

# Pull updates
git pull origin main

# Reinstall dependencies
pip install --upgrade -r requirements.txt

# Restart services
sudo systemctl restart wazuh-mcp-indexer
sudo systemctl restart wazuh-mcp-manager
```

## 🗑️ Uninstallation

### Docker Cleanup

```bash
# Stop and remove containers
docker compose down

# Remove images
docker rmi $(docker images | grep wazuh-mcp | awk '{print $3}')

# Remove volumes (optional)
docker volume prune
```

### System Service Cleanup

```bash
# Stop services
sudo systemctl stop wazuh-mcp-indexer
sudo systemctl stop wazuh-mcp-manager

# Disable services
sudo systemctl disable wazuh-mcp-indexer
sudo systemctl disable wazuh-mcp-manager

# Remove service files
sudo rm /etc/systemd/system/wazuh-mcp-*.service
sudo systemctl daemon-reload

# Remove installation
sudo rm -rf /opt/wazuh-mcp-server
sudo userdel wazuh-mcp
```

## 🆘 Installation Troubleshooting

### Common Issues

**Connection Refused:**

```bash
# Check if services are running
docker compose ps
sudo systemctl status wazuh-mcp-*

# Check port availability
netstat -tlnp | grep 800[1-4]
```

**Authentication Errors:**

```bash
# Verify Wazuh credentials
curl -k "https://your-wazuh-manager:55000/" \
  -u "username:password"

curl -k "https://your-wazuh-indexer:9200/_cluster/health" \
  -u "username:password"
```

**SSL/TLS Issues:**

```bash
# Test without SSL verification
curl -k https://your-wazuh-service:port/

# Check certificate validity
openssl s_client -connect your-wazuh-service:port
```

For additional troubleshooting, see the [Troubleshooting Guide](./troubleshooting.md).
