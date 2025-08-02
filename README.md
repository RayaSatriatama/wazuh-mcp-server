# Wazuh MCP Server

Model Context Protocol (MCP) servers for Wazuh services, providing seamless integration between Wazuh security platform and AI applications through the MCP framework.

## 🚀 Quick Start

Get started in 5 minutes with our comprehensive documentation:

- **[📚 Documentation Overview](./docs/README.md)** - Start here for complete guide
- **[⚡ Quick Start Guide](./docs/quick-start.md)** - 5-minute setup
- **[🐳 Docker Deployment](./docs/docker-deployment.md)** - Production deployment
- **[📖 API Reference](./docs/api-reference.md)** - Complete API documentation
- **[🔧 Configuration Guide](./docs/configuration.md)** - Configuration reference
- **[🛠️ Tools Reference](./docs/tools-reference.md)** - All available tools
- **[📋 Installation Guide](./docs/installation.md)** - Detailed installation
- **[🔍 Troubleshooting](./docs/troubleshooting.md)** - Common issues and solutions

## 📁 Project Structure

```
wazuh-mcp-server/
├── src/                    # Source code package
│   └── wazuh_mcp_server/   # Main application package
│       ├── wazuh_indexer/  # Wazuh Indexer MCP Server
│       │   ├── config/     # Configuration modules
│       │   │   ├── base_config.py
│       │   │   └── indexer_config.py
│       │   ├── services/   # Service implementations
│       │   │   └── indexer_service.py
│       │   ├── utils/      # Utilities
│       │   │   └── logger.py
│       │   ├── tools/      # MCP tools
│       │   │   ├── cluster_tools.py
│       │   │   ├── index_tools.py
│       │   │   ├── monitoring_tools.py
│       │   │   ├── search_tools.py
│       │   │   ├── security_tools.py
│       │   │   └── tool_clients.py
│       │   └── server.py   # Main server entry point
│       ├── wazuh_manager/  # Wazuh Manager MCP Server
│       │   ├── config/     # Configuration modules
│       │   │   ├── base_config.py
│       │   │   └── manager_config.py
│       │   ├── services/   # Service implementations
│       │   │   └── manager_service.py
│       │   ├── utils/      # Utilities
│       │   │   └── logger.py
│       │   ├── tools/      # MCP tools
│       │   │   ├── agents.py
│       │   │   ├── api_info.py
│       │   │   ├── cluster.py
│       │   │   ├── decoders.py
│       │   │   ├── experimental.py
│       │   │   ├── groups.py
│       │   │   ├── lists.py
│       │   │   ├── manager.py
│       │   │   ├── mitre.py
│       │   │   ├── overview.py
│       │   │   ├── rootcheck.py
│       │   │   ├── rules.py
│       │   │   ├── sca.py
│       │   │   ├── security.py
│       │   │   ├── syscollector.py
│       │   │   ├── syscheck.py
│       │   │   ├── tasks.py
│       │   │   └── wazuh_manager_base_api.py
│       │   └── server.py   # Main server entry point
│       ├── server_manager.py  # Server management CLI
│       └── __init__.py     # Package initialization
├── deployment/             # Docker deployment
│   ├── .env.docker.example      # Docker environment template
│   ├── .env.production.example  # Production environment template
│   ├── docker/
│   │   ├── docker-compose.yml
│   │   ├── Dockerfile
│   │   └── nginx.conf
│   ├── requirements-mcp.txt     # Python dependencies
│   └── README.md               # Deployment documentation
├── docs/                   # Documentation
├── tests/                  # Test suite
├── .env.example            # Environment configuration template
├── pyproject.toml          # Modern Python package configuration
├── SECURITY.md             # Security policy
├── CHANGELOG.md            # Version history
└── README.md               # Project documentation
```

## Features

- **Self-Contained**: Each MCP server has its own complete module structure
- **Modular Architecture**: Clean separation of concerns within each server
- **Docker Ready**: Deployable via Docker Compose
- **Warning Suppression**: Deprecation and runtime warnings are filtered
- **Local Imports**: All imports are relative to prevent external dependencies
- **Clean Logging**: Production-ready log output with reduced verbosity

## Logging

The MCP servers use structured logging with the following levels:

- **ERROR**: Authentication failures, connection errors, critical issues
- **WARNING**: JWT expiration, recoverable issues, deprecated usage
- **INFO**: Startup messages, connection success, tool registration summaries
- **DEBUG**: Data fetching operations, detailed API interactions (disabled by default)

### Log Output Examples

```text
✅ Successfully connected to Wazuh API
✅ Successfully imported and registered 106 Wazuh Manager tools from 18 modules
✅ Successfully imported and registered 36 Wazuh Indexer tools from 5 modules
```

Verbose debug logging (API requests, data fetching operations) has been moved to DEBUG level to reduce log noise while maintaining troubleshooting capabilities when needed.

## Architecture Changes

### Tool Migration

The tools have been restructured for better organization:

- Wazuh Indexer tools are located in `wazuh_indexer/tools/`
- Wazuh Manager tools are located in `wazuh_manager/tools/`

### Import Cleanup

- Removed external imports: `from utils.logger import logger`
- Removed external imports: `from config.wazuh_config import WazuhConfig`
- Removed configuration instantiation: `config = WazuhConfig()`
- Updated to use centralized service instances set by servers

### Service Integration

Each MCP server now:

1. Creates its own service instance (WazuhIndexerMCPService/WazuhManagerMCPService)
2. Patches tool clients to use the centralized service
3. Imports and registers tools using relative imports
4. Handles all configuration through environment variables

## ⚡ Quick Installation

```bash
# 1. Clone repository
git clone https://github.com/RayaSatriatama/wazuh-mcp-server.git
cd wazuh-mcp-server

# 2. Deploy with Docker (recommended)
docker compose --profile http up -d

# 3. Verify deployment
curl http://localhost:8001/health  # Indexer
curl http://localhost:8002/health  # Manager
```

For detailed installation instructions, see the **[Installation Guide](./docs/installation.md)**.

## 🎛️ Server Management

Use the built-in server manager for easy development and testing:

```bash
# Start all MCP servers
uvx --from fastmcp python -m src.wazuh_mcp_server.server_manager start-all

# Check server status  
uvx --from fastmcp python -m src.wazuh_mcp_server.server_manager status

# Stop all servers
uvx --from fastmcp python -m src.wazuh_mcp_server.server_manager stop-all

# Start individual servers
uvx --from fastmcp python -m src.wazuh_mcp_server.server_manager start wazuh_indexer
uvx --from fastmcp python -m src.wazuh_mcp_server.server_manager start wazuh_manager
```

## 🏗️ Architecture

The Wazuh MCP Server provides two main services:

- **Wazuh Indexer MCP Server** (Port 8001) - Search, alerts, analytics
- **Wazuh Manager MCP Server** (Port 8002) - Agents, rules, management

### 🚀 Transport Modes

- **HTTP Mode** - Production REST API (ports 8001/8002)
- **SSE Mode** - Real-time Server-Sent Events (ports 8003/8004)  
- **STDIO Mode** - Direct MCP client integration

For detailed architecture and configuration, see:
- **[Transport Modes Guide](./docs/transport-modes.md)**
- **[Configuration Reference](./docs/configuration.md)**
- **[Docker Deployment Guide](./docs/docker-deployment.md)**

## 🔧 Features

- **Comprehensive Wazuh Integration** - Full access to Wazuh Manager and Indexer APIs
- **Multi-Transport Support** - HTTP, SSE, and STDIO modes for different use cases
- **Modular Architecture** - Clean separation of concerns with service layers
- **Production Ready** - Docker deployment with health checks and monitoring
- **MCP Compatible** - Native integration with Model Context Protocol clients
- **Rich Tool Set** - 140+ tools for security analysis, agent management, and system monitoring

### Available Tools

**Wazuh Indexer Tools (36 tools):**
- Alert search and analytics
- Vulnerability management  
- Cluster health monitoring
- Index management
- Search aggregations

**Wazuh Manager Tools (106 tools):**
- Agent management and monitoring
- Rule and decoder management
- Group and configuration management
- Security compliance (SCA, CIS-CAT)
- System monitoring (Syscheck, Rootcheck)

For complete tool documentation, see **[Tools Reference](./docs/tools-reference.md)**.

## 🤝 Contributing

We welcome contributions! Please see our **[Development Guide](./docs/development.md)** for:

- Development environment setup
- Code style guidelines  
- Testing procedures
- Pull request process

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: [docs/](./docs/) folder contains comprehensive guides
- **Issues**: Report bugs and feature requests on GitHub Issues
- **Troubleshooting**: See [Troubleshooting Guide](./docs/troubleshooting.md)

## 🎯 Project Status

**✅ PRODUCTION READY** - The Wazuh MCP Server is fully functional and ready for production use with comprehensive documentation, Docker deployment, and multi-transport support.
