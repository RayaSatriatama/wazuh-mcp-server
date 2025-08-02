# Wazuh MCP Server Documentation

Welcome to the Wazuh Model Context Protocol (MCP) Server documentation. This comprehensive guide will help you understand, deploy, and use the Wazuh MCP Server effectively.

## 📚 Documentation Structure

| Document | Description |
|----------|-------------|
| [Quick Start Guide](./quick-start.md) | Get started in 5 minutes |
| [Installation Guide](./installation.md) | Detailed installation instructions |
| [Configuration Guide](./configuration.md) | Environment and server configuration |
| [Docker Deployment](./docker-deployment.md) | Containerized deployment with Docker |
| [Transport Modes](./transport-modes.md) | HTTP, SSE, and STDIO transport options |
| [API Reference](./api-reference.md) | Complete API documentation |
| [MCP Client Integration](./mcp-client-integration.md) | Integrate with Cursor, Claude Desktop |
| [Tools Reference](./tools-reference.md) | Available tools and capabilities |
| [Troubleshooting](./troubleshooting.md) | Common issues and solutions |
| [Development Guide](./development.md) | Contributing and development setup |

## 🚀 Quick Links

### For Users
- **New to MCP?** Start with the [Quick Start Guide](./quick-start.md)
- **Docker User?** Check [Docker Deployment](./docker-deployment.md)
- **Need Help?** See [Troubleshooting](./troubleshooting.md)

### For Developers
- **Contributing?** Read the [Development Guide](./development.md)
- **Building Tools?** See [API Reference](./api-reference.md)
- **Custom Integration?** Check [Transport Modes](./transport-modes.md)

## 🎯 What is Wazuh MCP Server?

The Wazuh MCP Server is a bridge that exposes Wazuh's security monitoring and SIEM capabilities through the Model Context Protocol (MCP), enabling AI assistants like Claude, Cursor, and other MCP-compatible clients to interact with Wazuh data and functionality.

### Key Features
- **🔍 Security Analytics**: Query Wazuh alerts, events, and security data
- **👥 Agent Management**: Monitor and manage Wazuh agents
- **📊 Real-time Monitoring**: Access live security events and metrics
- **🔧 Configuration Management**: Manage rules, decoders, and policies
- **🌐 Multi-Transport**: HTTP, SSE, and STDIO transport support
- **🐳 Docker Ready**: Production-ready containerized deployment

### Architecture Overview
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   MCP Client    │────│ Wazuh MCP Server │────│  Wazuh Platform │
│ (Cursor/Claude) │    │   (HTTP/SSE)     │    │ (Manager/Index) │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 📋 Prerequisites

- **Wazuh Platform**: Running Wazuh Manager and Indexer
- **Python**: 3.11 or higher
- **Docker**: For containerized deployment (optional)
- **Network Access**: To Wazuh Manager API (port 55000) and Indexer (port 9200)

## 🏃‍♂️ Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/RayaSatriatama/wazuh-mcp-server.git
   cd wazuh-mcp-server
   ```

2. **Configure environment**
   ```bash
   cp deployment/docker/.env.example deployment/docker/.env
   # Edit .env with your Wazuh credentials
   ```

3. **Deploy with Docker**
   ```bash
   cd deployment/docker
   docker compose --profile http up -d
   ```

4. **Test the deployment**
   ```bash
   curl http://localhost:8001/health  # Indexer
   curl http://localhost:8002/health  # Manager
   ```

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/RayaSatriatama/wazuh-mcp-server/issues)
- **Discussions**: [GitHub Discussions](https://github.com/RayaSatriatama/wazuh-mcp-server/discussions)
- **Documentation**: This documentation site

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.

---

> **Note**: This project is not officially affiliated with Wazuh, Inc. It's a community-driven integration to bridge Wazuh with MCP-compatible AI assistants.
