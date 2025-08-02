# Changelog

All notable changes to the Wazuh MCP Server project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Source code reorganization under `src/` directory structure
- Comprehensive documentation in `docs/` folder
- Security policy and vulnerability reporting process
- Best practice repository structure implementation

### Changed
- Moved application code to `src/wazuh_mcp_server/` for better package organization
- Updated project structure to follow Python packaging best practices
- Reorganized documentation for better navigation and maintenance

### Security
- Added security policy documentation
- Implemented security best practices guidelines
- Added Docker security configurations

## [1.0.0] - 2025-08-02

### Added
- **Wazuh Indexer MCP Server** with comprehensive search and analytics tools
- **Wazuh Manager MCP Server** with full agent and rule management capabilities
- **Multi-transport support** (HTTP, SSE, STDIO) for different deployment scenarios
- **Docker deployment** with Docker Compose orchestration
- **FastMCP framework integration** v2.11.0 for reliable MCP protocol implementation
- **140+ tools** across both servers for complete Wazuh integration
- **Comprehensive documentation** including:
  - Quick start guide
  - Installation instructions
  - API reference
  - Tools reference
  - Configuration guide
  - Troubleshooting guide
  - Development guide
  - Transport modes guide

### Tools Added

#### Wazuh Indexer Tools (36 tools)
- **Search Tools**: `search_alerts`, `search_vulnerabilities`, `search_events`
- **Cluster Management**: `get_cluster_health`, `get_cluster_stats`, `list_indices`
- **Index Operations**: `get_index_info`, `get_index_mapping`, `get_index_stats`
- **Monitoring**: `get_cat_*` tools for compact cluster information
- **Security**: `get_authentication_info`, `get_permissions_info`, `get_roles_info`

#### Wazuh Manager Tools (106 tools)
- **Agent Management**: `get_agents`, `add_agent`, `restart_agent`, `get_agent_info`
- **Rules & Decoders**: `get_rules`, `get_rule_info`, `get_decoders`
- **Groups**: `get_groups`, `create_group`, `assign_group`
- **Security Compliance**: SCA, CIS-CAT, security configuration assessment
- **System Monitoring**: Syscheck, Rootcheck, file integrity monitoring
- **System Information**: `get_manager_info`, `get_manager_stats`, `get_manager_logs`

### Technical Implementation
- **Modular Architecture** with clean separation of concerns
- **Service Layer Pattern** for business logic encapsulation
- **Environment-based Configuration** for flexible deployment
- **Health Checks** and monitoring capabilities
- **Error Handling** with comprehensive logging
- **Production-ready** Docker containers with health checks

### Deployment Features
- **Docker Compose** with multiple profiles (HTTP, SSE, STDIO)
- **Environment Configuration** templates and examples
- **Port Configuration**: 8001 (Indexer HTTP), 8002 (Manager HTTP), 8003 (Indexer SSE), 8004 (Manager SSE)
- **Volume Mounting** for logs and configuration persistence
- **Network Isolation** with dedicated Docker network

### Documentation
- **10 comprehensive guides** covering all aspects of the project
- **API documentation** with examples in multiple languages (Python, JavaScript, cURL)
- **Tools reference** with detailed parameter descriptions
- **Troubleshooting guide** with common issues and solutions
- **Development guide** for contributors

### Security
- **Authentication support** for both Wazuh Manager and Indexer
- **SSL/TLS configuration** options
- **Environment variable protection** for sensitive data
- **Security best practices** documentation

## [0.9.0] - 2025-08-01

### Added
- Initial project structure
- Basic MCP server implementations
- Core Wazuh integrations
- Docker deployment foundation

### Development
- FastMCP framework integration
- Tool registration system
- Basic testing structure
- Virtual environment setup

---

## Version History Summary

- **v1.0.0** (2025-08-02): Full production release with comprehensive features
- **v0.9.0** (2025-08-01): Initial development version

## Contributors

- **RayaSatriatama** - Project creator and maintainer

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Note**: This changelog follows the [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) format. Each version includes categorized changes:
- **Added** for new features
- **Changed** for changes in existing functionality  
- **Deprecated** for soon-to-be removed features
- **Removed** for now removed features
- **Fixed** for any bug fixes
- **Security** for security-related changes
