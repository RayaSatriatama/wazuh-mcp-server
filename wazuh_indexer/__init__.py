"""
Wazuh Indexer MCP Server

This package provides an MCP server for Wazuh Indexer API operations including:
- Index management and monitoring
- Cluster operations
- Search capabilities  
- Security monitoring
- Performance metrics

Tools included:
- Index information and statistics
- Cluster health and status
- Search and query operations
- Security and monitoring tools
"""

from .server import mcp, main

__version__ = "1.0.0"
__all__ = ["mcp", "main"] 