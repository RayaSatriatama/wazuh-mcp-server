"""
Wazuh MCP Server Package

This package contains MCP (Model Context Protocol) servers for Wazuh services:
- wazuh_indexer: Tools for Wazuh Indexer API operations
- wazuh_manager: Tools for Wazuh Manager API operations

Each server runs independently and can be started separately.
"""

__version__ = "1.0.0"
__author__ = "Wazuh MCP Server"

# Server categories
SERVERS = [
    "wazuh_indexer",
    "wazuh_manager"
]

# Default ports for each server
DEFAULT_PORTS = {
    "wazuh_indexer": 8001,
    "wazuh_manager": 8002
} 