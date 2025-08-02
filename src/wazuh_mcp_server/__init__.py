"""
Wazuh MCP Server Package

A Model Context Protocol (MCP) server implementation for Wazuh integration.
Provides tools for interacting with Wazuh Indexer and Wazuh Manager APIs.
"""

__version__ = "1.0.0"
__author__ = "Wazuh MCP Server Team"

# Import main components
from .server_manager import SimpleServerManager

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

__all__ = ["SimpleServerManager", "SERVERS", "DEFAULT_PORTS"] 