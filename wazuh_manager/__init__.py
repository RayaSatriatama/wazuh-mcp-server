"""
Wazuh Manager MCP Server

This package provides an MCP server for Wazuh Manager API operations including:
- Agent management and monitoring
- Configuration management
- Rule and decoder management
- Security compliance checking
- System administration

Tools included:
- Agent operations and status
- Configuration analysis
- Rule and decoder management
- Security compliance tools
- Manager administration
"""

from .server import mcp, main

__version__ = "1.0.0"
__all__ = ["mcp", "main"] 