"""
Wazuh Manager MCP Server Implementation

This server provides MCP tools for Wazuh Manager API operations including
agent management, configuration, rules, and security compliance.
"""
import sys
import os
import warnings
from pathlib import Path
from typing import Dict, Any

# Suppress specific warnings
warnings.filterwarnings("ignore", category=DeprecationWarning, module="websockets")
warnings.filterwarnings("ignore", category=RuntimeWarning, module="runpy")

# Add current directory to Python path for local imports
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

# Add project root to path for external tool imports
project_root = current_dir.parent.parent
sys.path.insert(0, str(project_root))

from fastmcp import FastMCP

# Import local modules (no external dependencies)
from .config.manager_config import WazuhManagerConfig
from .services.manager_service import WazuhManagerMCPService
from .utils.logger import logger
import logging

# Load configuration from environment
SERVER_PORT = int(os.getenv("WAZUH_MANAGER_MCP_PORT", "8002"))

# Create FastMCP server
mcp = FastMCP(
    name="Wazuh Manager MCP Server",
    instructions="""
    This server provides comprehensive Wazuh Manager API operations including:
    - Agent management and monitoring
    - Configuration management
    - Rule and decoder management
    - Security compliance checking
    - System administration

    Use agent tools for managing agents, config tools for configuration,
    rule tools for security rules, and security tools for compliance monitoring.
    """
)

# Initialize configuration and services
config = WazuhManagerConfig()
wazuh_api = WazuhManagerMCPService(config)

# Test connection
try:
    logger.info("Testing connection to Wazuh API...")
    if wazuh_api.check_connection():
        logger.info("Successfully connected to Wazuh API")
    else:
        logger.warning("Failed to connect to Wazuh API - some tools may not work properly")
except Exception as e:
    logger.error(f"Error testing Wazuh API connection: {e}")

# Override the tools' API clients to use our centralized service
# This ensures all tools use the same authentication and connection
logger = logging.getLogger(__name__)

# Apply the patch before importing tools
# patch_tool_api_clients() -- This is no longer needed.
# Tools will get the client from the centralized tool_clients module.

# Import and register tools with decorators (keeping all original tools)
try:
    logger.info("Importing and registering Wazuh Manager tools...")

    # Import MCP instances from local tools modules - they already have @mcp.tool decorators
    from .tools.agents import mcp as agents_mcp
    from .tools.manager import mcp as manager_mcp
    from .tools.security import mcp as security_mcp
    from .tools.rules import mcp as rules_mcp
    from .tools.decoders import mcp as decoders_mcp
    from .tools.cluster import mcp as cluster_mcp
    from .tools.groups import mcp as groups_mcp
    from .tools.lists import mcp as lists_mcp
    from .tools.experimental import mcp as experimental_mcp
    from .tools.overview import mcp as overview_mcp
    from .tools.rootcheck import mcp as rootcheck_mcp
    from .tools.sca import mcp as sca_mcp
    from .tools.syscheck import mcp as syscheck_mcp
    from .tools.syscollector import mcp as syscollector_mcp
    from .tools.mitre import mcp as mitre_mcp
    from .tools.ciscat import mcp as ciscat_mcp
    from .tools.api_info import mcp as api_info_mcp
    from .tools.tasks import mcp as tasks_mcp

    # Merge all tools from imported MCP instances into our main server
    tool_mcps = [
        agents_mcp, manager_mcp, security_mcp, rules_mcp, decoders_mcp,
        cluster_mcp, groups_mcp, lists_mcp, experimental_mcp, overview_mcp,
        rootcheck_mcp, sca_mcp, syscheck_mcp, syscollector_mcp, mitre_mcp,
        ciscat_mcp, api_info_mcp, tasks_mcp
    ]

    total_tools_imported = 0

    for tool_mcp in tool_mcps:
        if hasattr(tool_mcp, '_tool_manager') and hasattr(tool_mcp._tool_manager, '_tools'):
            tools_dict = tool_mcp._tool_manager._tools
            for tool_name, tool_obj in tools_dict.items():
                # Use proper registration method to ensure UI visibility
                try:
                    # Extract the function from the Tool object and register it properly
                    if hasattr(tool_obj, 'fn'):
                        # Register the extracted function using mcp.tool()
                        mcp.tool(tool_obj.fn)
                        total_tools_imported += 1
                    else:
                        logger.warning(f"Tool {tool_name} does not have 'fn' attribute")
                except Exception as e:
                    logger.warning(f"Failed to register tool {tool_name}: {e}")

    logger.info(f"Successfully imported and registered {total_tools_imported} Wazuh Manager tools from {len(tool_mcps)} modules using centralized authentication")

except ImportError as e:
    logger.error(f"Failed to import Wazuh Manager tools: {e}")

    # Fallback tools if imports fail
    @mcp.tool()
    def error_info():
        """Error information - tools not available"""
        return {
            "error": "Wazuh Manager tools not available",
            "reason": str(e),
            "suggestion": "Check if Wazuh Manager service is running and accessible"
        }

# Add server utility tools
@mcp.tool()
def server_info():
    """Get Wazuh Manager MCP server information"""
    return {
        "server_name": "Wazuh Manager MCP Server",
        "version": "2.0.0",
        "description": "MCP Server for Wazuh Manager API operations using centralized services",
        "capabilities": [
            "Agent management and monitoring",
            "Configuration management",
            "Rule and decoder management",
            "Security compliance checking",
            "System administration"
        ],
        "tool_categories": {
            "agents": [
                "list_agents", "get_agent_details", "get_agent_configuration",
                "get_agent_key_info", "get_agent_daemon_statistics"
            ],
            "manager": ["manager_info", "manager_configuration", "manager_statistics"],
            "security": ["security_configuration", "authentication_context", "rbac_resources"],
            "rules": ["list_rules", "list_rule_files", "list_rule_groups"],
            "decoders": ["list_decoders", "list_decoder_files"],
            "utility": ["server_info", "health_check"]
        },
        "manager_config": {
            "url": config.api_url,
            "verify_ssl": config.verify_ssl,
            "connection_status": "configured"
        },
        "architecture": "centralized_services",
        "authentication": "jwt_with_centralized_management"
    }

@mcp.tool()
def health_check():
    """Perform health check for the MCP server"""
    api_status = "healthy" if wazuh_api and wazuh_api.check_connection() else "unhealthy"

    return {
        "status": api_status,
        "server_name": "Wazuh Manager MCP Server",
        "manager_url": config.api_url,
        "ssl_verification": config.verify_ssl,
        "total_tools": 108,  # Expected count including all imported tools
        "timestamp": "2024-01-01T00:00:00Z",
        "api_connection": api_status,
        "architecture": "centralized_services_with_tool_patching"
    }

# Main application entry point for ASGI servers like Uvicorn
# Add simple HTTP health endpoint alongside MCP endpoint
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route, Mount

async def health_endpoint(request):
    """Simple HTTP health endpoint for Docker health checks"""
    api_status = "healthy" if wazuh_api and wazuh_api.check_connection() else "unhealthy"
    return JSONResponse({
        "status": api_status,
        "server_name": "Wazuh Manager MCP Server"
    })

app = Starlette(
    routes=[
        Route("/health", health_endpoint, methods=["GET"]),
        Mount("/sse", mcp.sse_app()),
        Mount("/mcp", mcp.http_app())
    ]
)

def main():
    """Main entry point for the Wazuh Manager MCP Server."""
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description="Wazuh Manager MCP Server")
    parser.add_argument("--stdio", action="store_true", help="Run in STDIO mode for MCP clients")
    parser.add_argument("--port", type=int, default=SERVER_PORT, help="Port for HTTP/SSE mode")
    args = parser.parse_args()
    
    if args.stdio or len(sys.argv) == 1:  # Default to STDIO if no args
        # Run in STDIO mode for MCP clients like Cursor/Claude Desktop
        logger.info("Starting Wazuh Manager MCP Server in STDIO mode...")
        mcp.run()  # Defaults to STDIO transport
    else:
        # Run in HTTP/SSE mode
        import uvicorn
        logger.info(f"Starting Wazuh Manager MCP Server on port {args.port}...")
        uvicorn.run(app, host="0.0.0.0", port=args.port)

if __name__ == "__main__":
    main()
