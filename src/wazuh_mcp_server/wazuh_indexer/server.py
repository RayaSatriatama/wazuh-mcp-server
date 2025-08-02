"""
Wazuh Indexer MCP Server Implementation


This server provides MCP tools for Wazuh Indexer operations including
search operations, index management, and cluster monitoring.
"""
import sys
import os
import warnings
from pathlib import Path
from typing import Dict, Any, List, Optional


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
from .config.indexer_config import WazuhIndexerConfig
from .services.indexer_service import WazuhIndexerMCPService
from .utils.logger import logger
import logging


# Load configuration from environment
SERVER_PORT = int(os.getenv("WAZUH_INDEXER_MCP_PORT", "8001"))


# Create FastMCP server
mcp = FastMCP(
    name="Wazuh Indexer MCP Server",
    instructions="""
    This server provides comprehensive Wazuh Indexer operations including:
    - Search and query operations for alerts and events
    - Index management and statistics
    - Cluster health monitoring
    - Performance metrics


    Use search tools for finding alerts and events, index tools for management,
    and cluster tools for monitoring health and performance.
    """
)


# Initialize configuration and services
config = WazuhIndexerConfig()
indexer_service = WazuhIndexerMCPService(config)


# Test connection
try:
    logger.info("Testing connection to Wazuh Indexer...")
    if indexer_service.check_connection():
        cluster_health = indexer_service.get_cluster_health()
        status = cluster_health.get("status", "unknown")
        logger.info(f"Successfully connected to Wazuh Indexer - Cluster status: {status}")
    else:
        logger.warning("Wazuh Indexer connection issue - some tools may not work properly")
except Exception as e:
    logger.error(f"Error testing Wazuh Indexer connection: {e}")


# Patch local tool clients to use our local service
logger = logging.getLogger(__name__)


def patch_tool_clients():
    """Patch tool modules to use local indexer service"""
    try:
        # Import and patch the local tool client module
        from .tools import tool_clients


        # Replace the global client instance with our local service
        tool_clients._indexer_client_instance = indexer_service


        logger.info("Successfully patched local tool clients to use local service")
        return True
    except Exception as e:
        logger.warning(f"Could not patch local tool clients: {e}")
        return False


# Patch clients before importing tools
patch_success = patch_tool_clients()


# Import and register tools
try:
    logger.info("Importing and registering Wazuh Indexer tools...")


    # Import MCP instances from local tools modules
    tool_modules = [
        ("cluster_tools", "cluster_tools"),
        ("index_tools", "index_tools"),
        ("security_tools", "security_tools"),
        ("monitoring_tools", "monitoring_tools"),
        ("search_tools", "search_tools")
    ]


    tool_mcps = []


    for tool_name, module_path in tool_modules:
        try:
            # Import using relative imports from tools package
            if module_path == "cluster_tools":
                from .tools.cluster_tools import mcp as cluster_mcp
                tool_mcps.append(cluster_mcp)
            elif module_path == "index_tools":
                from .tools.index_tools import mcp as index_mcp
                tool_mcps.append(index_mcp)
            elif module_path == "security_tools":
                from .tools.security_tools import mcp as security_mcp
                tool_mcps.append(security_mcp)
            elif module_path == "monitoring_tools":
                from .tools.monitoring_tools import mcp as monitoring_mcp
                tool_mcps.append(monitoring_mcp)
            elif module_path == "search_tools":
                from .tools.search_tools import mcp as search_mcp
                tool_mcps.append(search_mcp)


        except Exception as e:
            logger.warning(f"⚠️  Could not import {tool_name}: {e}")


    # Register tools from imported MCP instances
    total_tools_imported = 0


    for tool_mcp in tool_mcps:
        if hasattr(tool_mcp, '_tool_manager') and hasattr(tool_mcp._tool_manager, '_tools'):
            tools_dict = tool_mcp._tool_manager._tools
            for tool_name, tool_obj in tools_dict.items():
                try:
                    if hasattr(tool_obj, 'fn'):
                        mcp.tool(tool_obj.fn)
                        total_tools_imported += 1
                    else:
                        logger.warning(f"Tool {tool_name} does not have 'fn' attribute")
                except Exception as e:
                    logger.warning(f"Failed to register tool {tool_name}: {e}")


    logger.info(f"Successfully imported and registered {total_tools_imported} Wazuh Indexer tools from {len(tool_mcps)} modules")


except ImportError as e:
    logger.error(f"Failed to import Wazuh Indexer tools: {e}")


    # Fallback tools if imports fail
    @mcp.tool()
    def error_info():
        """Error information - tools not available"""
        return {
            "error": "Wazuh Indexer tools not available",
            "reason": str(e),
            "suggestion": "Check if Wazuh Indexer service is running and accessible"
        }


# Add server utility tools
@mcp.tool()
def server_info():
    """Get Wazuh Indexer MCP server information"""
    return {
        "server_name": "Wazuh Indexer MCP Server",
        "version": "2.0.0",
        "description": "MCP Server for Wazuh Indexer operations using centralized services",
        "capabilities": [
            "Search and query operations",
            "Index management and monitoring",
            "Cluster health monitoring",
            "Performance metrics"
        ],
        "tool_categories": {
            "cluster": [
                "get_cluster_health", "get_cluster_stats", "get_cluster_settings",
                "get_nodes_info", "get_nodes_stats", "get_cluster_allocation_explain", "get_cluster_pending_tasks"
            ],
            "index": [
                "get_index_info", "get_index_stats", "get_index_mapping", "get_index_settings",
                "list_indices", "get_index_templates", "get_index_aliases"
            ],
            "search": [
                "search_alerts", "search_vulnerabilities", "search_events",
                "get_document_by_id", "count_documents", "search_with_aggregations",
                "scroll_search", "multi_search_simple"
            ],
            "monitoring": [
                "get_cat_indices", "get_cat_nodes", "get_cat_shards", "get_cat_allocation",
                "get_cat_health", "get_cat_pending_tasks", "get_cat_plugins", "get_cat_thread_pool"
            ],
            "security": [
                "get_security_config", "get_users_info", "get_roles_info",
                "get_permissions_info", "get_security_audit_log", "get_authentication_info"
            ],
            "utility": ["server_info", "health_check"]
        },
        "indexer_config": {
            "url": config.indexer_url,
            "verify_ssl": config.verify_ssl,
            "connection_status": "configured"
        },
        "architecture": "centralized_services",
        "authentication": "basic_auth_with_centralized_management",
        "total_tools": total_tools_imported
    }


@mcp.tool()
def health_check():
    """Perform health check for the MCP server"""
    api_status = "healthy"
    cluster_status = "unknown"


    if indexer_service:
        try:
            health = indexer_service.get_cluster_health()
            cluster_status = health.get("status", "unknown")
            api_status = "healthy" if cluster_status in ["green", "yellow"] else "unhealthy"
        except:
            api_status = "unhealthy"
    else:
        api_status = "unhealthy"


    return {
        "status": api_status,
        "server_name": "Wazuh Indexer MCP Server",
        "indexer_url": config.indexer_url,
        "ssl_verification": config.verify_ssl,
        "total_tools": total_tools_imported,
        "timestamp": "2024-01-01T00:00:00Z",
        "cluster_status": cluster_status,
        "architecture": "centralized_services_with_tools_folder_only"
    }


# Main application entry point for ASGI servers like Uvicorn
# Add simple HTTP health endpoint alongside MCP endpoint
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route, Mount

async def health_endpoint(request):
    """Simple HTTP health endpoint for Docker health checks"""
    api_status = "healthy"
    cluster_status = "unknown"

    if indexer_service:
        try:
            health = indexer_service.get_cluster_health()
            cluster_status = health.get("status", "unknown")
            api_status = "healthy" if cluster_status in ["green", "yellow"] else "unhealthy"
        except:
            api_status = "unhealthy"
    else:
        api_status = "unhealthy"

    return JSONResponse({
        "status": api_status,
        "server_name": "Wazuh Indexer MCP Server",
        "cluster_status": cluster_status
    })

app = Starlette(
    routes=[
        Route("/health", health_endpoint, methods=["GET"]),
        Mount("/sse", mcp.sse_app()),
        Mount("/mcp", mcp.http_app())
    ]
)


def main():
    """Main entry point for the Wazuh Indexer MCP Server."""
    import sys
    import argparse

    parser = argparse.ArgumentParser(description="Wazuh Indexer MCP Server")
    parser.add_argument("--stdio", action="store_true", help="Run in STDIO mode for MCP clients")
    parser.add_argument("--port", type=int, default=SERVER_PORT, help="Port for HTTP/SSE mode")
    args = parser.parse_args()

    if args.stdio or len(sys.argv) == 1:  # Default to STDIO if no args
        # Run in STDIO mode for MCP clients like Cursor/Claude Desktop
        logger.info("Starting Wazuh Indexer MCP Server in STDIO mode...")
        mcp.run()  # Defaults to STDIO transport
    else:
        # Run in HTTP/SSE mode
        import uvicorn
        logger.info(f"Starting Wazuh Indexer MCP Server on port {args.port}...")
        uvicorn.run(app, host="0.0.0.0", port=args.port)


if __name__ == "__main__":
    main()
