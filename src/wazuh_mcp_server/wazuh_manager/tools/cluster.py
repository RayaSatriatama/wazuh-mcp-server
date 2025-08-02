"""
Wazuh Cluster Module - MCP Tools and Resources for Wazuh Cluster Management
"""
import json
import re
from typing import Dict, Any, List, Optional, Union

from fastmcp import FastMCP

from .wazuh_manager_base_api import WazuhAPIBase
from .tool_clients import get_manager_client
import logging

# ====== SECURE ERROR HANDLING ======

def sanitize_error_message(error_message: str) -> str:
    """Sanitize error messages to prevent information disclosure."""
    if not isinstance(error_message, str):
        error_message = str(error_message)

    sensitive_patterns = [
        (r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.)\d{1,3}\b', r'\1XXX')
    ]
    sanitized = error_message
    for pattern, replacement in sensitive_patterns:
        sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)
    return sanitized

def handle_secure_error(e: Any, operation: str = "operation") -> Dict[str, Any]:
    """
    Handle exceptions securely by sanitizing error messages.

    Args:
        e: Exception to handle
        operation: Description of the operation that failed

    Returns:
        Secure error response dictionary
    """
    original_error = str(e)
    sanitized_error = sanitize_error_message(original_error)

    logger.error(f"Error in {operation}: {sanitized_error}")

    return {
        "error": sanitized_error,
        "data": {"affected_items": []},
        "message": f"Failed to complete {operation}"
    }

# Create MCP server instance
mcp = FastMCP("wazuh_cluster_mcp")

# Initialize logger
logger = logging.getLogger(__name__)

# Initialize API client and config

api_client = get_manager_client()

# ====== MCP TOOLS ======

@mcp.tool()
def get_cluster_nodes(
        pretty: bool = False,
        wait_for_complete: bool = False,
        nodes_list: Optional[List[str]] = None,
        offset: int = 0,
        limit: int = 500,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[List[str]] = None,
        node_type: Optional[str] = None,
        q: Optional[str] = None,
        distinct: bool = False
) -> Dict[str, Any]:
    """
    Get information about all nodes in the cluster or a list of them.
    Corresponds to GET /cluster/nodes.

    Args:
        pretty: Show results in human-readable format.
        wait_for_complete: Disable timeout response.
        nodes_list: List of node IDs to query.
        offset: First element to return.
        limit: Maximum number of elements to return.
        sort: Fields to sort by.
        search: Look for elements containing the specified string.
        select: Fields to return.
        node_type: Filter by node type (e.g., "worker", "master").
        q: Query to filter results.
        distinct: Look for distinct values.

    Returns:
        Dictionary with cluster nodes information.
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'offset': offset,
        'limit': limit,
        'sort': sort,
        'search': search,
        'select': ','.join(select) if select else None,
        'type': node_type,
        'q': q,
        'distinct': distinct
    }
    if nodes_list:
        params['nodes_list'] = ','.join(nodes_list)
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.debug("Fetching cluster nodes information from /cluster/nodes")
        return api_client._make_request("GET", "/cluster/nodes", params=params)
    except Exception as e:
        return handle_secure_error(e, "fetching cluster nodes")

@mcp.tool()
def get_cluster_healthcheck(
        pretty: bool = False,
        wait_for_complete: bool = False,
        nodes_list: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Return cluster healthcheck information for all nodes or a list of them.
    Corresponds to GET /cluster/healthcheck.

    Args:
        pretty: Show results in human-readable format.
        wait_for_complete: Disable timeout response.
        nodes_list: List of node IDs to query.

    Returns:
        Dictionary with cluster healthcheck information.
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete
    }
    if nodes_list:
        params['nodes_list'] = ','.join(nodes_list)

    try:
        logger.debug("Fetching cluster healthcheck from /cluster/healthcheck")
        return api_client._make_request("GET", "/cluster/healthcheck", params=params)
    except Exception as e:
        return handle_secure_error(e, "fetching cluster healthcheck")

@mcp.tool()
def get_cluster_status(
        pretty: bool = False,
        wait_for_complete: bool = False
) -> Dict[str, Any]:
    """
    Return information about the cluster status.
    Corresponds to GET /cluster/status.

    Args:
        pretty: Show results in human-readable format.
        wait_for_complete: Disable timeout response.

    Returns:
        Dictionary with cluster status information.
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete
    }
    try:
        logger.debug("Fetching cluster status from /cluster/status")
        return api_client._make_request("GET", "/cluster/status", params=params)
    except Exception as e:
        return handle_secure_error(e, "fetching cluster status")

@mcp.tool()
def get_node_info(
        node_id: str,
        pretty: bool = False,
        wait_for_complete: bool = False
) -> Dict[str, Any]:
    """
    Return information about a specific node in the cluster.
    Corresponds to GET /cluster/{node_id}/info.

    Args:
        node_id: The ID of the node to query.
        pretty: Show results in human-readable format.
        wait_for_complete: Disable timeout response.

    Returns:
        Dictionary with node information.
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete
    }
    try:
        logger.info(f"Fetching info for node {node_id} from /cluster/{node_id}/info")
        return api_client._make_request("GET", f"/cluster/{node_id}/info", params=params)
    except Exception as e:
        return handle_secure_error(e, f"fetching info for node {node_id}")

@mcp.tool()
def get_node_config(
        node_id: str,
        pretty: bool = False,
        wait_for_complete: bool = False,
        section: Optional[str] = None,
        field: Optional[str] = None,
        raw: Optional[bool] = None
) -> Dict[str, Any]:
    """
    Return the configuration (ossec.conf) of the specified node.
    Corresponds to GET /cluster/{node_id}/config

    Args:
        node_id: The ID of the node to query.
        pretty: Show results in human-readable format.
        wait_for_complete: Disable timeout response.
        section: Indicates the wazuh configuration section.
        field: Indicate a section child.
        raw: Format response in plain text.

    Returns:
        Dictionary with node configuration.
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'section': section,
        'field': field,
        'raw': raw
    }
    params = {k: v for k, v in params.items() if v is not None}
    try:
        logger.info(f"Fetching configuration for node {node_id}")
        endpoint = f"/cluster/{node_id}/config"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        return handle_secure_error(e, f"fetching config for node {node_id}")

@mcp.tool()
def get_node_logs(
        node_id: str,
        pretty: bool = False,
        wait_for_complete: bool = False,
        offset: int = 0,
        limit: int = 500,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        tag: Optional[str] = None,
        level: Optional[str] = None,
        q: Optional[str] = None,
        select: Optional[List[str]] = None,
        distinct: bool = False
) -> Dict[str, Any]:
    """
    Return the last 5000 lines of the ossec.log file from the specified node.
    Corresponds to GET /cluster/{node_id}/log

    Args:
        node_id: The ID of the node to query.
        pretty: Show results in human-readable format.
        wait_for_complete: Disable timeout response.
        offset: First element to return in the collection.
        limit: Maximum number of lines to return.
        sort: Sort the collection by fields. Use +/- for ascending/descending.
        search: Look for elements containing the specified string.
        tag: Wazuh component that logged the event.
        level: Filter by log level (e.g., "info", "error").
        q: Query to filter results.
        select: Select which fields to return.
        distinct: Look for distinct values.

    Returns:
        Dictionary with node logs.
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'offset': offset,
        'limit': limit,
        'sort': sort,
        'search': search,
        'tag': tag,
        'level': level,
        'q': q,
        'select': ','.join(select) if select else None,
        'distinct': distinct
    }
    params = {k: v for k, v in params.items() if v is not None}
    try:
        logger.info(f"Fetching logs for node {node_id}")
        endpoint = f"/cluster/{node_id}/log"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        return handle_secure_error(e, f"fetching logs for node {node_id}")

@mcp.tool()
def get_nodes_ruleset_sync_status(
        pretty: bool = False,
        wait_for_complete: bool = False,
        nodes_list: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Return ruleset synchronization status for all nodes or a list of them.

    Args:
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        nodes_list: List of node IDs

    Returns:
        Dictionary with ruleset synchronization status
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete
    }

    if nodes_list:
        params['nodes_list'] = ','.join(nodes_list)

    try:
        logger.debug("Fetching ruleset synchronization status")
        endpoint = "/cluster/ruleset/synchronization"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        logger.error(f"Error fetching ruleset sync status: {str(e)}")
        return {"error": str(e)}

@mcp.tool()
def get_nodes_api_config(
        pretty: bool = False,
        wait_for_complete: bool = False,
        nodes_list: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Return the API configuration of all nodes or a list of them in JSON format.

    Args:
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        nodes_list: List of node IDs

    Returns:
        Dictionary with API configuration for selected nodes
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete
    }

    if nodes_list:
        params['nodes_list'] = ','.join(nodes_list)

    try:
        logger.debug("Fetching nodes API configuration")
        endpoint = "/cluster/api/config"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        logger.error(f"Error fetching nodes API config: {str(e)}")
        return {"error": str(e)}

@mcp.tool()
def get_node_status(
        node_id: str,
        pretty: bool = False,
        wait_for_complete: bool = False
) -> Dict[str, Any]:
    """
    Return the status of all Wazuh daemons in the specified node.

    Args:
        node_id: Node ID
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response

    Returns:
        Dictionary with node status information
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete
    }

    try:
        logger.info(f"Fetching status for node {node_id}")
        endpoint = f"/cluster/nodes/{node_id}/status"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        logger.error(f"Error fetching node status: {str(e)}")
        return {"error": str(e)}

@mcp.tool()
def get_node_daemon_stats(
        node_id: str,
        pretty: bool = False,
        wait_for_complete: bool = False,
        daemons_list: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Return Wazuh statistical information from specified daemons in a cluster node.

    Args:
        node_id: Cluster node name
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        daemons_list: List of daemon names (options: "wazuh-analysisd", "wazuh-remoted", "wazuh-db"),
                      all daemons selected by default if not specified

    Returns:
        Dictionary with daemon statistics
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete
    }

    if daemons_list:
        params['daemons_list'] = ','.join(daemons_list)

    try:
        logger.info(f"Fetching daemon stats for node {node_id}")
        endpoint = f"/cluster/nodes/{node_id}/stats/internal"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        logger.error(f"Error fetching node daemon stats: {str(e)}")
        return {"error": str(e)}

@mcp.tool()
def get_node_stats(
        node_id: str,
        pretty: bool = False,
        wait_for_complete: bool = False,
        date: Optional[str] = None
) -> Dict[str, Any]:
    """
    Return Wazuh statistical information in node for the current or specified date.

    Args:
        node_id: Cluster node name
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        date: Date to obtain statistical information from. Format YYYY-MM-DD

    Returns:
        Dictionary with node statistics
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete
    }

    if date:
        params['date'] = date

    try:
        logger.info(f"Fetching statistics for node {node_id}")
        endpoint = f"/cluster/nodes/{node_id}/stats"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        logger.error(f"Error fetching node stats: {str(e)}")
        return {"error": str(e)}

@mcp.tool()
def get_node_stats_hourly(
        node_id: str,
        pretty: bool = False,
        wait_for_complete: bool = False
) -> Dict[str, Any]:
    """
    Return Wazuh statistical information per hour for the specified node.

    Args:
        node_id: Node ID
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response

    Returns:
        Dictionary with hourly statistics
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete
    }

    try:
        logger.info(f"Fetching hourly statistics for node {node_id}")
        endpoint = f"/cluster/nodes/{node_id}/stats/hourly"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        logger.error(f"Error fetching node hourly stats: {str(e)}")
        return {"error": str(e)}

@mcp.tool()
def get_node_stats_weekly(
        node_id: str,
        pretty: bool = False,
        wait_for_complete: bool = False
) -> Dict[str, Any]:
    """
    Return Wazuh statistical information per week for the specified node.

    Args:
        node_id: Node ID
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response

    Returns:
        Dictionary with weekly statistics
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete
    }

    try:
        logger.info(f"Fetching weekly statistics for node {node_id}")
        endpoint = f"/cluster/nodes/{node_id}/stats/weekly"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        logger.error(f"Error fetching node weekly stats: {str(e)}")
        return {"error": str(e)}

@mcp.tool()
def get_node_logs_summary(
        node_id: str,
        pretty: bool = False,
        wait_for_complete: bool = False
) -> Dict[str, Any]:
    """
    Return a summary of the last 2000 Wazuh log entries in the specified node.

    Args:
        node_id: Node ID
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response

    Returns:
        Dictionary with node logs summary
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete
    }

    try:
        logger.info(f"Fetching logs summary for node {node_id}")
        endpoint = f"/cluster/nodes/{node_id}/logs/summary"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        logger.error(f"Error fetching node logs summary: {str(e)}")
        return {"error": str(e)}

@mcp.tool()
def get_check_nodes_config(
        pretty: bool = False,
        wait_for_complete: bool = False,
        nodes_list: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Return whether the Wazuh configuration is correct in all nodes or a list of them.

    Args:
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        nodes_list: List of node IDs

    Returns:
        Dictionary with configuration check results
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete
    }

    if nodes_list:
        params['nodes_list'] = ','.join(nodes_list)

    try:
        logger.info("Checking nodes configuration")
        endpoint = "/cluster/configuration/validation"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        logger.error(f"Error checking nodes configuration: {str(e)}")
        return {"error": str(e)}

@mcp.tool()
def get_node_active_config(
        node_id: str,
        component: str,
        configuration: str,
        pretty: bool = False,
        wait_for_complete: bool = False
) -> Dict[str, Any]:
    """
    Return the requested configuration in JSON format for the specified node.

    Args:
        node_id: Cluster node name
        component: Selected agent's component. Valid options: "agent", "agentless", "analysis", "auth", "com",
                 "csyslog", "integrator", "logcollector", "mail", "monitor", "request", "syscheck",
                 "wazuh-db", "wmodules"
        configuration: Selected agent's configuration to read. Valid options depend on the selected component.
                      Common values include: "client", "buffer", "labels", "internal", "global", "active_response",
                      "alerts", "command", "rules", "decoders", "auth", "logging", "reports", "active-response",
                      "cluster", "csyslog", "integration", "localfile", "socket", "remote", "syscheck",
                      "rootcheck", "wdb", "wmodules", "rule_test"
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response

    Returns:
        Dictionary with active configuration

    Note:
        The valid configuration values depend on the component selected. For example:
        - If component="agent", valid configurations are "client", "buffer", "labels", "internal", "anti_tampering"
        - If component="analysis", valid configurations are "global", "active_response", "alerts", "command", "rules", etc.
        Please refer to the API documentation for all valid combinations.
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete
    }

    try:
        logger.info(f"Fetching active configuration for node {node_id}")
        endpoint = f"/cluster/nodes/{node_id}/config/{component}/{configuration}"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        logger.error(f"Error fetching node active config: {str(e)}")
        return {"error": str(e)}

@mcp.tool()
def get_local_node_info_cluster(
    pretty: bool = False,
    wait_for_complete: bool = False
) -> Dict[str, Any]:
    """
    Return basic information about the cluster node receiving the request.

    Args:
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response

    Returns:
        Dictionary with local node information
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete
    }

    try:
        logger.debug("Fetching local node information")
        endpoint = "/cluster/local/info"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        logger.error(f"Error fetching local node info: {str(e)}")
        return {"error": str(e)}

@mcp.tool()
def get_local_node_config_cluster(
    pretty: bool = False,
    wait_for_complete: bool = False
) -> Dict[str, Any]:
    """
    Return the current node cluster configuration.

    Args:
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response

    Returns:
        Dictionary with local node cluster configuration
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete
    }

    try:
        logger.debug("Fetching local node cluster configuration")
        endpoint = "/cluster/local/config"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        logger.error(f"Error fetching local node config: {str(e)}")
        return {"error": str(e)}