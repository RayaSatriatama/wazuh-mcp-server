"""
Wazuh Agents Module - MCP Tools and Resources for Wazuh Agents API
"""
import json
import re
import logging
from typing import Dict, Any, List, Optional, Union

from fastmcp import FastMCP

# Simple local logger
logger = logging.getLogger(__name__)

# Use relative imports for local modules
try:
    from .wazuh_manager_base_api import WazuhAPIBase
    from .tool_clients import get_manager_client
except ImportError:
    # Fallback for testing or standalone execution
    from wazuh_manager_base_api import WazuhAPIBase
    # Define a dummy get_manager_client for standalone execution if needed
    def get_manager_client():
        print("WARNING: Using fallback client. This should only happen in standalone tests.")
        # Configure a default client for testing if necessary
        return WazuhAPIBase("https://localhost:55000", "user", "pass", verify_ssl=False)

# ====== SECURITY UTILITIES ======

def sanitize_error_message(error_message: str) -> str:
    """
    Sanitize error messages to prevent information disclosure.

    Args:
        error_message: Original error message

    Returns:
        Sanitized error message with sensitive information removed
    """
    if not error_message:
        return error_message

    # Patterns to sanitize
    sensitive_patterns = [
        # Database connection strings - completely remove
        (r'mysql://[^@]+@[^/]+[^\s]*', 'Database connection failed'),
        (r'postgresql://[^@]+@[^/]+[^\s]*', 'Database connection failed'),
        (r'mongodb://[^@]+@[^/]+[^\s]*', 'Database connection failed'),

        # File paths - completely remove
        (r'/etc/[^\s]+', 'Configuration file not found'),
        (r'/var/[^\s]+', 'System file not found'),
        (r'/home/[^\s]+', 'User file not found'),
        (r'C:\\[^\s]+', 'System file not found'),

        # IP addresses (partial sanitization)
        (r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.)\d{1,3}\b', r'\1XXX'),

        # Passwords and tokens
        (r'password[=:]\s*[^\s]+', 'password=[HIDDEN]'),
        (r'token[=:]\s*[^\s]+', 'token=[HIDDEN]'),
        (r'key[=:]\s*[^\s]+', 'key=[HIDDEN]'),
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
mcp = FastMCP("wazuh_agents_mcp")

# Initialize config

# Hapus kelas WazuhAgentsAPI yang tidak digunakan lagi
# class WazuhAgentsAPI(WazuhAPIBase):
#    ...

# Hapus inisialisasi agents_api yang usang
# agents_api = WazuhAgentsAPI(...)

# ====== BUSINESS LOGIC FUNCTIONS (TESTABLE) ======

@mcp.tool()
def get_list_agents(
    pretty: bool = False,
    wait_for_complete: bool = False,
    agents_list: Optional[List[str]] = None,
    offset: int = 0,
    limit: int = 500,
    select: Optional[str] = None,
    sort: Optional[str] = None,
    search: Optional[str] = None,
    status: Optional[List[str]] = None,
    q: Optional[str] = None,
    older_than: Optional[str] = None,
    os_platform: Optional[str] = None,
    os_version: Optional[str] = None,
    os_name: Optional[str] = None,
    manager: Optional[str] = None,
    version: Optional[str] = None,
    group: Optional[str] = None,
    node_name: Optional[str] = None,
    name: Optional[str] = None,
    ip: Optional[str] = None,
    register_ip: Optional[str] = None,
    group_config_status: Optional[str] = None,
    distinct: bool = False
) -> Dict[str, Any]:
    """
    List all available Wazuh AGENTS (not alerts/events) with detailed filtering options.

    *** USE THIS TOOL FOR: ***
    - Managing Wazuh agents (monitoring endpoints/systems)
    - Getting agent status, connectivity, versions
    - Agent inventory and health monitoring
    - Filtering agents by OS, group, status

    *** DO NOT use for security alerts/events - use search_alerts instead ***

    Args:
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        agents_list: List of agent IDs (separated by comma)
        offset: First element to return in the collection
        limit: Maximum number of elements to return (max 500 recommended)
        select: Fields to return (separated by comma)
        sort: Fields to sort by (separated by comma)
        search: Look for elements containing the specified string
        status: Filter by agent status
        q: Query to filter results (Wazuh syntax) - for agent properties, NOT alert levels
        older_than: Filter out agents with older last keep alive
        os_platform: Filter by OS platform
        os_version: Filter by OS version
        os_name: Filter by OS name
        manager: Filter by manager hostname
        version: Filter by agent version
        group: Filter by group of agents
        node_name: Filter by node name
        name: Filter by agent name
        ip: Filter by agent IP
        register_ip: Filter by agent registration IP
        group_config_status: Agent groups configuration sync status
        distinct: Look for distinct values

    Returns:
        Dictionary with agent data (systems/endpoints), NOT security alerts
    """
    try:
        logger.debug("Fetching agents list")
        response = get_manager_client().get(
            "agents",
            pretty=pretty,
            wait_for_complete=wait_for_complete,
            offset=offset,
            limit=limit,
            select=select,
            sort=sort,
            search=search,
            q=q,
            # Additional Wazuh-specific parameters
            agents_list=','.join(agents_list) if agents_list else None,
            status=','.join(status) if status else None,
            older_than=older_than,
            **{
        'os.platform': os_platform,
        'os.version': os_version,
        'os.name': os_name,
        'manager': manager,
        'version': version,
        'group': group,
        'node_name': node_name,
        'name': name,
        'ip': ip,
        'registerIP': register_ip,
        'group_config_status': group_config_status,
        'distinct': distinct
    }
        )
        return response

    except Exception as e:
        return handle_secure_error(e, "fetching agents list")

@mcp.tool()
def get_active_configuration(
        agent_id: str,
        component: str,
        configuration: str,
        pretty: bool = False,
        wait_for_complete: bool = False
) -> Dict[str, Any]:
    """
    Return the active configuration the agent is currently using.

    Args:
        agent_id: Agent ID. All possible values from 000 onwards.
        component: Selected agent's component. Must be one of: "agent", "agentless", "analysis",
                  "auth", "com", "csyslog", "integrator", "logcollector", "mail", "monitor",
                  "request", "syscheck", "wazuh-db", "wmodules".
        configuration: Selected agent's configuration to read. Must be one of: "client", "buffer",
                      "labels", "internal", "anti_tampering", "agentless", "global",
                      "active_response", "alerts", "command", "rules", "decoders", "auth",
                      "logging", "reports", "active-response", "cluster", "csyslog",
                      "integration", "localfile", "socket", "remote", "syscheck",
                      "rootcheck", "wdb", "wmodules", "rule_test".
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response

    Returns:
        Dictionary with agent's active configuration
    """
    try:
        logger.info(
            f"Fetching active configuration for agent {agent_id}, component {component}, configuration {configuration}")
        endpoint = f"agents/{agent_id}/config/{component}/{configuration}"
        return get_manager_client().get(endpoint, pretty=pretty, wait_for_complete=wait_for_complete)
    except Exception as e:
        return handle_secure_error(e, "fetching active configuration")

@mcp.tool()
def get_agent_key(
    agent_id: str,
    pretty: bool = False,
    wait_for_complete: bool = False
) -> Dict[str, Any]:
    """
    Get the key of an agent.

    Args:
        agent_id: Agent ID. All possible values from 000 onwards.
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response

    Returns:
        Dictionary with agent key information
    """
    try:
        logger.info(f"Fetching agent key for agent {agent_id}")
        endpoint = f"agents/{agent_id}/key"
        return get_manager_client().get(endpoint, pretty=pretty, wait_for_complete=wait_for_complete)
    except Exception as e:
        return handle_secure_error(e, "fetching agent key")

@mcp.tool()
def get_agent_daemon_stats(
    agent_id: str,
    pretty: bool = False,
    wait_for_complete: bool = False,
    daemons_list: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Get Wazuh statistical information from the specified agent.

    Args:
        agent_id: Agent ID. All possible values from 000 onwards.
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        daemons_list: List of daemon names

    Returns:
        Dictionary with agent daemon statistics
    """
    try:
        logger.info(f"Fetching daemon stats for agent {agent_id}")
        endpoint = f"agents/{agent_id}/stats/analysisd"
        params = {
            'pretty': pretty,
            'wait_for_complete': wait_for_complete
        }
        if daemons_list:
            params['daemons_list'] = ','.join(daemons_list)
        return get_manager_client().get(endpoint, **params)
    except Exception as e:
        return handle_secure_error(e, "fetching agent daemon stats")

@mcp.tool()
def get_agent_component_stats(
    agent_id: str,
    component: str,
    pretty: bool = False,
    wait_for_complete: bool = False
) -> Dict[str, Any]:
    """
    Get agent's component stats.

    Args:
        agent_id: Agent ID. All possible values from 000 onwards.
        component: Component name
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response

    Returns:
        Dictionary with agent component statistics
    """
    try:
        logger.info(f"Fetching component stats for agent {agent_id}, component {component}")
        endpoint = f"agents/{agent_id}/stats/{component}"
        return get_manager_client().get(endpoint, pretty=pretty, wait_for_complete=wait_for_complete)
    except Exception as e:
        return handle_secure_error(e, "fetching agent component stats")

@mcp.tool()
def get_upgrade_results(
    pretty: bool = False,
    wait_for_complete: bool = False,
    agents_list: Optional[List[str]] = None,
    q: Optional[str] = None,
    os_platform: Optional[str] = None,
    os_version: Optional[str] = None,
    os_name: Optional[str] = None,
    manager: Optional[str] = None,
    version: Optional[str] = None,
    group: Optional[str] = None,
    node_name: Optional[str] = None,
    name: Optional[str] = None,
    ip: Optional[str] = None,
    register_ip: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get upgrade results from agents.

    Args:
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        agents_list: List of agent IDs
        q: Query to filter results
        os_platform: Filter by OS platform
        os_version: Filter by OS version
        os_name: Filter by OS name
        manager: Filter by manager hostname
        version: Filter by agent version
        group: Filter by group of agents
        node_name: Filter by node name
        name: Filter by agent name
        ip: Filter by agent IP
        register_ip: Filter by agent registration IP

    Returns:
        Dictionary with upgrade results
    """
    try:
        logger.debug("Fetching upgrade results")
        params = {
            'pretty': pretty,
            'wait_for_complete': wait_for_complete,
            'q': q
        }

        if agents_list:
            params['agents_list'] = ','.join(agents_list)

        # Add OS and other filters
        filter_params = {
            'os.platform': os_platform,
            'os.version': os_version,
            'os.name': os_name,
            'manager': manager,
            'version': version,
            'group': group,
            'node_name': node_name,
            'name': name,
            'ip': ip,
            'registerIP': register_ip
        }

        # Only add non-None parameters
        for key, value in filter_params.items():
            if value is not None:
                params[key] = value
        return get_manager_client().get("agents/upgrade_result", **params)
    except Exception as e:
        return handle_secure_error(e, "fetching upgrade results")

@mcp.tool()
def get_check_user_uninstall_permission(
    pretty: bool = False,
    wait_for_complete: bool = False
) -> Dict[str, Any]:
    """
    Check if the user has permission to uninstall agents.

    Args:
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response

    Returns:
        Dictionary with permission check results
    """
    try:
        logger.info("Checking user uninstall permission")
        return get_manager_client().get("agents/no_group", pretty=pretty, wait_for_complete=wait_for_complete)
    except Exception as e:
        return handle_secure_error(e, "checking uninstall permission")

@mcp.tool()
def get_list_agents_without_group(
    pretty: bool = False,
    wait_for_complete: bool = False,
    offset: int = 0,
    limit: int = 500,
    select: Optional[str] = None,
    sort: Optional[str] = None,
    search: Optional[str] = None,
    q: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get agents without group assigned.

    Args:
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        offset: First element to return in the collection
        limit: Maximum number of elements to return
        select: Fields to return (separated by comma)
        sort: Fields to sort by (separated by comma)
        search: Look for elements containing the specified string
        q: Query to filter results

    Returns:
        Dictionary with agents without group
    """
    try:
        logger.debug("Fetching agents without group")
        return get_manager_client().get(
            "agents/no_group",
            pretty=pretty,
            wait_for_complete=wait_for_complete,
            offset=offset,
            limit=limit,
            select=select,
            sort=sort,
            search=search,
            q=q
        )
    except Exception as e:
        return handle_secure_error(e, "fetching agents without group")

@mcp.tool()
def get_list_outdated_agents(
    pretty: bool = False,
    wait_for_complete: bool = False,
    offset: int = 0,
    limit: int = 500,
    sort: Optional[str] = None,
    search: Optional[str] = None,
    select: Optional[str] = None,
    q: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get outdated agents.

    Args:
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        offset: First element to return in the collection
        limit: Maximum number of elements to return
        sort: Fields to sort by (separated by comma)
        search: Look for elements containing the specified string
        select: Fields to return (separated by comma)
        q: Query to filter results

    Returns:
        Dictionary with outdated agents
    """
    try:
        logger.debug("Fetching outdated agents")
        return get_manager_client().get(
            "agents/outdated",
            pretty=pretty,
            wait_for_complete=wait_for_complete,
            offset=offset,
            limit=limit,
            sort=sort,
            search=search,
            select=select,
            q=q
        )
    except Exception as e:
        return handle_secure_error(e, "fetching outdated agents")

@mcp.tool()
def get_list_agents_distinct(
    pretty: bool = False,
    wait_for_complete: bool = False,
    fields: Optional[List[str]] = None,
    offset: int = 0,
    limit: int = 500,
    sort: Optional[str] = None,
    search: Optional[str] = None,
    q: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get distinct values for specified fields in agents.

    Args:
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        fields: List of fields to get distinct values for
        offset: First element to return in the collection
        limit: Maximum number of elements to return
        sort: Fields to sort by (separated by comma)
        search: Look for elements containing the specified string
        q: Query to filter results

    Returns:
        Dictionary with distinct agent field values
    """
    try:
        logger.debug("Fetching distinct agent values")
        params = {
            'pretty': pretty,
            'wait_for_complete': wait_for_complete,
            'offset': offset,
            'limit': limit,
            'sort': sort,
            'search': search,
            'q': q
        }

        if fields:
            params['fields'] = ','.join(fields)
        return get_manager_client().get("agents/stats/distinct", **params)
    except Exception as e:
        return handle_secure_error(e, "fetching distinct agent values")

@mcp.tool()
def get_summarize_agents_os(
    pretty: bool = False,
    wait_for_complete: bool = False
) -> Dict[str, Any]:
    """
    Get summary of agents by OS.

    Args:
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response

    Returns:
        Dictionary with OS summary of agents
    """
    try:
        logger.debug("Fetching agents OS summary")
        return get_manager_client().get("overview/agents", pretty=pretty, wait_for_complete=wait_for_complete)
    except Exception as e:
        return handle_secure_error(e, "fetching agents OS summary")

@mcp.tool()
def get_summarize_agents_status(
    pretty: bool = False,
    wait_for_complete: bool = False
) -> Dict[str, Any]:
    """
    Get summary of agents by status.

    Args:
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response

    Returns:
        Dictionary with status summary of agents
    """
    try:
        logger.debug("Fetching agents status summary")
        return get_manager_client().get("overview/agents", pretty=pretty, wait_for_complete=wait_for_complete)
    except Exception as e:
        return handle_secure_error(e, "fetching agents status summary")

@mcp.tool()
def get_agents_info(
    pretty: bool = False,
    wait_for_complete: bool = False,
    agents_list: Optional[List[str]] = None,
    offset: int = 0,
    limit: int = 500,
    select: Optional[str] = None,
    sort: Optional[str] = None,
    search: Optional[str] = None,
    status: Optional[List[str]] = None,
    q: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get basic information about Wazuh agents.
    This is an alias for get_list_agents with commonly used parameters.

    Args:
        pretty (bool): Show results in human-readable format
        wait_for_complete (bool): Wait for task completion
        agents_list (List[str], optional): List of agent IDs to retrieve
        offset (int): First element to return in the collection
        limit (int): Maximum number of elements to return
        select (str, optional): Select which fields to return
        sort (str, optional): Criteria to use for sorting results
        search (str, optional): Look for elements with the specified string
        status (List[str], optional): Filter by agent status (active, pending, never_connected, disconnected)
        q (str, optional): Query to filter results

    Returns:
        Dict containing agent information
    """
    try:
        params = {
            'pretty': pretty,
            'wait_for_complete': wait_for_complete,
            'offset': offset,
            'limit': limit,
            'select': select,
            'sort': sort,
            'search': search,
            'q': q,
            'agents_list': ','.join(agents_list) if agents_list else None,
            'status': ','.join(status) if status else None,
        }
        # Hapus parameter None agar tidak dikirim
        params = {k: v for k, v in params.items() if v is not None}
        return get_manager_client().get("agents", **params)
    except Exception as e:
        return handle_secure_error(e, "getting agents info")
