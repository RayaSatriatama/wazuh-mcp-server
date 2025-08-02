"""
Wazuh Tasks Module - MCP Tools and Resources for Wazuh Tasks API
"""
import json
import re
import datetime
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
    sensitive_patterns = [(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.)\d{1,3}\b', r'\1XXX')]
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
mcp = FastMCP("wazuh_tasks_mcp")

# Initialize logger
logger = logging.getLogger(__name__)

# Initialize API client and config

api_client = get_manager_client()

# ====== MCP TOOLS ======

@mcp.tool()
def get_tasks_status(
        pretty: bool = False,
        wait_for_complete: bool = False,
        offset: int = 0,
        limit: int = 500,
        q: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[List[str]] = None,
        sort: Optional[str] = None,
        agents_list: Optional[List[str]] = None,
        tasks_list: Optional[List[str]] = None,
        command: Optional[str] = None,
        node: Optional[str] = None,
        module: Optional[str] = None,
        status: Optional[str] = None
) -> Dict[str, Any]:
    """
    Returns all available information about the specified tasks.

    Args:
        pretty: Show results in human-readable format.
        wait_for_complete: Disable timeout response.
        offset: First element to return.
        limit: Maximum number of elements to return.
        q: Query to filter results.
        search: Look for elements containing the specified string.
        select: Select which fields to return.
        sort: Sort the collection by a field or fields.
        agents_list: List of agent IDs.
        tasks_list: List of task IDs.
        command: Filter by command.
        node: Show results filtered by node.
        module: Show results filtered by module.
        status: Filter by status.

    Returns:
        Dictionary with tasks information.
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'offset': offset,
        'limit': limit,
        'q': q,
        'search': search,
        'select': ','.join(select) if select else None,
        'sort': sort,
        'agents_list': ','.join(agents_list) if agents_list else None,
        'tasks_list': ','.join(tasks_list) if tasks_list else None,
        'command': command,
        'node': node,
        'module': module,
        'status': status
    }

    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.debug("Fetching tasks status information")
        endpoint = "/tasks/status"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        return handle_secure_error(e, "fetching tasks status")
