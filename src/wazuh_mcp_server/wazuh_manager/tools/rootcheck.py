"""
Wazuh Rootcheck Module - MCP Tools and Resources for Rootcheck Data
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
mcp = FastMCP("wazuh_rootcheck_mcp")

# Initialize logger
logger = logging.getLogger(__name__)

# Initialize API client and config

api_client = get_manager_client()

# ====== MCP TOOLS ======

@mcp.tool()
def get_rootcheck_results(
        agent_id: str,
        pretty: bool = False,
        wait_for_complete: bool = False,
        offset: int = 0,
        limit: int = 500,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[List[str]] = None,
        status: Optional[str] = None,
        q: Optional[str] = None,
        distinct: bool = False,
        pci_dss: Optional[str] = None,
        cis: Optional[str] = None
) -> Dict[str, Any]:
    """
    Return the rootcheck database of an agent.

    Args:
        agent_id: Agent ID
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        offset: First element to return
        limit: Maximum number of elements to return
        sort: Fields to sort by
        search: Look for elements containing the specified string
        select: Fields to return
        status: Filter by status (outstanding, solved, all)
        q: Query to filter results
        distinct: Look for distinct values
        pci_dss: Filter by PCI DSS requirement
        cis: Filter by CIS requirement

    Returns:
        Dictionary with rootcheck results
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'offset': offset,
        'limit': limit,
        'sort': sort,
        'search': search,
        'select': ','.join(select) if select else None,
        'status': status,
        'q': q,
        'distinct': distinct,
        'pci_dss': pci_dss,
        'cis': cis
    }

    # Remove None values
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.info(f"Fetching rootcheck results for agent {agent_id}")
        endpoint = f"/rootcheck/{agent_id}"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        return handle_secure_error(e, f"fetching rootcheck results for agent {agent_id}")

@mcp.tool()
def get_rootcheck_last_scan(
        agent_id: str,
        pretty: bool = False,
        wait_for_complete: bool = False
) -> Dict[str, Any]:
    """
    Return the timestamp of the last rootcheck scan of an agent.

    Args:
        agent_id: Agent ID
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response

    Returns:
        Dictionary with last scan datetime
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete
    }

    try:
        logger.info(f"Fetching rootcheck last scan datetime for agent {agent_id}")
        endpoint = f"/rootcheck/{agent_id}/last_scan"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        return handle_secure_error(e, f"fetching rootcheck last scan for agent {agent_id}")