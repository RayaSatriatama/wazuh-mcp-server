"""
Wazuh Overview Module - MCP Tools and Resources for Overview Data
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
mcp = FastMCP("wazuh_overview_mcp")

# Initialize logger
logger = logging.getLogger(__name__)

# Initialize API client and config

api_client = get_manager_client()

# ====== MCP TOOLS ======

@mcp.tool()
def get_agents_overview(
        pretty: bool = False,
        wait_for_complete: bool = False,
        select: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Return agent summary information.

    Args:
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        select: Fields to return

    Returns:
        Dictionary with agent summary information
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'select': ','.join(select) if select else None,
    }

    # Remove None values
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.debug("Fetching agent overview from /overview/agents")
        endpoint = "/overview/agents"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        return handle_secure_error(e, "fetching agent overview")

