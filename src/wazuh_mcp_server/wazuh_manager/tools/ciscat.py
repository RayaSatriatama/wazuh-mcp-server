"""
Wazuh CIS-CAT Module - MCP Tools and Resources for CIS-CAT results
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
mcp = FastMCP("wazuh_ciscat_mcp")

# Initialize logger
logger = logging.getLogger(__name__)

# Initialize API client and config

api_client = get_manager_client()

# ====== MCP TOOLS ======

@mcp.tool()
def get_ciscat_results(
        agent_id: str,
        pretty: bool = False,
        wait_for_complete: bool = False,
        offset: int = 0,
        limit: int = 500,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[List[str]] = None,
        benchmark: Optional[str] = None,
        profile: Optional[str] = None,
        passed: Optional[int] = None,
        fail: Optional[int] = None,
        error: Optional[int] = None,
        notchecked: Optional[int] = None,
        unknown: Optional[int] = None,
        score: Optional[int] = None,
        q: Optional[str] = None
) -> Dict[str, Any]:
    """
    Retrieve CIS-CAT scan results from a specific agent.

    Args:
        agent_id: Agent ID. All possible values from 000 onwards.
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        offset: First element to return in the collection
        limit: Maximum number of elements to return
        sort: Fields to sort by (separated by comma)
        search: Look for elements containing the specified string
        select: Fields to return (separated by comma)
        benchmark: Filter by benchmark type
        profile: Filter by evaluated profile
        passed: Filter by passed checks
        fail: Filter by failed checks
        error: Filter by encountered errors
        notchecked: Filter by not checked
        unknown: Filter by unknown results
        score: Filter by final score
        q: Query to filter results

    Returns:
        Dictionary with CIS-CAT scan results
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'offset': offset,
        'limit': limit,
        'sort': sort,
        'search': search,
        'select': ','.join(select) if select else None,
        'benchmark': benchmark,
        'profile': profile,
        'pass': passed,  # 'pass' is a keyword in Python, use 'passed' in function arg
        'fail': fail,
        'error': error,
        'notchecked': notchecked,
        'unknown': unknown,
        'score': score,
        'q': q
    }

    # Remove None values
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.info(f"Fetching CIS-CAT results for agent {agent_id}")
        endpoint = f"/ciscat/{agent_id}/results"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        return handle_secure_error(e, f"fetching CIS-CAT results for agent {agent_id}")
