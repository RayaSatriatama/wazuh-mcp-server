"""
Wazuh Syscheck Module - MCP Tools and Resources for Syscheck/FIM API
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
mcp = FastMCP("wazuh_syscheck_mcp")

# Initialize logger
logger = logging.getLogger(__name__)

# Initialize API client and config

api_client = get_manager_client()

# ====== MCP TOOLS ======

@mcp.tool()
def get_syscheck_results(
        agent_id: str,
        pretty: bool = False,
        wait_for_complete: bool = False,
        offset: int = 0,
        limit: int = 500,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[List[str]] = None,
        file: Optional[str] = None,
        arch: Optional[str] = None,
        value_name: Optional[str] = None,
        value_type: Optional[str] = None,
        type: Optional[str] = None,
        summary: bool = False,
        md5: Optional[str] = None,
        sha1: Optional[str] = None,
        sha256: Optional[str] = None,
        hash: Optional[str] = None,
        distinct: bool = False,
        q: Optional[str] = None
) -> Dict[str, Any]:
    """
    Return FIM findings in the specified agent.

    Args:
        agent_id: Agent ID.
        pretty: Show results in human-readable format.
        wait_for_complete: Disable timeout response.
        offset: First element to return.
        limit: Maximum number of elements to return.
        sort: Sort the collection by a field or fields.
        search: Look for elements containing the specified string.
        select: Select which fields to return.
        file: Filter by full path.
        arch: Filter by architecture.
        value_name: Filter by value name.
        value_type: Filter by value type.
        type: Filter by file type.
        summary: Return a summary grouping by filename.
        md5: Filter files with the specified MD5 checksum.
        sha1: Filter files with the specified SHA1 checksum.
        sha256: Filter files with the specified SHA256 checksum.
        hash: Filter files with the specified hash (md5, sha256 or sha1).
        distinct: Look for distinct values.
        q: Query to filter results.

    Returns:
        Dictionary with syscheck results.
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'offset': offset,
        'limit': limit,
        'sort': sort,
        'search': search,
        'select': ','.join(select) if select else None,
        'file': file,
        'arch': arch,
        'value.name': value_name,
        'value.type': value_type,
        'type': type,
        'summary': summary,
        'md5': md5,
        'sha1': sha1,
        'sha256': sha256,
        'hash': hash,
        'distinct': distinct,
        'q': q
    }

    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.info(f"Fetching syscheck results for agent {agent_id}")
        endpoint = f"/syscheck/{agent_id}"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        return handle_secure_error(e, f"fetching syscheck results for agent {agent_id}")

@mcp.tool()
def get_syscheck_last_scan(
        agent_id: str,
        pretty: bool = False,
        wait_for_complete: bool = False
) -> Dict[str, Any]:
    """
    Return when the last syscheck scan started and ended.

    Args:
        agent_id: Agent ID.
        pretty: Show results in human-readable format.
        wait_for_complete: Disable timeout response.

    Returns:
        Dictionary with last scan information.
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete
    }

    try:
        logger.info(f"Fetching last syscheck scan information for agent {agent_id}")
        endpoint = f"/syscheck/{agent_id}/last_scan"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        return handle_secure_error(e, f"fetching last syscheck scan for agent {agent_id}")