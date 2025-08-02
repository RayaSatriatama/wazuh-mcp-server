"""
Wazuh Groups Module - MCP Tools and Resources for Wazuh Groups API
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
mcp = FastMCP("wazuh_groups_mcp")

# Initialize logger
logger = logging.getLogger(__name__)

# Initialize API client and config

api_client = get_manager_client()

# ====== MCP TOOLS ======
@mcp.tool()
def get_groups(
        pretty: bool = False,
        wait_for_complete: bool = False,
        groups_list: Optional[List[str]] = None,
        offset: int = 0,
        limit: int = 500,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        hash_filter: Optional[str] = None,
        q: Optional[str] = None,
        select: Optional[List[str]] = None,
        distinct: bool = False
) -> Dict[str, Any]:
    """
    Get information about all groups or a list of them.
    Corresponds to GET /groups.

    Args:
        pretty (bool): Show results in human-readable format.
        wait_for_complete (bool): Disable timeout response.
        groups_list (Optional[List[str]]): List of group IDs.
        offset (int): First element to return.
        limit (int): Maximum number of elements to return.
        sort (Optional[str]): Fields to sort by.
        search (Optional[str]): Look for elements containing the specified string.
        hash_filter (Optional[str]): Filter by hash algorithm (md5, sha1, etc.). Named to avoid conflict with Python's hash().
        q (Optional[str]): Query to filter results.
        select (Optional[List[str]]): Fields to return.
        distinct (bool): Look for distinct values.

    Returns:
        Dict[str, Any]: Dictionary with groups information.
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'groups_list': ','.join(groups_list) if groups_list else None,
        'offset': offset,
        'limit': limit,
        'sort': sort,
        'search': search,
        'hash': hash_filter,
        'q': q,
        'select': ','.join(select) if select else None,
        'distinct': distinct
    }
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.debug("Fetching groups information from /groups")
        return api_client._make_request("GET", "/groups", params=params)
    except Exception as e:
        return handle_secure_error(e, "fetching groups information")

@mcp.tool()
def get_agents_in_group(
        group_id: str,
        pretty: bool = False,
        wait_for_complete: bool = False,
        offset: int = 0,
        limit: int = 500,
        select: Optional[List[str]] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        status: Optional[List[str]] = None,
        q: Optional[str] = None,
        distinct: bool = False
) -> Dict[str, Any]:
    """
    Return the list of agents that belong to the specified group.
    Corresponds to GET /groups/{group_id}/agents.

    Args:
        group_id (str): The ID of the group to query.
        pretty (bool): Show results in human-readable format.
        wait_for_complete (bool): Disable timeout response.
        offset (int): First element to return.
        limit (int): Maximum number of elements to return.
        select (Optional[List[str]]): Fields to return.
        sort (Optional[str]): Fields to sort by.
        search (Optional[str]): Look for elements containing the specified string.
        status (Optional[List[str]]): Filter by agent status (e.g., active, pending).
        q (Optional[str]): Query to filter results.
        distinct (bool): Look for distinct values.

    Returns:
        Dict[str, Any]: Dictionary with agents in the group.
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'offset': offset,
        'limit': limit,
        'select': ','.join(select) if select else None,
        'sort': sort,
        'search': search,
        'status': ','.join(status) if status else None,
        'q': q,
        'distinct': distinct
    }
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.info(f"Fetching agents in group {group_id} from /groups/{group_id}/agents")
        return api_client._make_request("GET", f"/groups/{group_id}/agents", params=params)
    except Exception as e:
        return handle_secure_error(e, f"fetching agents in group {group_id}")

@mcp.tool()
def get_group_configuration(
        group_id: str,
        pretty: bool = False,
        wait_for_complete: bool = False,
        offset: int = 0,
        limit: int = 500
) -> Dict[str, Any]:
    """
    Return the group configuration (agent.conf).
    Corresponds to GET /groups/{group_id}/configuration.
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'offset': offset,
        'limit': limit
    }
    try:
        logger.info(f"Fetching configuration for group {group_id}")
        return api_client._make_request("GET", f"/groups/{group_id}/configuration", params=params)
    except Exception as e:
        return handle_secure_error(e, f"fetching configuration for group {group_id}")

@mcp.tool()
def get_group_files(
        group_id: str,
        pretty: bool = False,
        wait_for_complete: bool = False,
        offset: int = 0,
        limit: int = 500,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        hash: Optional[str] = None,
        q: Optional[str] = None,
        select: Optional[List[str]] = None,
        distinct: bool = False
) -> Dict[str, Any]:
    """
    Return the files placed under the group directory.

    Args:
        group_id: Group ID
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        offset: First element to return
        limit: Maximum number of elements to return
        sort: Fields to sort by
        search: Look for elements containing the specified string
        hash: Filter by hash
        q: Query to filter results by. For example q="status=active"
        select: Fields to return
        distinct: Look for distinct values

    Returns:
        Dictionary with group files
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'offset': offset,
        'limit': limit,
        'sort': sort,
        'search': search,
        'hash': hash,
        'q': q,
        'select': ','.join(select) if select else None,
        'distinct': distinct
    }

    # Remove None values
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.info(f"Fetching files for group {group_id}")
        endpoint = f"/groups/{group_id}/files"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        logger.error(f"Error fetching group files: {str(e)}")
        return {"error": str(e)}

@mcp.tool()
def get_group_file_content(
        group_id: str,
        file_name: str,
        pretty: bool = False,
        wait_for_complete: bool = False,
        type_content: Optional[List[str]] = None,
        raw: bool = False
) -> Dict[str, Any]:
    """
    Return the content of the specified group file.

    Args:
        group_id: Group ID
        file_name: Name of the file
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        type_content: Type of file (conf, rootkit_files, rootkit_trojans, rcl)
        raw: Format response in plain text

    Returns:
        Dictionary with file content
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'type_content': ','.join(type_content) if type_content else None,
        'raw': raw
    }
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.info(f"Fetching content of file {file_name} from group {group_id}")
        endpoint = f"/groups/{group_id}/files/{file_name}"
        return api_client._make_request("GET", endpoint, params=params, expect_raw=raw)
    except Exception as e:
        return handle_secure_error(e, f"fetching content of file {file_name} from group {group_id}")