"""
Wazuh Lists Module - MCP Tools and Resources for Wazuh CDB Lists API
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
mcp = FastMCP("wazuh_lists_mcp")

# Initialize logger
logger = logging.getLogger(__name__)

# Initialize API client and config

api_client = get_manager_client()

# ====== MCP TOOLS ======
@mcp.tool()
def get_cdb_lists_info(
        pretty: bool = False,
        wait_for_complete: bool = False,
        offset: int = 0,
        limit: int = 500,
        select: Optional[List[str]] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        relative_dirname: Optional[str] = None,
        filename: Optional[List[str]] = None,
        q: Optional[str] = None,
        distinct: bool = False
) -> Dict[str, Any]:
    """
    Return the content of all CDB lists (key-value pairs).
    Corresponds to GET /lists.
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'offset': offset,
        'limit': limit,
        'select': ','.join(select) if select else None,
        'sort': sort,
        'search': search,
        'relative_dirname': relative_dirname,
        'filename': ','.join(filename) if filename else None,
        'q': q,
        'distinct': distinct
    }
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.debug("Fetching CDB lists content from /lists")
        return api_client._make_request("GET", "/lists", params=params)
    except Exception as e:
        return handle_secure_error(e, "fetching CDB lists content")

@mcp.tool()
def get_cdb_lists_files(
        pretty: bool = False,
        wait_for_complete: bool = False,
        offset: int = 0,
        limit: int = 500,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        relative_dirname: Optional[str] = None,
        filename: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Return the path and metadata of all CDB list files.
    Corresponds to GET /lists/files.
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'offset': offset,
        'limit': limit,
        'sort': sort,
        'search': search,
        'relative_dirname': relative_dirname,
        'filename': ','.join(filename) if filename else None
    }
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.debug("Fetching CDB lists files from /lists/files")
        return api_client._make_request("GET", "/lists/files", params=params)
    except Exception as e:
        return handle_secure_error(e, "fetching CDB list files")

@mcp.tool()
def get_cdb_list_file_content(
        filename: str,
        pretty: bool = False,
        wait_for_complete: bool = False,
        raw: bool = False
) -> Dict[str, Any]:
    """
    Return the content of a specific CDB list file.
    Corresponds to GET /lists/files/{filename}.
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'raw': raw
    }

    try:
        logger.info(f"Fetching content of CDB list file: {filename}")
        endpoint = f"/lists/files/{filename}"
        return api_client._make_request("GET", endpoint, params=params, expect_raw=raw)
    except Exception as e:
        return handle_secure_error(e, f"fetching content of CDB list file {filename}")