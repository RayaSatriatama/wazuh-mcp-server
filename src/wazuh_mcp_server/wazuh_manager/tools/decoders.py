"""
Wazuh Decoders Module - MCP Tools and Resources for Wazuh Decoders API
"""
import json
import re
from datetime import datetime
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
mcp = FastMCP("wazuh_decoders_mcp")

# Initialize logger
logger = logging.getLogger(__name__)

# Initialize API client and config

api_client = get_manager_client()

# ====== MCP TOOLS ======

@mcp.tool()
def get_list_decoders(
        pretty: bool = False,
        wait_for_complete: bool = False,
        offset: int = 0,
        limit: int = 500,
        select: Optional[List[str]] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        q: Optional[str] = None,
        decoder_names: Optional[List[str]] = None,
        filename: Optional[List[str]] = None,
        relative_dirname: Optional[str] = None,
        status: Optional[str] = None,
        distinct: bool = False
) -> Dict[str, Any]:
    """
    Return information about all decoders.
    Corresponds to GET /decoders.

    Args:
        pretty (bool): Show results in human-readable format.
        wait_for_complete (bool): Disable timeout response.
        offset (int): First element to return in the collection.
        limit (int): Maximum number of elements to return.
        select (Optional[List[str]]): Fields to return.
        sort (Optional[str]): Fields to sort by.
        search (Optional[str]): Look for elements containing the specified string.
        q (Optional[str]): Query to filter results.
        decoder_names (Optional[List[str]]): Filter by a list of decoder names.
        filename (Optional[List[str]]): Filter by a list of filenames.
        relative_dirname (Optional[str]): Filter by relative directory name.
        status (Optional[str]): Filter by status ("enabled", "disabled", "all").
        distinct (bool): Look for distinct values.

    Returns:
        Dict[str, Any]: Dictionary with decoders information.
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'offset': offset,
        'limit': limit,
        'select': ','.join(select) if select else None,
        'sort': sort,
        'search': search,
        'q': q,
        'relative_dirname': relative_dirname,
        'status': status,
        'distinct': distinct
    }
    if decoder_names:
        params['names'] = ','.join(decoder_names)
    if filename:
        params['filename'] = ','.join(filename)
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.debug("Fetching decoders list from /decoders")
        return api_client._make_request("GET", "/decoders", params=params)
    except Exception as e:
        return handle_secure_error(e, "fetching decoders list")

@mcp.tool()
def get_decoder_files(
        pretty: bool = False,
        wait_for_complete: bool = False,
        offset: int = 0,
        limit: int = 500,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        status: Optional[str] = None,
        filename: Optional[List[str]] = None,
        relative_dirname: Optional[str] = None,
        q: Optional[str] = None,
        select: Optional[List[str]] = None,
        distinct: bool = False
) -> Dict[str, Any]:
    """
    Return information about all decoder files.
    Corresponds to GET /decoders/files.

    Args:
        pretty (bool): Show results in human-readable format.
        wait_for_complete (bool): Disable timeout response.
        offset (int): First element to return.
        limit (int): Maximum number of elements to return.
        sort (Optional[str]): Fields to sort by.
        search (Optional[str]): Look for elements containing the specified string.
        status (Optional[str]): Filter by status ("enabled", "disabled", "all").
        filename (Optional[List[str]]): Filter by a list of filenames.
        relative_dirname (Optional[str]): Filter by relative directory name.
        q (Optional[str]): Query to filter results.
        select (Optional[List[str]]): Fields to return.
        distinct (bool): Look for distinct values.

    Returns:
        Dict[str, Any]: Dictionary with decoder files information.
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'offset': offset,
        'limit': limit,
        'sort': sort,
        'search': search,
        'status': status,
        'relative_dirname': relative_dirname,
        'q': q,
        'distinct': distinct
    }
    if filename:
        params['filename'] = ','.join(filename)
    if select:
        params['select'] = ','.join(select)
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.debug("Fetching decoder files from /decoders/files")
        return api_client._make_request("GET", "/decoders/files", params=params)
    except Exception as e:
        return handle_secure_error(e, "fetching decoder files")

@mcp.tool()
def get_decoder_file_content(
        filename: str,
        pretty: bool = False,
        wait_for_complete: bool = False,
        raw: bool = False,
        relative_dirname: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get the content of a specified decoder file.
    Corresponds to GET /decoders/files/{filename}.

    Args:
        filename (str): Name of the decoder file.
        pretty (bool): Show results in human-readable format.
        wait_for_complete (bool): Disable timeout response.
        raw (bool): Respond in plain text.
        relative_dirname (Optional[str]): Relative directory of the file.

    Returns:
        Dict[str, Any]: Dictionary with decoder file content.
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'raw': raw,
        'relative_dirname': relative_dirname
    }
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.info(f"Fetching content for decoder file: {filename}")
        endpoint = f"/decoders/files/{filename}"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        return handle_secure_error(e, f"fetching content for decoder file {filename}")

@mcp.tool()
def get_parent_decoders(
        pretty: bool = False,
        wait_for_complete: bool = False,
        offset: int = 0,
        limit: int = 500,
        select: Optional[List[str]] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None
) -> Dict[str, Any]:
    """
    Return information about all parent decoders.
    Corresponds to GET /decoders/parents.

    Args:
        pretty (bool): Show results in human-readable format.
        wait_for_complete (bool): Disable timeout response.
        offset (int): First element to return.
        limit (int): Maximum number of elements to return.
        select (Optional[List[str]]): Fields to return.
        sort (Optional[str]): Fields to sort by.
        search (Optional[str]): Look for elements containing the specified string.

    Returns:
        Dict[str, Any]: Dictionary with parent decoders information.
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'offset': offset,
        'limit': limit,
        'select': ','.join(select) if select else None,
        'sort': sort,
        'search': search
    }
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.debug("Fetching parent decoders from /decoders/parents")
        return api_client._make_request("GET", "/decoders/parents", params=params)
    except Exception as e:
        return handle_secure_error(e, "fetching parent decoders")
