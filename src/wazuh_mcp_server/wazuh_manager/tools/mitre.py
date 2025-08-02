"""
Wazuh MITRE Module - MCP Tools and Resources for MITRE ATT&CK framework integration
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
mcp = FastMCP("wazuh_mitre_mcp")

# Initialize logger
logger = logging.getLogger(__name__)

# Initialize API client and config

api_client = get_manager_client()

# ====== MCP TOOLS ======

@mcp.tool()
def get_mitre_groups(
        pretty: bool = False,
        wait_for_complete: bool = False,
        offset: int = 0,
        limit: int = 500,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[List[str]] = None,
        q: Optional[str] = None,
        group_ids: Optional[List[str]] = None,
        distinct: bool = False
) -> Dict[str, Any]:
    """
    Return the groups from MITRE database.

    Args:
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        offset: First element to return
        limit: Maximum number of elements to return
        sort: Fields to sort by
        search: Look for elements containing the specified string
        select: Fields to return
        q: Query to filter results
        group_ids: List of MITRE's group IDs
        distinct: Look for distinct values

    Returns:
        Dictionary with MITRE groups information
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'offset': offset,
        'limit': limit,
        'sort': sort,
        'search': search,
        'select': ','.join(select) if select else None,
        'q': q,
        'group_ids': ','.join(group_ids) if group_ids else None,
        'distinct': distinct
    }
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.debug("Fetching MITRE groups from /mitre/groups")
        return api_client._make_request("GET", "/mitre/groups", params=params)
    except Exception as e:
        return handle_secure_error(e, "fetching MITRE groups")

@mcp.tool()
def get_mitre_metadata(
        pretty: bool = False,
        wait_for_complete: bool = False
) -> Dict[str, Any]:
    """
    Return the metadata from MITRE database.

    Args:
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response

    Returns:
        Dictionary with MITRE metadata
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete
    }
    try:
        logger.debug("Fetching MITRE metadata from /mitre/metadata")
        return api_client._make_request("GET", "/mitre/metadata", params=params)
    except Exception as e:
        return handle_secure_error(e, "fetching MITRE metadata")

@mcp.tool()
def get_mitre_mitigations(
        pretty: bool = False,
        wait_for_complete: bool = False,
        offset: int = 0,
        limit: int = 500,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[List[str]] = None,
        q: Optional[str] = None,
        mitigation_ids: Optional[List[str]] = None,
        distinct: bool = False
) -> Dict[str, Any]:
    """
    Return the mitigations from MITRE database.

    Args:
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        offset: First element to return
        limit: Maximum number of elements to return
        sort: Fields to sort by
        search: Look for elements containing the specified string
        select: Fields to return
        q: Query to filter results
        mitigation_ids: List of MITRE's mitigation IDs
        distinct: Look for distinct values

    Returns:
        Dictionary with MITRE mitigations
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'offset': offset,
        'limit': limit,
        'sort': sort,
        'search': search,
        'select': ','.join(select) if select else None,
        'q': q,
        'mitigation_ids': ','.join(mitigation_ids) if mitigation_ids else None,
        'distinct': distinct
    }
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.debug("Fetching MITRE mitigations from /mitre/mitigations")
        return api_client._make_request("GET", "/mitre/mitigations", params=params)
    except Exception as e:
        return handle_secure_error(e, "fetching MITRE mitigations")

@mcp.tool()
def get_mitre_references(
        pretty: bool = False,
        wait_for_complete: bool = False,
        reference_ids: Optional[List[str]] = None,
        offset: int = 0,
        limit: int = 500,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[List[str]] = None,
        q: Optional[str] = None
) -> Dict[str, Any]:
    """
    Return the references from MITRE database.

    Args:
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        reference_ids: List of MITRE's references IDs
        offset: First element to return
        limit: Maximum number of elements to return
        sort: Fields to sort by
        search: Look for elements containing the specified string
        select: Fields to return
        q: Query to filter results

    Returns:
        Dictionary with MITRE references
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'reference_ids': ','.join(reference_ids) if reference_ids else None,
        'offset': offset,
        'limit': limit,
        'sort': sort,
        'search': search,
        'select': ','.join(select) if select else None,
        'q': q
    }
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.debug("Fetching MITRE references from /mitre/references")
        return api_client._make_request("GET", "/mitre/references", params=params)
    except Exception as e:
        return handle_secure_error(e, "fetching MITRE references")

@mcp.tool()
def get_mitre_software(
        pretty: bool = False,
        wait_for_complete: bool = False,
        software_ids: Optional[List[str]] = None,
        offset: int = 0,
        limit: int = 500,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[List[str]] = None,
        q: Optional[str] = None,
        distinct: bool = False
) -> Dict[str, Any]:
    """
    Return the software from MITRE database.

    Args:
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        software_ids: List of MITRE's software IDs
        offset: First element to return
        limit: Maximum number of elements to return
        sort: Fields to sort by
        search: Look for elements containing the specified string
        select: Fields to return
        q: Query to filter results
        distinct: Look for distinct values

    Returns:
        Dictionary with MITRE software information
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'software_ids': ','.join(software_ids) if software_ids else None,
        'offset': offset,
        'limit': limit,
        'sort': sort,
        'search': search,
        'select': ','.join(select) if select else None,
        'q': q,
        'distinct': distinct
    }
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.debug("Fetching MITRE software from /mitre/software")
        return api_client._make_request("GET", "/mitre/software", params=params)
    except Exception as e:
        return handle_secure_error(e, "fetching MITRE software")

@mcp.tool()
def get_mitre_tactics(
        pretty: bool = False,
        wait_for_complete: bool = False,
        tactic_ids: Optional[List[str]] = None,
        offset: int = 0,
        limit: int = 500,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[List[str]] = None,
        q: Optional[str] = None,
        distinct: bool = False
) -> Dict[str, Any]:
    """
    Return the tactics from MITRE database.

    Args:
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        tactic_ids: List of MITRE's tactic IDs
        offset: First element to return
        limit: Maximum number of elements to return
        sort: Fields to sort by
        search: Look for elements containing the specified string
        select: Fields to return
        q: Query to filter results
        distinct: Look for distinct values

    Returns:
        Dictionary with MITRE tactics information
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'tactic_ids': ','.join(tactic_ids) if tactic_ids else None,
        'offset': offset,
        'limit': limit,
        'sort': sort,
        'search': search,
        'select': ','.join(select) if select else None,
        'q': q,
        'distinct': distinct
    }
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.debug("Fetching MITRE tactics from /mitre/tactics")
        return api_client._make_request("GET", "/mitre/tactics", params=params)
    except Exception as e:
        return handle_secure_error(e, "fetching MITRE tactics")

@mcp.tool()
def get_mitre_techniques(
        pretty: bool = False,
        wait_for_complete: bool = False,
        offset: int = 0,
        limit: int = 500,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[List[str]] = None,
        q: Optional[str] = None,
        technique_ids: Optional[List[str]] = None,
        distinct: bool = False
) -> Dict[str, Any]:
    """
    Return the techniques from MITRE database.

    Args:
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        offset: First element to return
        limit: Maximum number of elements to return
        sort: Fields to sort by
        search: Look for elements containing the specified string
        select: Fields to return
        q: Query to filter results
        technique_ids: List of MITRE's technique IDs
        distinct: Look for distinct values

    Returns:
        Dictionary with MITRE techniques information
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'offset': offset,
        'limit': limit,
        'sort': sort,
        'search': search,
        'select': ','.join(select) if select else None,
        'q': q,
        'technique_ids': ','.join(technique_ids) if technique_ids else None,
        'distinct': distinct
    }
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.debug("Fetching MITRE techniques from /mitre/techniques")
        return api_client._make_request("GET", "/mitre/techniques", params=params)
    except Exception as e:
        return handle_secure_error(e, "fetching MITRE techniques")