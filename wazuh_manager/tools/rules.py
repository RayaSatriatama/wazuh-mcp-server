"""
Wazuh Rules Module - MCP Tools and Resources for Wazuh Rules API
"""
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
mcp = FastMCP("wazuh_rules_mcp")

# Initialize logger
logger = logging.getLogger(__name__)

# Initialize API client and config

api_client = get_manager_client()

# ====== MCP TOOLS ======

@mcp.tool()
def get_rules(
        pretty: bool = False,
        wait_for_complete: bool = False,
        rule_ids: Optional[List[str]] = None,
        offset: int = 0,
        limit: int = 500,
        select: Optional[List[str]] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        filename: Optional[List[str]] = None,
        relative_dirname: Optional[str] = None,
        status: Optional[str] = None,
        group: Optional[str] = None,
        level: Optional[Union[int, str]] = None,
        q: Optional[str] = None,
        pci_dss: Optional[str] = None,
        gdpr: Optional[str] = None,
        hipaa: Optional[str] = None,
        nist_800_53: Optional[str] = None,
        tsc: Optional[str] = None,
        mitre: Optional[str] = None,
        distinct: bool = False
) -> Dict[str, Any]:
    """
    Return a list of all available rules.

    Args:
        pretty: Show results in human-readable format.
        wait_for_complete: Disable timeout response.
        rule_ids: List of rule IDs.
        offset: First element to return.
        limit: Maximum number of elements to return.
        select: List of fields to return.
        sort: Sorts the results by the specified field.
        search: Looks for elements with the specified string.
        filename: Filters by filename. Can be a list.
        relative_dirname: Filters by relative directory name.
        status: Filters by rule status. Allowed values: 'enabled', 'disabled', 'all'.
        group: Filters by rule group.
        level: Filters by rule level. Can be a single level or a range (e.g., '8' or '8-10').
        q: Query to filter results.
        pci_dss: Filters by PCI DSS requirement.
        gdpr: Filters by GDPR requirement.
        hipaa: Filters by HIPAA requirement.
        nist_800_53: Filters by NIST 800-53 requirement.
        tsc: Filters by TSC requirement.
        mitre: Filters by MITRE requirement.
        distinct: Looks for distinct values.

    Returns:
        A dictionary containing the list of rules.
    """
    endpoint = "/rules"
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'rule_ids': ','.join(rule_ids) if rule_ids else None,
        'offset': offset,
        'limit': limit,
        'select': ','.join(select) if select else None,
        'sort': sort,
        'search': search,
        'filename': ','.join(filename) if filename else None,
        'relative_dirname': relative_dirname,
        'status': status,
        'group': group,
        'level': level,
        'q': q,
        'pci_dss': pci_dss,
        'gdpr': gdpr,
        'hipaa': hipaa,
        'nist-800-53': nist_800_53,
        'tsc': tsc,
        'mitre': mitre,
        'distinct': distinct
    }
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.info(f"Fetching rules from endpoint: {endpoint}")
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        return handle_secure_error(e, f"fetching rules from {endpoint}")

@mcp.tool()
def get_rule_files(
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
    Return a list of all files used to define rules and their status.

    Args:
        pretty: Show results in human-readable format.
        wait_for_complete: Disable timeout response.
        offset: First element to return.
        limit: Maximum number of elements to return.
        sort: Sorts the results by the specified field.
        search: Looks for elements with the specified string.
        status: Filters by rule status. Allowed values: 'enabled', 'disabled', 'all'.
        filename: Filters by filename. Can be a list.
        relative_dirname: Filters by relative directory name.
        q: Query to filter results.
        select: List of fields to return.
        distinct: Looks for distinct values.

    Returns:
        A dictionary containing the list of rule files.
    """
    endpoint = "/rules/files"
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'offset': offset,
        'limit': limit,
        'sort': sort,
        'search': search,
        'status': status,
        'filename': ','.join(filename) if filename else None,
        'relative_dirname': relative_dirname,
        'q': q,
        'select': ','.join(select) if select else None,
        'distinct': distinct,
    }
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.info(f"Fetching rule files from endpoint: {endpoint}")
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        return handle_secure_error(e, f"fetching rule files from {endpoint}")

@mcp.tool()
def get_rule_groups(
        pretty: bool = False,
        wait_for_complete: bool = False,
        offset: int = 0,
        limit: int = 500,
        sort: Optional[str] = None,
        search: Optional[str] = None
) -> Dict[str, Any]:
    """
    Return a list of all rule group names.

    Args:
        pretty: Show results in human-readable format.
        wait_for_complete: Disable timeout response.
        offset: First element to return.
        limit: Maximum number of elements to return.
        sort: Sorts the results by the specified field.
        search: Looks for elements with the specified string.

    Returns:
        A dictionary containing the list of rule groups.
    """
    endpoint = "/rules/groups"
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'offset': offset,
        'limit': limit,
        'sort': sort,
        'search': search,
    }
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.info(f"Fetching rule groups from endpoint: {endpoint}")
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        return handle_secure_error(e, f"fetching rule groups from {endpoint}")