"""
Wazuh SCA Module - MCP Tools and Resources for Security Configuration Assessment
"""
import re
from typing import Dict, Any, List, Optional

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
mcp = FastMCP("wazuh_sca_mcp")

# Initialize logger
logger = logging.getLogger(__name__)

# Initialize API client and config

api_client = get_manager_client()

# ====== MCP TOOLS ======

@mcp.tool()
def get_agent_sca_checks(
        agent_id: str,
        pretty: bool = False,
        wait_for_complete: bool = False,
        offset: int = 0,
        limit: int = 500,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
        references: Optional[str] = None,
        select: Optional[List[str]] = None,
        q: Optional[str] = None,
        distinct: bool = False
) -> Dict[str, Any]:
    """
    Return the SCA checks for a specific agent.

    Args:
        agent_id: The ID of the agent.
        pretty: Show results in human-readable format.
        wait_for_complete: Disable timeout response.
        offset: First element to return.
        limit: Maximum number of elements to return.
        sort: Field to sort by.
        search: Look for elements containing the specified string.
        name: Filter by policy name.
        description: Filter by policy description.
        references: Filter by policy references.
        select: List of fields to return.
        q: Query to filter results.
        distinct: Look for distinct values.

    Returns:
        A dictionary containing the SCA check results.
    """
    endpoint = f"/sca/{agent_id}"
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'offset': offset,
        'limit': limit,
        'sort': sort,
        'search': search,
        'name': name,
        'description': description,
        'references': references,
        'select': ','.join(select) if select else None,
        'q': q,
        'distinct': distinct,
    }
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.info(f"Fetching SCA checks for agent {agent_id}")
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        return handle_secure_error(e, f"fetching SCA checks for agent {agent_id}")

@mcp.tool()
def get_agent_sca_policy_checks(
        agent_id: str,
        policy_id: str,
        pretty: bool = False,
        wait_for_complete: bool = False,
        offset: int = 0,
        limit: int = 500,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        title: Optional[str] = None,
        description: Optional[str] = None,
        rationale: Optional[str] = None,
        remediation: Optional[str] = None,
        command: Optional[str] = None,
        reason: Optional[str] = None,
        file: Optional[str] = None,
        process: Optional[str] = None,
        directory: Optional[str] = None,
        registry: Optional[str] = None,
        references: Optional[str] = None,
        result: Optional[str] = None,
        condition: Optional[str] = None,
        select: Optional[List[str]] = None,
        q: Optional[str] = None,
        distinct: bool = False
) -> Dict[str, Any]:
    """
    Return the checks of a specific SCA policy for an agent.

    Args:
        agent_id: The ID of the agent.
        policy_id: The ID of the policy.
        pretty: Show results in human-readable format.
        wait_for_complete: Disable timeout response.
        offset: First element to return.
        limit: Maximum number of elements to return.
        sort: Field to sort by.
        search: Look for elements containing the specified string.
        title: Filter by check title.
        description: Filter by policy description.
        rationale: Filter by rationale.
        remediation: Filter by remediation.
        command: Filter by command.
        reason: Filter by reason.
        file: Filter by full path.
        process: Filter by process name.
        directory: Filter by directory.
        registry: Filter by registry.
        references: Filter by references.
        result: Filter by result.
        condition: Filter by condition.
        select: List of fields to return.
        q: Query to filter results.
        distinct: Look for distinct values.

    Returns:
        A dictionary containing the policy check results.
    """
    endpoint = f"/sca/{agent_id}/checks/{policy_id}"
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'offset': offset,
        'limit': limit,
        'sort': sort,
        'search': search,
        'title': title,
        'description': description,
        'rationale': rationale,
        'remediation': remediation,
        'command': command,
        'reason': reason,
        'file': file,
        'process': process,
        'directory': directory,
        'registry': registry,
        'references': references,
        'result': result,
        'condition': condition,
        'select': ','.join(select) if select else None,
        'q': q,
        'distinct': distinct,
    }
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.info(f"Fetching SCA policy checks for agent {agent_id}, policy {policy_id}")
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        return handle_secure_error(e, f"fetching SCA policy checks for agent {agent_id}, policy {policy_id}")