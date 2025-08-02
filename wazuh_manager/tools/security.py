"""
Wazuh Security Module - MCP Tools and Resources for Wazuh Security API
"""
import json
import re
import datetime
from typing import Dict, Any, List, Optional, Union

from mcp.server.fastmcp import FastMCP

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
mcp = FastMCP("wazuh_security_mcp")

# Initialize logger
logger = logging.getLogger(__name__)

# API client instance - will be patched by server to use centralized service
api_client = get_manager_client()

# ====== MCP TOOLS ======

@mcp.tool()
def get_current_user_info(
        pretty: bool = False,
        wait_for_complete: bool = False
) -> Dict[str, Any]:
    """
    Get the information of the current user.

    Args:
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response

    Returns:
        Dictionary with current user information
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete
    }

    try:
        logger.debug("Fetching current user information")
        endpoint = "/security/users/me"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        return handle_secure_error(e, "fetching current user information")

@mcp.tool()
def get_current_user_processed_policies(
        pretty: bool = False,
        wait_for_complete: bool = False
) -> Dict[str, Any]:
    """
    Get the processed policies information for the current user.

    Args:
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response

    Returns:
        Dictionary with current user's processed policies
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete
    }

    try:
        logger.debug("Fetching current user processed policies")
        endpoint = "/security/users/me/policies"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        return handle_secure_error(e, "fetching current user processed policies")

@mcp.tool()
def get_list_rbac_actions(
        pretty: bool = False,
        wait_for_complete: bool = False,
        endpoint: Optional[str] = None,
        offset: int = 0,
        limit: int = 500,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        q: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get all RBAC actions, including the potential related resources and endpoints.

    Args:
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        endpoint: Look for the RBAC actions which are related to the specified endpoint
        offset: First element to return
        limit: Maximum number of elements to return
        sort: Fields to sort by
        search: Look for elements containing the specified string
        q: Query to filter results

    Returns:
        Dictionary with RBAC actions
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'endpoint': endpoint,
        'offset': offset,
        'limit': limit,
        'sort': sort,
        'search': search,
        'q': q
    }

    # Remove None values
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.debug("Fetching RBAC actions")
        endpoint_url = "/security/actions"
        return api_client._make_request("GET", endpoint_url, params=params)
    except Exception as e:
        return handle_secure_error(e, "fetching RBAC actions")

@mcp.tool()
def list_rbac_resources(
        pretty: bool = False,
        wait_for_complete: bool = False,
        resource: Optional[str] = None,
        offset: int = 0,
        limit: int = 500,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[List[str]] = None,
        q: Optional[str] = None,
        distinct: bool = False
) -> Dict[str, Any]:
    """
    Get all current defined RBAC resources.

    Args:
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        resource: List of current RBAC's resources. Enum: "*:*", "agent:group", "agent:id", "group:id", etc.
        offset: First element to return
        limit: Maximum number of elements to return
        sort: Fields to sort by
        search: Look for elements containing the specified string
        select: Select which fields to return
        q: Query to filter results
        distinct: Look for distinct values

    Returns:
        Dictionary with RBAC resources
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'resource': resource,
        'offset': offset,
        'limit': limit,
        'sort': sort,
        'search': search,
        'select': ','.join(select) if select else None,
        'q': q,
        'distinct': distinct
    }

    # Remove None values
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.debug("Fetching RBAC resources")
        endpoint = "/security/resources"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        return handle_secure_error(e, "fetching RBAC resources")

@mcp.tool()
def list_users(
        pretty: bool = False,
        wait_for_complete: bool = False,
        offset: int = 0,
        limit: int = 500,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[List[str]] = None,
        user_ids: Optional[List[str]] = None,
        q: Optional[str] = None,
        distinct: bool = False
) -> Dict[str, Any]:
    """
    Get the information of users.

    Args:
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        offset: First element to return
        limit: Maximum number of elements to return
        sort: Fields to sort by
        search: Look for elements containing the specified string
        select: Fields to return
        user_ids: List of user IDs
        q: Query to filter results
        distinct: Look for distinct values

    Returns:
        Dictionary with users information
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'offset': offset,
        'limit': limit,
        'sort': sort,
        'search': search,
        'select': ','.join(select) if select else None,
        'user_ids': ','.join(user_ids) if user_ids else None,
        'q': q,
        'distinct': distinct
    }

    # Remove None values
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.debug("Fetching users information")
        endpoint = "/security/users"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        return handle_secure_error(e, "fetching users information")

@mcp.tool()
def list_roles(
        pretty: bool = False,
        wait_for_complete: bool = False,
        offset: int = 0,
        limit: int = 500,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[List[str]] = None,
        role_ids: Optional[List[str]] = None,
        q: Optional[str] = None,
        distinct: bool = False
) -> Dict[str, Any]:
    """
    Get roles information.

    Args:
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        offset: First element to return
        limit: Maximum number of elements to return
        sort: Fields to sort by
        search: Look for elements containing the specified string
        select: Fields to return
        role_ids: List of role IDs (separated by commas)
        q: Query to filter results
        distinct: Look for distinct values

    Returns:
        Dictionary with roles information
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'offset': offset,
        'limit': limit,
        'sort': sort,
        'search': search,
        'select': ','.join(select) if select else None,
        'role_ids': ','.join(role_ids) if role_ids else None,
        'q': q,
        'distinct': distinct
    }

    # Remove None values
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.debug("Fetching roles information")
        endpoint = "/security/roles"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        return handle_secure_error(e, "fetching roles information")

@mcp.tool()
def list_security_rules(
        pretty: bool = False,
        wait_for_complete: bool = False,
        offset: int = 0,
        limit: int = 500,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[List[str]] = None,
        rule_ids: Optional[List[str]] = None,
        q: Optional[str] = None,
        distinct: bool = False
) -> Dict[str, Any]:
    """
    Get a list of security rules from the system.

    Args:
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        offset: First element to return
        limit: Maximum number of elements to return
        sort: Fields to sort by
        search: Look for elements containing the specified string
        select: Select which fields to return
        rule_ids: List of rule IDs (separated by commas)
        q: Query to filter results
        distinct: Look for distinct values

    Returns:
        Dictionary with security rules information
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'offset': offset,
        'limit': limit,
        'sort': sort,
        'search': search,
        'select': ','.join(select) if select else None,
        'rule_ids': ','.join(rule_ids) if rule_ids else None,
        'q': q,
        'distinct': distinct
    }

    # Remove None values
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.debug("Fetching security rules information")
        endpoint = "/security/rules"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        return handle_secure_error(e, "fetching security rules information")

@mcp.tool()
def list_policies(
        pretty: bool = False,
        wait_for_complete: bool = False,
        offset: int = 0,
        limit: int = 500,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[List[str]] = None,
        policy_ids: Optional[List[str]] = None,
        q: Optional[str] = None,
        distinct: bool = False
) -> Dict[str, Any]:
    """
    Get all policies in the system, including the administrator policy.

    Args:
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        offset: First element to return
        limit: Maximum number of elements to return
        sort: Fields to sort by
        search: Look for elements containing the specified string
        select: Select which fields to return
        policy_ids: List of policy IDs (separated by commas)
        q: Query to filter results
        distinct: Look for distinct values

    Returns:
        Dictionary with policies information
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'offset': offset,
        'limit': limit,
        'sort': sort,
        'search': search,
        'select': ','.join(select) if select else None,
        'policy_ids': ','.join(policy_ids) if policy_ids else None,
        'q': q,
        'distinct': distinct
    }

    # Remove None values
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.debug("Fetching policies information")
        endpoint = "/security/policies"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        return handle_secure_error(e, "fetching policies information")

@mcp.tool()
def get_security_config(
        pretty: bool = False,
        wait_for_complete: bool = False
) -> Dict[str, Any]:
    """
    Get security configuration information.

    Args:
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response

    Returns:
        Dictionary with security configuration
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete
    }

    try:
        logger.debug("Fetching security configuration")
        endpoint = "/security/config"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        return handle_secure_error(e, "fetching security configuration")

@mcp.tool()
def get_auth_context(
        pretty: bool = False,
        wait_for_complete: bool = False
) -> Dict[str, Any]:
    """
    Get authentication context information for the current session.

    Args:
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response

    Returns:
        Dictionary with authentication context information
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete
    }

    try:
        logger.debug("Fetching authentication context")
        # Get current user info as authentication context
        endpoint = "/security/users/me"
        result = api_client._make_request("GET", endpoint, params=params)
        
        # Add context metadata
        if 'data' in result and 'affected_items' in result['data']:
            user_data = result['data']['affected_items'][0] if result['data']['affected_items'] else {}
            auth_context = {
                "authentication_method": "API Key",
                "current_user": user_data.get('username', 'Unknown'),
                "user_roles": user_data.get('roles', []),
                "session_active": True,
                "last_login": user_data.get('last_login', None),
                "user_permissions": user_data.get('allow_run_as', False),
                "context_timestamp": datetime.datetime.now().isoformat()
            }
            return {
                "error": 0,
                "data": {"affected_items": [auth_context]},
                "message": "Authentication context retrieved successfully"
            }
        else:
            return result
            
    except Exception as e:
        return handle_secure_error(e, "fetching authentication context")

@mcp.tool()
def get_rbac_resources(
        pretty: bool = False,
        wait_for_complete: bool = False,
        resource: Optional[str] = None,
        offset: int = 0,
        limit: int = 500
) -> Dict[str, Any]:
    """
    Get RBAC (Role-Based Access Control) resources information.

    Args:
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        resource: Specific resource to filter by
        offset: First element to return
        limit: Maximum number of elements to return

    Returns:
        Dictionary with RBAC resources information
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'offset': offset,
        'limit': limit
    }
    
    if resource:
        params['resource'] = resource

    try:
        logger.debug("Fetching RBAC resources")
        endpoint = "/security/resources"
        return api_client._make_request("GET", endpoint, params=params)
        
    except Exception as e:
        return handle_secure_error(e, "fetching RBAC resources")