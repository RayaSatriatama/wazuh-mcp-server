"""
Wazuh Manager Module - MCP Tools and Resources for Wazuh Manager API
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
mcp = FastMCP("wazuh_manager_mcp")

# Initialize logger
logger = logging.getLogger(__name__)

# API client instance - will be patched by server to use centralized service
api_client = get_manager_client()

# ====== MCP TOOLS ======

@mcp.tool()
def get_manager_status(
        pretty: bool = False,
        wait_for_complete: bool = False
) -> Dict[str, Any]:
    """
    Return the status of all Wazuh daemons.
    Corresponds to GET /manager/status.
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete
    }

    try:
        logger.debug("Fetching manager status from /manager/status")
        return api_client._make_request("GET", "/manager/status", params=params)
    except Exception as e:
        return handle_secure_error(e, "fetching manager status")

@mcp.tool()
def get_manager_info(
        pretty: bool = False,
        wait_for_complete: bool = False
) -> Dict[str, Any]:
    """
    Return basic information about the Wazuh manager.
    Corresponds to GET /manager/info.
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete
    }
    try:
        logger.debug("Fetching manager information from /manager/info")
        return api_client._make_request("GET", "/manager/info", params=params)
    except Exception as e:
        return handle_secure_error(e, "fetching manager information")

@mcp.tool()
def get_manager_configuration(
        pretty: bool = False,
        wait_for_complete: bool = False,
        section: Optional[str] = None,
        field: Optional[str] = None,
        raw: bool = False,
        distinct: bool = False
) -> Dict[str, Any]:
    """
    Return Wazuh configuration (ossec.conf) in JSON or raw XML format.
    Corresponds to GET /manager/configuration.
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'section': section,
        'field': field,
        'raw': raw,
        'distinct': distinct
    }
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.debug("Fetching manager configuration from /manager/configuration")
        return api_client._make_request("GET", "/manager/configuration", params=params, expect_raw=raw)
    except Exception as e:
        return handle_secure_error(e, "fetching manager configuration")

@mcp.tool()
def get_manager_daemon_stats(
        pretty: bool = False,
        wait_for_complete: bool = False,
        daemons_list: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Return Wazuh statistical information from specified daemons.
    Corresponds to GET /manager/daemons/stats.
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'daemons_list': ','.join(daemons_list) if daemons_list else None
    }
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.debug("Fetching manager daemon statistics from /manager/daemons/stats")
        return api_client._make_request("GET", "/manager/daemons/stats", params=params)
    except Exception as e:
        return handle_secure_error(e, "fetching manager daemon statistics")

@mcp.tool()
def get_manager_stats(
        pretty: bool = False,
        wait_for_complete: bool = False,
        date: Optional[str] = None
) -> Dict[str, Any]:
    """
    Return Wazuh statistical information for the current or specified date.
    Corresponds to GET /manager/stats.
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'date': date
    }
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.debug("Fetching manager statistics from /manager/stats")
        return api_client._make_request("GET", "/manager/stats", params=params)
    except Exception as e:
        return handle_secure_error(e, "fetching manager statistics")

@mcp.tool()
def get_manager_stats_hourly(
        pretty: bool = False,
        wait_for_complete: bool = False
) -> Dict[str, Any]:
    """
    Return Wazuh statistical information per hour.
    Corresponds to GET /manager/stats/hourly.
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete
    }
    try:
        logger.debug("Fetching manager hourly statistics from /manager/stats/hourly")
        return api_client._make_request("GET", "/manager/stats/hourly", params=params)
    except Exception as e:
        return handle_secure_error(e, "fetching manager hourly statistics")

@mcp.tool()
def get_manager_stats_weekly(
        pretty: bool = False,
        wait_for_complete: bool = False
) -> Dict[str, Any]:
    """
    Return Wazuh statistical information per week.
    Corresponds to GET /manager/stats/weekly.
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete
    }
    try:
        logger.debug("Fetching manager weekly statistics from /manager/stats/weekly")
        return api_client._make_request("GET", "/manager/stats/weekly", params=params)
    except Exception as e:
        return handle_secure_error(e, "fetching manager weekly statistics")

@mcp.tool()
def get_manager_logs(
        pretty: bool = False,
        wait_for_complete: bool = False,
        offset: int = 0,
        limit: int = 500,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        tag: Optional[str] = None,
        level: Optional[str] = None,
        q: Optional[str] = None,
        select: Optional[List[str]] = None,
        distinct: bool = False
) -> Dict[str, Any]:
    """
    Return the last 13000 entries of wazuh log file (ossec.log).
    Corresponds to GET /manager/logs.
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'offset': offset,
        'limit': limit,
        'sort': sort,
        'search': search,
        'tag': tag,
        'level': level,
        'q': q,
        'select': ','.join(select) if select else None,
        'distinct': distinct
    }
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.debug("Fetching manager logs from /manager/logs")
        return api_client._make_request("GET", "/manager/logs", params=params)
    except Exception as e:
        return handle_secure_error(e, "fetching manager logs")

@mcp.tool()
def get_manager_logs_summary(
        pretty: bool = False,
        wait_for_complete: bool = False
) -> Dict[str, Any]:
    """
    Return a summary of the wazuh log file.
    Corresponds to GET /manager/logs/summary.
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete
    }
    try:
        logger.debug("Fetching manager logs summary from /manager/logs/summary")
        return api_client._make_request("GET", "/manager/logs/summary", params=params)
    except Exception as e:
        return handle_secure_error(e, "fetching manager logs summary")

@mcp.tool()
def get_api_config(
        pretty: bool = False,
        wait_for_complete: bool = False
) -> Dict[str, Any]:
    """
    Shows the API configuration.
    Corresponds to GET /manager/api/config.
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
    }
    try:
        logger.debug("Fetching API configuration from /manager/api/config")
        return api_client._make_request("GET", "/manager/api/config", params=params)
    except Exception as e:
        return handle_secure_error(e, "fetching API configuration")

@mcp.tool()
def validate_manager_configuration(
        pretty: bool = False,
        wait_for_complete: bool = False
) -> Dict[str, Any]:
    """
    Check if Wazuh configuration is correct.
    Corresponds to GET /manager/configuration/validation.
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete
    }
    try:
        logger.info("Validating manager configuration from /manager/configuration/validation")
        return api_client._make_request("GET", "/manager/configuration/validation", params=params)
    except Exception as e:
        return handle_secure_error(e, "validating manager configuration")

@mcp.tool()
def get_manager_active_config(
        component: str,
        configuration: str,
        pretty: bool = False,
        wait_for_complete: bool = False
) -> Dict[str, Any]:
    """
    Return the active configuration for a specific component and configuration.
    Corresponds to GET /manager/component/{component}/configuration/{configuration}.
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete
    }
    try:
        logger.info(f"Fetching active configuration for {component}/{configuration}")
        endpoint = f"/manager/component/{component}/configuration/{configuration}"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        return handle_secure_error(e, f"fetching active configuration for {component}/{configuration}")

@mcp.tool()
def get_wazuh_version_info(
        pretty: bool = False,
        wait_for_complete: bool = False,
        force_query: bool = False
) -> Dict[str, Any]:
    """
    Return available updates for Wazuh, framework and ruleset.
    Corresponds to GET /manager/info/updates.
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'force_query': force_query
    }
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.debug("Fetching Wazuh version update info from /manager/info/updates")
        return api_client._make_request("GET", "/manager/info/updates", params=params)
    except Exception as e:
        return handle_secure_error(e, "fetching Wazuh version update info")