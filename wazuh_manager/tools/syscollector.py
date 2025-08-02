"""
Wazuh Syscollector Module - MCP Tools and Resources for Syscollector API
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
mcp = FastMCP("wazuh_syscollector_mcp")

# Initialize logger
logger = logging.getLogger(__name__)

# Initialize API client and config

api_client = get_manager_client()

# ====== MCP TOOLS ======

@mcp.tool()
def get_agent_hardware(
        agent_id: str,
        pretty: bool = False,
        wait_for_complete: bool = False,
        select: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Return the agent's hardware info.

    Args:
        agent_id: Agent ID
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        select: Fields to return

    Returns:
        Dictionary with agent hardware information
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'select': ','.join(select) if select else None
    }
    params = {k: v for k, v in params.items() if v is not None}
    try:
        logger.info(f"Fetching hardware information for agent {agent_id}")
        endpoint = f"/syscollector/{agent_id}/hardware"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        return handle_secure_error(e, f"fetching agent hardware for agent {agent_id}")

@mcp.tool()
def get_agent_hotfixes(
        agent_id: str,
        pretty: bool = False,
        wait_for_complete: bool = False,
        offset: int = 0,
        limit: int = 500,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[List[str]] = None,
        hotfix: Optional[str] = None,
        q: Optional[str] = None,
        distinct: bool = False
) -> Dict[str, Any]:
    """
    Return all hotfixes installed by Microsoft(R) in Windows(R) systems.

    Args:
        agent_id: Agent ID
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        offset: First element to return
        limit: Maximum number of elements to return
        sort: Fields to sort by
        search: Look for elements containing the specified string
        select: Fields to return
        hotfix: Filter by hotfix ID
        q: Query to filter results
        distinct: Look for distinct values

    Returns:
        Dictionary with agent hotfixes information
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'offset': offset,
        'limit': limit,
        'sort': sort,
        'search': search,
        'select': ','.join(select) if select else None,
        'hotfix': hotfix,
        'q': q,
        'distinct': distinct
    }
    params = {k: v for k, v in params.items() if v is not None}
    try:
        logger.info(f"Fetching hotfixes for agent {agent_id}")
        endpoint = f"/syscollector/{agent_id}/hotfixes"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        return handle_secure_error(e, f"fetching agent hotfixes for agent {agent_id}")

@mcp.tool()
def get_agent_netaddr(
        agent_id: str,
        pretty: bool = False,
        wait_for_complete: bool = False,
        offset: int = 0,
        limit: int = 500,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[List[str]] = None,
        iface: Optional[str] = None,
        proto: Optional[str] = None,
        address: Optional[str] = None,
        broadcast: Optional[str] = None,
        netmask: Optional[str] = None,
        q: Optional[str] = None,
        distinct: bool = False
) -> Dict[str, Any]:
    """
    Return the agent's network address info.

    Args:
        agent_id: Agent ID
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        offset: First element to return
        limit: Maximum number of elements to return
        sort: Fields to sort by
        search: Look for elements containing the specified string
        select: Fields to return
        iface: Filter by interface name
        proto: Filter by protocol
        address: Filter by address
        broadcast: Filter by broadcast
        netmask: Filter by netmask
        q: Query to filter results
        distinct: Look for distinct values

    Returns:
        Dictionary with agent network address information
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'offset': offset,
        'limit': limit,
        'sort': sort,
        'search': search,
        'select': ','.join(select) if select else None,
        'iface': iface,
        'proto': proto,
        'address': address,
        'broadcast': broadcast,
        'netmask': netmask,
        'q': q,
        'distinct': distinct
    }
    params = {k: v for k, v in params.items() if v is not None}
    try:
        logger.info(f"Fetching network addresses for agent {agent_id}")
        endpoint = f"/syscollector/{agent_id}/netaddr"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        return handle_secure_error(e, f"fetching agent network addresses for agent {agent_id}")

@mcp.tool()
def get_agent_netiface(
        agent_id: str,
        pretty: bool = False,
        wait_for_complete: bool = False,
        offset: int = 0,
        limit: int = 500,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[List[str]] = None,
        name: Optional[str] = None,
        adapter: Optional[str] = None,
        iface_type: Optional[str] = None,
        state: Optional[str] = None,
        mtu: Optional[int] = None,
        tx_packets: Optional[int] = None,
        rx_packets: Optional[int] = None,
        tx_bytes: Optional[int] = None,
        rx_bytes: Optional[int] = None,
        tx_errors: Optional[int] = None,
        rx_errors: Optional[int] = None,
        tx_dropped: Optional[int] = None,
        rx_dropped: Optional[int] = None,
        q: Optional[str] = None,
        distinct: bool = False
) -> Dict[str, Any]:
    """
    Return the agent's network interface info.

    Args:
        agent_id: Agent ID
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        offset: First element to return
        limit: Maximum number of elements to return
        sort: Fields to sort by
        search: Look for elements containing the specified string
        select: Fields to return
        name: Filter by name
        adapter: Filter by adapter
        iface_type: Filter by type
        state: Filter by state
        mtu: Filter by MTU
        tx_packets: Filter by tx.packets
        rx_packets: Filter by rx.packets
        tx_bytes: Filter by tx.bytes
        rx_bytes: Filter by rx.bytes
        tx_errors: Filter by tx.errors
        rx_errors: Filter by rx.errors
        tx_dropped: Filter by tx.dropped
        rx_dropped: Filter by rx.dropped
        q: Query to filter results
        distinct: Look for distinct values

    Returns:
        Dictionary with agent network interface information
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'offset': offset,
        'limit': limit,
        'sort': sort,
        'search': search,
        'select': ','.join(select) if select else None,
        'name': name,
        'adapter': adapter,
        'type': iface_type,
        'state': state,
        'mtu': mtu,
        'tx.packets': tx_packets,
        'rx.packets': rx_packets,
        'tx.bytes': tx_bytes,
        'rx.bytes': rx_bytes,
        'tx.errors': tx_errors,
        'rx.errors': rx_errors,
        'tx.dropped': tx_dropped,
        'rx.dropped': rx_dropped,
        'q': q,
        'distinct': distinct
    }
    params = {k: v for k, v in params.items() if v is not None}
    try:
        logger.info(f"Fetching network interfaces for agent {agent_id}")
        endpoint = f"/syscollector/{agent_id}/netiface"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        return handle_secure_error(e, f"fetching agent network interfaces for agent {agent_id}")

@mcp.tool()
def get_agent_netproto(
        agent_id: str,
        pretty: bool = False,
        wait_for_complete: bool = False,
        offset: int = 0,
        limit: int = 500,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[List[str]] = None,
        iface: Optional[str] = None,
        proto_type: Optional[str] = None,
        gateway: Optional[str] = None,
        dhcp: Optional[str] = None,
        q: Optional[str] = None,
        distinct: bool = False
) -> Dict[str, Any]:
    """
    Return the agent's routing configuration for each network interface.

    Args:
        agent_id: Agent ID
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        offset: First element to return
        limit: Maximum number of elements to return
        sort: Fields to sort by
        search: Look for elements containing the specified string
        select: Fields to return
        iface: Filter by network interface
        proto_type: Type of network
        gateway: Filter by network gateway
        dhcp: Filter by network dhcp
        q: Query to filter results
        distinct: Look for distinct values

    Returns:
        Dictionary with agent network protocol information
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'offset': offset,
        'limit': limit,
        'sort': sort,
        'search': search,
        'select': ','.join(select) if select else None,
        'iface': iface,
        'type': proto_type,
        'gateway': gateway,
        'dhcp': dhcp,
        'q': q,
        'distinct': distinct
    }
    params = {k: v for k, v in params.items() if v is not None}
    try:
        logger.info(f"Fetching network protocol for agent {agent_id}")
        endpoint = f"/syscollector/{agent_id}/netproto"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        return handle_secure_error(e, f"fetching agent network protocol for agent {agent_id}")

@mcp.tool()
def get_agent_os(
        agent_id: str,
        pretty: bool = False,
        wait_for_complete: bool = False,
        select: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Return the agent's OS info.

    Args:
        agent_id: Agent ID
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        select: Fields to return

    Returns:
        Dictionary with agent OS information
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'select': ','.join(select) if select else None
    }
    params = {k: v for k, v in params.items() if v is not None}
    try:
        logger.info(f"Fetching OS information for agent {agent_id}")
        endpoint = f"/syscollector/{agent_id}/os"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        return handle_secure_error(e, f"fetching agent OS information for agent {agent_id}")

@mcp.tool()
def get_agent_packages(
        agent_id: str,
        pretty: bool = False,
        wait_for_complete: bool = False,
        offset: int = 0,
        limit: int = 500,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[List[str]] = None,
        vendor: Optional[str] = None,
        name: Optional[str] = None,
        architecture: Optional[str] = None,
        pkg_format: Optional[str] = None,
        version: Optional[str] = None,
        q: Optional[str] = None,
        distinct: bool = False
) -> Dict[str, Any]:
    """
    Return the agent's packages info.

    Args:
        agent_id: Agent ID
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        offset: First element to return
        limit: Maximum number of elements to return
        sort: Fields to sort by
        search: Look for elements containing the specified string
        select: Fields to return
        vendor: Filter by vendor
        name: Filter by name
        architecture: Filter by architecture
        pkg_format: Filter by file format
        version: Filter by package version
        q: Query to filter results
        distinct: Look for distinct values

    Returns:
        Dictionary with agent packages information
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'offset': offset,
        'limit': limit,
        'sort': sort,
        'search': search,
        'select': ','.join(select) if select else None,
        'vendor': vendor,
        'name': name,
        'architecture': architecture,
        'format': pkg_format,
        'version': version,
        'q': q,
        'distinct': distinct
    }
    params = {k: v for k, v in params.items() if v is not None}
    try:
        logger.info(f"Fetching packages for agent {agent_id}")
        endpoint = f"/syscollector/{agent_id}/packages"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        return handle_secure_error(e, f"fetching agent packages for agent {agent_id}")

@mcp.tool()
def get_agent_ports(
        agent_id: str,
        pretty: bool = False,
        wait_for_complete: bool = False,
        offset: int = 0,
        limit: int = 500,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[List[str]] = None,
        pid: Optional[str] = None,
        protocol: Optional[str] = None,
        local_ip: Optional[str] = None,
        local_port: Optional[str] = None,
        remote_ip: Optional[str] = None,
        tx_queue: Optional[str] = None,
        state: Optional[str] = None,
        process: Optional[str] = None,
        q: Optional[str] = None,
        distinct: bool = False
) -> Dict[str, Any]:
    """
    Return the agent's ports info.

    Args:
        agent_id: Agent ID
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        offset: First element to return
        limit: Maximum number of elements to return
        sort: Fields to sort by
        search: Look for elements containing the specified string
        select: Fields to return
        pid: Filter by pid
        protocol: Filter by protocol
        local_ip: Filter by Local IP
        local_port: Filter by Local Port
        remote_ip: Filter by Remote IP
        tx_queue: Filter by tx_queue
        state: Filter by state
        process: Filter by process name
        q: Query to filter results
        distinct: Look for distinct values

    Returns:
        Dictionary with agent ports information
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'offset': offset,
        'limit': limit,
        'sort': sort,
        'search': search,
        'select': ','.join(select) if select else None,
        'pid': pid,
        'protocol': protocol,
        'local.ip': local_ip,
        'local.port': local_port,
        'remote.ip': remote_ip,
        'tx_queue': tx_queue,
        'state': state,
        'process': process,
        'q': q,
        'distinct': distinct
    }
    params = {k: v for k, v in params.items() if v is not None}
    try:
        logger.info(f"Fetching ports for agent {agent_id}")
        endpoint = f"/syscollector/{agent_id}/ports"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        return handle_secure_error(e, f"fetching agent ports for agent {agent_id}")

@mcp.tool()
def get_agent_processes(
        agent_id: str,
        pretty: bool = False,
        wait_for_complete: bool = False,
        offset: int = 0,
        limit: int = 500,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        select: Optional[List[str]] = None,
        pid: Optional[str] = None,
        state: Optional[str] = None,
        ppid: Optional[str] = None,
        egroup: Optional[str] = None,
        euser: Optional[str] = None,
        fgroup: Optional[str] = None,
        name: Optional[str] = None,
        nlwp: Optional[str] = None,
        pgrp: Optional[str] = None,
        priority: Optional[str] = None,
        rgroup: Optional[str] = None,
        ruser: Optional[str] = None,
        sgroup: Optional[str] = None,
        suser: Optional[str] = None,
        q: Optional[str] = None,
        distinct: bool = False
) -> Dict[str, Any]:
    """
    Return the agent's processes info.

    Args:
        agent_id: Agent ID
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        offset: First element to return
        limit: Maximum number of elements to return
        sort: Fields to sort by
        search: Look for elements containing the specified string
        select: Fields to return
        pid: Filter by process pid
        state: Filter by process state
        ppid: Filter by process parent pid
        egroup: Filter by process egroup
        euser: Filter by process euser
        fgroup: Filter by process fgroup
        name: Filter by process name
        nlwp: Filter by process nlwp
        pgrp: Filter by process pgrp
        priority: Filter by process priority
        rgroup: Filter by process rgroup
        ruser: Filter by process ruser
        sgroup: Filter by process sgroup
        suser: Filter by process suser
        q: Query to filter results
        distinct: Look for distinct values

    Returns:
        Dictionary with agent processes information
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'offset': offset,
        'limit': limit,
        'sort': sort,
        'search': search,
        'select': ','.join(select) if select else None,
        'pid': pid,
        'state': state,
        'ppid': ppid,
        'egroup': egroup,
        'euser': euser,
        'fgroup': fgroup,
        'name': name,
        'nlwp': nlwp,
        'pgrp': pgrp,
        'priority': priority,
        'rgroup': rgroup,
        'ruser': ruser,
        'sgroup': sgroup,
        'suser': suser,
        'q': q,
        'distinct': distinct
    }
    params = {k: v for k, v in params.items() if v is not None}
    try:
        logger.info(f"Fetching processes for agent {agent_id}")
        endpoint = f"/syscollector/{agent_id}/processes"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        return handle_secure_error(e, f"fetching agent processes for agent {agent_id}")