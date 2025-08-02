"""
Wazuh Experimental Module - MCP Tools and Resources for Wazuh Experimental API
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
mcp = FastMCP("wazuh_experimental_mcp")

# Initialize logger
logger = logging.getLogger(__name__)

# Initialize API client and config

api_client = get_manager_client()

# ====== MCP TOOLS ======

@mcp.tool()
def get_agents_ciscat(
        pretty: bool = False,
        wait_for_complete: bool = False,
        agents_list: Optional[List[str]] = None,
        offset: int = 0,
        limit: int = 500,
        select: Optional[List[str]] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        q: Optional[str] = None,
        benchmark: Optional[str] = None,
        profile: Optional[str] = None,
        pass_filter: Optional[int] = None,
        fail: Optional[int] = None,
        error: Optional[int] = None,
        notchecked: Optional[int] = None,
        unknown: Optional[int] = None,
        score: Optional[int] = None
) -> Dict[str, Any]:
    """
    Return CIS-CAT results for all agents or a list of them.
    Corresponds to GET /experimental/ciscat/results.

    Args:
        pretty (bool): Show results in human-readable format.
        wait_for_complete (bool): Disable timeout response.
        agents_list (Optional[List[str]]): List of agent IDs.
        offset (int): First element to return.
        limit (int): Maximum number of elements to return.
        select (Optional[List[str]]): Fields to return.
        sort (Optional[str]): Fields to sort by.
        search (Optional[str]): Look for elements containing the specified string.
        q (Optional[str]): Query to filter results.
        benchmark (Optional[str]): Filter by benchmark.
        profile (Optional[str]): Filter by profile.
        pass_filter (Optional[int]): Filter by passed checks.
        fail (Optional[int]): Filter by failed checks.
        error (Optional[int]): Filter by encountered errors.
        notchecked (Optional[int]): Filter by not checked.
        unknown (Optional[int]): Filter by unknown results.
        score (Optional[int]): Filter by final score.

    Returns:
        Dict[str, Any]: Dictionary with CIS-CAT results.
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'agents_list': ','.join(agents_list) if agents_list else None,
        'offset': offset,
        'limit': limit,
        'select': ','.join(select) if select else None,
        'sort': sort,
        'search': search,
        'q': q,
        'benchmark': benchmark,
        'profile': profile,
        'pass': pass_filter,  # Use 'pass' for the API, from 'pass_filter' arg
        'fail': fail,
        'error': error,
        'notchecked': notchecked,
        'unknown': unknown,
        'score': score
    }
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.debug("Fetching agents CIS-CAT results from /experimental/ciscat/results")
        return api_client._make_request("GET", "/experimental/ciscat/results", params=params)
    except Exception as e:
        return handle_secure_error(e, "fetching agents CIS-CAT results")

@mcp.tool()
def get_agents_hardware(
        pretty: bool = False,
        wait_for_complete: bool = False,
        agents_list: Optional[List[str]] = None,
        offset: int = 0,
        limit: int = 500,
        select: Optional[List[str]] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        q: Optional[str] = None,
        ram_free: Optional[int] = None,
        ram_total: Optional[int] = None,
        cpu_cores: Optional[int] = None,
        cpu_mhz: Optional[float] = None,
        cpu_name: Optional[str] = None,
        board_serial: Optional[str] = None
) -> Dict[str, Any]:
    """
    Return hardware info for all agents or a list of them.
    Corresponds to GET /experimental/syscollector/hardware.
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'agents_list': ','.join(agents_list) if agents_list else None,
        'offset': offset,
        'limit': limit,
        'select': ','.join(select) if select else None,
        'sort': sort,
        'search': search,
        'q': q,
        'ram.free': ram_free,
        'ram.total': ram_total,
        'cpu.cores': cpu_cores,
        'cpu.mhz': cpu_mhz,
        'cpu.name': cpu_name,
        'board_serial': board_serial
    }
    params = {k: v for k, v in params.items() if v is not None}
    try:
        logger.debug("Fetching agents hardware info from /experimental/syscollector/hardware")
        return api_client._make_request("GET", "/experimental/syscollector/hardware", params=params)
    except Exception as e:
        return handle_secure_error(e, "fetching agents hardware info")

@mcp.tool()
def get_agents_netaddr(
        pretty: bool = False,
        wait_for_complete: bool = False,
        agents_list: Optional[List[str]] = None,
        offset: int = 0,
        limit: int = 500,
        select: Optional[List[str]] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        proto: Optional[str] = None,
        address: Optional[str] = None,
        broadcast: Optional[str] = None,
        netmask: Optional[str] = None,
        q: Optional[str] = None
) -> Dict[str, Any]:
    """
    Return IPv4 and IPv6 addresses for all agents or a list of them.

    Args:
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        agents_list: List of agent IDs
        offset: First element to return
        limit: Maximum number of elements to return
        select: Fields to return
        sort: Fields to sort by
        search: Look for elements containing the specified string
        proto: Filter by IP protocol
        address: Filter by IP address
        broadcast: Filter by broadcast direction
        netmask: Filter by netmask
        q: Query to filter results

    Returns:
        Dictionary with network address information
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'agents_list': ','.join(agents_list) if agents_list else None,
        'offset': offset,
        'limit': limit,
        'select': ','.join(select) if select else None,
        'sort': sort,
        'search': search,
        'proto': proto,
        'address': address,
        'broadcast': broadcast,
        'netmask': netmask,
        'q': q
    }

    # Remove None values
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.debug("Fetching agents network addresses")
        endpoint = "/experimental/syscollector/netaddr"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        logger.error(f"Error fetching agents network addresses: {str(e)}")
        return {"error": str(e)}

@mcp.tool()
def get_agents_netiface(
        pretty: bool = False,
        wait_for_complete: bool = False,
        agents_list: Optional[List[str]] = None,
        offset: int = 0,
        limit: int = 500,
        select: Optional[List[str]] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        name: Optional[str] = None,
        adapter: Optional[str] = None,
        type: Optional[str] = None,
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
        q: Optional[str] = None
) -> Dict[str, Any]:
    """
    Return network interfaces for all agents or a list of them.

    Args:
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        agents_list: List of agent IDs
        offset: First element to return
        limit: Maximum number of elements to return
        select: Fields to return
        sort: Fields to sort by
        search: Look for elements containing the specified string
        name: Filter by name
        adapter: Filter by adapter
        type: Type of network
        state: Filter by state
        mtu: Filter by mtu
        tx_packets: Filter by tx.packets
        rx_packets: Filter by rx.packets
        tx_bytes: Filter by tx.bytes
        rx_bytes: Filter by rx.bytes
        tx_errors: Filter by tx.errors
        rx_errors: Filter by rx.errors
        tx_dropped: Filter by tx.dropped
        rx_dropped: Filter by rx.dropped
        q: Query to filter results

    Returns:
        Dictionary with network interfaces information
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'agents_list': ','.join(agents_list) if agents_list else None,
        'offset': offset,
        'limit': limit,
        'select': ','.join(select) if select else None,
        'sort': sort,
        'search': search,
        'name': name,
        'adapter': adapter,
        'type': type,
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
        'q': q
    }

    # Remove None values
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.debug("Fetching agents network interfaces")
        endpoint = "/experimental/syscollector/netiface"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        logger.error(f"Error fetching agents network interfaces: {str(e)}")
        return {"error": str(e)}

@mcp.tool()
def get_agents_netproto(
        pretty: bool = False,
        wait_for_complete: bool = False,
        agents_list: Optional[List[str]] = None,
        offset: int = 0,
        limit: int = 500,
        select: Optional[List[str]] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        q: Optional[str] = None,
        iface: Optional[str] = None,
        type: Optional[str] = None,
        gateway: Optional[str] = None,
        dhcp: Optional[str] = None
) -> Dict[str, Any]:
    """
    Return routing configuration for all agents or a list of them.

    Args:
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        agents_list: List of agent IDs
        offset: First element to return
        limit: Maximum number of elements to return
        select: Fields to return
        sort: Fields to sort by
        search: Look for elements containing the specified string
        q: Query to filter results
        iface: Filter by network interface
        type: Type of network
        gateway: Filter by network gateway
        dhcp: Filter by network dhcp (enabled, disabled, unknown, or BOOTP)

    Returns:
        Dictionary with network protocol information
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'agents_list': ','.join(agents_list) if agents_list else None,
        'offset': offset,
        'limit': limit,
        'select': ','.join(select) if select else None,
        'sort': sort,
        'search': search,
        'q': q,
        'iface': iface,
        'type': type,
        'gateway': gateway,
        'dhcp': dhcp
    }

    # Remove None values
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.debug("Fetching agents network protocols")
        endpoint = "/experimental/syscollector/netproto"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        logger.error(f"Error fetching agents network protocols: {str(e)}")
        return {"error": str(e)}

@mcp.tool()
def get_agents_os(
        pretty: bool = False,
        wait_for_complete: bool = False,
        agents_list: Optional[List[str]] = None,
        offset: int = 0,
        limit: int = 500,
        select: Optional[List[str]] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        q: Optional[str] = None,
        os_name: Optional[str] = None,
        architecture: Optional[str] = None,
        os_version: Optional[str] = None,
        version: Optional[str] = None,
        release: Optional[str] = None
) -> Dict[str, Any]:
    """
    Return OS info for all agents or a list of them.

    Args:
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        agents_list: List of agent IDs
        offset: First element to return
        limit: Maximum number of elements to return
        select: Fields to return
        sort: Fields to sort by
        search: Look for elements containing the specified string
        q: Query to filter results
        os_name: Filter by OS name
        architecture: Filter by architecture
        os_version: Filter by OS version
        version: Filter by agents version (formats: 'X.Y.Z', 'vX.Y.Z', 'wazuh X.Y.Z', 'wazuh vX.Y.Z')
        release: Filter by release

    Returns:
        Dictionary with OS information
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'agents_list': ','.join(agents_list) if agents_list else None,
        'offset': offset,
        'limit': limit,
        'select': ','.join(select) if select else None,
        'sort': sort,
        'search': search,
        'q': q,
        'os.name': os_name,
        'architecture': architecture,
        'os.version': os_version,
        'version': version,
        'release': release
    }

    # Remove None values
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.debug("Fetching agents OS information")
        endpoint = "/experimental/syscollector/os"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        logger.error(f"Error fetching agents OS information: {str(e)}")
        return {"error": str(e)}

@mcp.tool()
def get_agents_packages(
        pretty: bool = False,
        wait_for_complete: bool = False,
        agents_list: Optional[List[str]] = None,
        offset: int = 0,
        limit: int = 500,
        select: Optional[List[str]] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        q: Optional[str] = None,
        vendor: Optional[str] = None,
        name: Optional[str] = None,
        architecture: Optional[str] = None,
        format: Optional[str] = None,
        version: Optional[str] = None
) -> Dict[str, Any]:
    """
    Return packages info for all agents or a list of them.

    Args:
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        agents_list: List of agent IDs
        offset: First element to return
        limit: Maximum number of elements to return
        select: Fields to return
        sort: Fields to sort by
        search: Look for elements containing the specified string
        q: Query to filter results
        vendor: Filter by vendor
        name: Filter by name
        architecture: Filter by architecture
        format: Filter by file format (e.g., 'deb')
        version: Filter by package version

    Returns:
        Dictionary with packages information
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'agents_list': ','.join(agents_list) if agents_list else None,
        'offset': offset,
        'limit': limit,
        'select': ','.join(select) if select else None,
        'sort': sort,
        'search': search,
        'q': q,
        'vendor': vendor,
        'name': name,
        'architecture': architecture,
        'format': format,
        'version': version
    }

    # Remove None values
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.debug("Fetching agents packages information")
        endpoint = "/experimental/syscollector/packages"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        logger.error(f"Error fetching agents packages information: {str(e)}")
        return {"error": str(e)}

@mcp.tool()
def get_agents_ports(
        pretty: bool = False,
        wait_for_complete: bool = False,
        agents_list: Optional[List[str]] = None,
        offset: int = 0,
        limit: int = 500,
        select: Optional[List[str]] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        q: Optional[str] = None,
        pid: Optional[str] = None,
        protocol: Optional[str] = None,
        local_ip: Optional[str] = None,
        local_port: Optional[str] = None,
        remote_ip: Optional[str] = None,
        tx_queue: Optional[str] = None,
        state: Optional[str] = None,
        process: Optional[str] = None
) -> Dict[str, Any]:
    """
    Return ports info for all agents or a list of them.

    Args:
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        agents_list: List of agent IDs
        offset: First element to return
        limit: Maximum number of elements to return
        select: Fields to return
        sort: Fields to sort by
        search: Look for elements containing the specified string
        q: Query to filter results
        pid: Filter by pid
        protocol: Filter by protocol
        local_ip: Filter by Local IP
        local_port: Filter by Local Port
        remote_ip: Filter by Remote IP
        tx_queue: Filter by tx_queue
        state: Filter by state
        process: Filter by process name

    Returns:
        Dictionary with ports information
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'agents_list': ','.join(agents_list) if agents_list else None,
        'offset': offset,
        'limit': limit,
        'select': ','.join(select) if select else None,
        'sort': sort,
        'search': search,
        'q': q,
        'pid': pid,
        'protocol': protocol,
        'local.ip': local_ip,
        'local.port': local_port,
        'remote.ip': remote_ip,
        'tx_queue': tx_queue,
        'state': state,
        'process': process
    }

    # Remove None values
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.debug("Fetching agents ports information")
        endpoint = "/experimental/syscollector/ports"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        logger.error(f"Error fetching agents ports information: {str(e)}")
        return {"error": str(e)}

@mcp.tool()
def get_agents_processes(
        pretty: bool = False,
        wait_for_complete: bool = False,
        agents_list: Optional[List[str]] = None,
        offset: int = 0,
        limit: int = 500,
        select: Optional[List[str]] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
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
        q: Optional[str] = None
) -> Dict[str, Any]:
    """
    Return processes info for all agents or a list of them.

    Args:
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        agents_list: List of agent IDs
        offset: First element to return
        limit: Maximum number of elements to return
        select: Fields to return
        sort: Fields to sort by
        search: Look for elements containing the specified string
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

    Returns:
        Dictionary with processes information
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'agents_list': ','.join(agents_list) if agents_list else None,
        'offset': offset,
        'limit': limit,
        'select': ','.join(select) if select else None,
        'sort': sort,
        'search': search,
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
        'q': q
    }

    # Remove None values
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.debug("Fetching agents processes information")
        endpoint = "/experimental/syscollector/processes"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        logger.error(f"Error fetching agents processes information: {str(e)}")
        return {"error": str(e)}

@mcp.tool()
def get_agents_hotfixes(
        pretty: bool = False,
        wait_for_complete: bool = False,
        agents_list: Optional[List[str]] = None,
        offset: int = 0,
        limit: int = 500,
        select: Optional[List[str]] = None,
        sort: Optional[str] = None,
        search: Optional[str] = None,
        hotfix: Optional[str] = None,
        q: Optional[str] = None
) -> Dict[str, Any]:
    """
    Return hotfixes info for all agents or a list of them.

    Args:
        pretty: Show results in human-readable format
        wait_for_complete: Disable timeout response
        agents_list: List of agent IDs
        offset: First element to return
        limit: Maximum number of elements to return
        select: Fields to return
        sort: Fields to sort by
        search: Look for elements containing the specified string
        hotfix: Filter by hotfix
        q: Query to filter results

    Returns:
        Dictionary with hotfixes information
    """
    params = {
        'pretty': pretty,
        'wait_for_complete': wait_for_complete,
        'agents_list': ','.join(agents_list) if agents_list else None,
        'offset': offset,
        'limit': limit,
        'select': ','.join(select) if select else None,
        'sort': sort,
        'search': search,
        'hotfix': hotfix,
        'q': q
    }

    # Remove None values
    params = {k: v for k, v in params.items() if v is not None}

    try:
        logger.debug("Fetching agents hotfixes information")
        endpoint = "/experimental/syscollector/hotfixes"
        return api_client._make_request("GET", endpoint, params=params)
    except Exception as e:
        logger.error(f"Error fetching agents hotfixes information: {str(e)}")
        return {"error": str(e)}