"""
Wazuh Indexer Cluster Tools - MCP Tools for Cluster Management and Monitoring

This module provides MCP tools for monitoring and managing the Wazuh Indexer cluster,
including health checks, node information, cluster settings, and performance metrics.

Following best practices:
- Clean code and PEP 8 compliance
- Comprehensive parameter validation
- GET-only operations for safety
- Detailed error handling
- Type hints and documentation
"""

from typing import Any, Dict, List, Optional
from datetime import datetime

from fastmcp import FastMCP

from .tool_clients import get_indexer_client
import logging

# Create MCP server instance
mcp = FastMCP("wazuh_indexer_cluster_mcp")

# Initialize logger
logger = logging.getLogger(__name__)

# Client instance will be obtained in tool functions to avoid import-time issues

@mcp.tool()
def get_cluster_health(
    level: str = "cluster",
    wait_for_status: Optional[str] = None,
    wait_for_no_relocating_shards: bool = False,
    wait_for_no_initializing_shards: bool = False,
    wait_for_active_shards: Optional[str] = None,
    wait_for_nodes: Optional[str] = None,
    timeout: str = "30s",
    master_timeout: str = "30s"
) -> Dict[str, Any]:
    """
    Get cluster health information.

    This tool provides comprehensive health information about the Wazuh Indexer
    cluster, including status, node counts, and shard information.

    Args:
        level: Level of detail (cluster, indices, shards)
        wait_for_status: Wait for specific status (green, yellow, red)
        wait_for_no_relocating_shards: Wait for no relocating shards
        wait_for_no_initializing_shards: Wait for no initializing shards
        wait_for_active_shards: Wait for active shards (number or 'all')
        wait_for_nodes: Wait for number of nodes (e.g., '>=2')
        timeout: Request timeout (e.g., '30s', '1m')
        master_timeout: Master node timeout

    Returns:
        Dictionary containing cluster health information
    """
    try:
        params = {
            "level": level,
            "timeout": timeout,
            "master_timeout": master_timeout
        }

        # Add optional wait conditions
        if wait_for_status:
            params["wait_for_status"] = wait_for_status
        if wait_for_no_relocating_shards:
            params["wait_for_no_relocating_shards"] = "true"
        if wait_for_no_initializing_shards:
            params["wait_for_no_initializing_shards"] = "true"
        if wait_for_active_shards:
            params["wait_for_active_shards"] = wait_for_active_shards
        if wait_for_nodes:
            params["wait_for_nodes"] = wait_for_nodes

        endpoint = "/_cluster/health"
        response = get_indexer_client()._make_request("GET", endpoint, params=params)

        # Add timestamp and human-readable status
        response["timestamp"] = datetime.utcnow().isoformat()
        response["status_description"] = {
            "green": "All shards are allocated",
            "yellow": "All primary shards are allocated, some replicas are not",
            "red": "Some primary shards are not allocated"
        }.get(response.get("status", "unknown"), "Unknown status")

        logger.info(f"Cluster health: {response.get('status')} - {response.get('number_of_nodes')} nodes")
        return response

    except Exception as e:
        logger.error(f"Error getting cluster health: {str(e)}")
        return {"error": str(e), "status": "unknown"}

@mcp.tool()
def get_cluster_stats(
    node_id: Optional[str] = None,
    human: bool = True,
    flat_settings: bool = False
) -> Dict[str, Any]:
    """
    Get cluster statistics and performance metrics.

    This tool retrieves comprehensive statistics about the cluster including
    indices, nodes, shards, and storage information.

    Args:
        node_id: Comma-separated list of node IDs or names to include
        human: Return human readable values
        flat_settings: Return settings in flat format

    Returns:
        Dictionary containing detailed cluster statistics
    """
    try:
        params = {}
        if human:
            params["human"] = "true"
        if flat_settings:
            params["flat_settings"] = "true"

        endpoint = "/_cluster/stats"
        if node_id:
            endpoint = f"/_cluster/stats/nodes/{node_id}"

        response = get_indexer_client()._make_request("GET", endpoint, params=params)

        # Add timestamp
        response["timestamp"] = datetime.utcnow().isoformat()

        # Calculate some useful metrics if available
        if "indices" in response:
            indices_stats = response["indices"]
            if "count" in indices_stats and "shards" in indices_stats:
                response["avg_shards_per_index"] = (
                    indices_stats["shards"]["total"] / max(indices_stats["count"], 1)
                )

        logger.debug(f"Retrieved cluster stats for {response.get('nodes', {}).get('count', 'unknown')} nodes")
        return response

    except Exception as e:
        logger.error(f"Error getting cluster stats: {str(e)}")
        return {"error": str(e), "stats": {}}

@mcp.tool()
def get_cluster_settings(
    include_defaults: bool = False,
    flat_settings: bool = False,
    master_timeout: str = "30s",
    timeout: str = "30s"
) -> Dict[str, Any]:
    """
    Get cluster settings configuration.

    This tool retrieves the current cluster settings including persistent
    and transient configurations.

    Args:
        include_defaults: Include default settings
        flat_settings: Return settings in flat format
        master_timeout: Master node timeout
        timeout: Request timeout

    Returns:
        Dictionary containing cluster settings
    """
    try:
        params = {
            "master_timeout": master_timeout,
            "timeout": timeout
        }

        if include_defaults:
            params["include_defaults"] = "true"
        if flat_settings:
            params["flat_settings"] = "true"

        endpoint = "/_cluster/settings"
        response = get_indexer_client()._make_request("GET", endpoint, params=params)

        # Add metadata
        response["timestamp"] = datetime.utcnow().isoformat()
        response["settings_summary"] = {
            "persistent_settings": len(response.get("persistent", {})),
            "transient_settings": len(response.get("transient", {}))
        }

        if include_defaults:
            response["settings_summary"]["default_settings"] = len(response.get("defaults", {}))

        logger.debug(f"Retrieved cluster settings")
        return response

    except Exception as e:
        logger.error(f"Error getting cluster settings: {str(e)}")
        return {"error": str(e), "settings": {}}

@mcp.tool()
def get_nodes_info(
    node_id: Optional[str] = None,
    metric: Optional[str] = None,
    human: bool = True,
    flat_settings: bool = False,
    timeout: str = "30s"
) -> Dict[str, Any]:
    """
    Get information about cluster nodes.

    This tool retrieves detailed information about nodes in the cluster
    including configuration, plugins, and system information.

    Args:
        node_id: Comma-separated list of node IDs, names, or attributes
        metric: Comma-separated list of metrics (settings, os, process, jvm, etc.)
        human: Return human readable values
        flat_settings: Return settings in flat format
        timeout: Request timeout

    Returns:
        Dictionary containing node information
    """
    try:
        params = {
            "timeout": timeout
        }

        if human:
            params["human"] = "true"
        if flat_settings:
            params["flat_settings"] = "true"

        # Build endpoint
        endpoint = "/_nodes"
        if node_id:
            endpoint = f"/_nodes/{node_id}"
        if metric:
            endpoint = f"{endpoint}/{metric}"

        response = get_indexer_client()._make_request("GET", endpoint, params=params)

        # Add summary information
        nodes = response.get("nodes", {})
        response["summary"] = {
            "total_nodes": len(nodes),
            "timestamp": datetime.utcnow().isoformat()
        }

        # Count node roles if available
        if nodes:
            role_counts = {}
            for node_data in nodes.values():
                roles = node_data.get("roles", [])
                for role in roles:
                    role_counts[role] = role_counts.get(role, 0) + 1
            response["summary"]["node_roles"] = role_counts

        logger.debug(f"Retrieved info for {len(nodes)} nodes")
        return response

    except Exception as e:
        logger.error(f"Error getting nodes info: {str(e)}")
        return {"error": str(e), "nodes": {}}

@mcp.tool()
def get_nodes_stats(
    node_id: Optional[str] = None,
    metric: Optional[str] = None,
    index_metric: Optional[str] = None,
    completion_fields: Optional[str] = None,
    fielddata_fields: Optional[str] = None,
    fields: Optional[str] = None,
    groups: bool = True,
    human: bool = True,
    level: str = "node",
    timeout: str = "30s"
) -> Dict[str, Any]:
    """
    Get node statistics and performance metrics.

    This tool retrieves runtime statistics about nodes including memory usage,
    CPU, network, and storage metrics.

    Args:
        node_id: Comma-separated list of node IDs or names
        metric: Comma-separated list of metrics (indices, os, process, jvm, etc.)
        index_metric: Comma-separated list of index metrics
        completion_fields: Comma-separated list of completion fields
        fielddata_fields: Comma-separated list of fielddata fields
        fields: Comma-separated list of search fields
        groups: Include stats groups
        human: Return human readable values
        level: Level of detail (node, indices, shards)
        timeout: Request timeout

    Returns:
        Dictionary containing node statistics
    """
    try:
        params = {
            "timeout": timeout,
            "level": level
        }

        if groups:
            params["groups"] = "true"
        if human:
            params["human"] = "true"
        if completion_fields:
            params["completion_fields"] = completion_fields
        if fielddata_fields:
            params["fielddata_fields"] = fielddata_fields
        if fields:
            params["fields"] = fields

        # Build endpoint
        endpoint = "/_nodes/stats"
        if node_id:
            endpoint = f"/_nodes/{node_id}/stats"
        if metric:
            endpoint = f"{endpoint}/{metric}"
        if index_metric:
            endpoint = f"{endpoint}/{index_metric}"

        response = get_indexer_client()._make_request("GET", endpoint, params=params)

        # Add summary and analysis
        nodes = response.get("nodes", {})
        response["summary"] = {
            "total_nodes": len(nodes),
            "timestamp": datetime.utcnow().isoformat()
        }

        # Calculate cluster-wide totals if available
        if nodes:
            cluster_totals = {
                "memory_used_bytes": 0,
                "memory_free_bytes": 0,
                "disk_total_bytes": 0,
                "disk_free_bytes": 0,
                "cpu_percent": []
            }

            for node_data in nodes.values():
                # Memory stats
                if "os" in node_data and "mem" in node_data["os"]:
                    mem = node_data["os"]["mem"]
                    cluster_totals["memory_used_bytes"] += mem.get("used_in_bytes", 0)
                    cluster_totals["memory_free_bytes"] += mem.get("free_in_bytes", 0)

                # Disk stats
                if "fs" in node_data and "total" in node_data["fs"]:
                    fs = node_data["fs"]["total"]
                    cluster_totals["disk_total_bytes"] += fs.get("total_in_bytes", 0)
                    cluster_totals["disk_free_bytes"] += fs.get("free_in_bytes", 0)

                # CPU stats
                if "os" in node_data and "cpu" in node_data["os"]:
                    cpu_percent = node_data["os"]["cpu"].get("percent")
                    if cpu_percent is not None:
                        cluster_totals["cpu_percent"].append(cpu_percent)

            # Calculate averages and percentages
            if cluster_totals["cpu_percent"]:
                cluster_totals["avg_cpu_percent"] = sum(cluster_totals["cpu_percent"]) / len(cluster_totals["cpu_percent"])
                del cluster_totals["cpu_percent"]

            if cluster_totals["disk_total_bytes"] > 0:
                cluster_totals["disk_used_percent"] = (
                    (cluster_totals["disk_total_bytes"] - cluster_totals["disk_free_bytes"]) /
                    cluster_totals["disk_total_bytes"] * 100
                )

            response["cluster_totals"] = cluster_totals

        logger.debug(f"Retrieved stats for {len(nodes)} nodes")
        return response

    except Exception as e:
        logger.error(f"Error getting nodes stats: {str(e)}")
        return {"error": str(e), "nodes": {}}

@mcp.tool()
def get_cluster_allocation_explain(
    index: Optional[str] = None,
    shard: Optional[int] = None,
    primary: Optional[bool] = None,
    current_node: Optional[str] = None,
    include_yes_decisions: bool = False,
    include_disk_info: bool = False,
    human: bool = True
) -> Dict[str, Any]:
    """
    Explain cluster allocation decisions.

    This tool provides detailed explanations about why shards are allocated
    or not allocated to specific nodes.

    Args:
        index: Index name for shard allocation explanation
        shard: Shard number
        primary: Whether to explain primary shard (true/false)
        current_node: Current node hosting the shard
        include_yes_decisions: Include positive allocation decisions
        include_disk_info: Include disk usage information
        human: Return human readable values

    Returns:
        Dictionary containing allocation explanations
    """
    try:
        params = {}

        if include_yes_decisions:
            params["include_yes_decisions"] = "true"
        if include_disk_info:
            params["include_disk_info"] = "true"
        if human:
            params["human"] = "true"

        request_body = {}

        # Build request body for specific shard
        if index is not None:
            request_body["index"] = index
        if shard is not None:
            request_body["shard"] = shard
        if primary is not None:
            request_body["primary"] = primary
        if current_node:
            request_body["current_node"] = current_node

        endpoint = "/_cluster/allocation/explain"

        if request_body:
            response = get_indexer_client()._make_request("GET", endpoint, params=params, json=request_body)
        else:
            response = get_indexer_client()._make_request("GET", endpoint, params=params)

        # Add timestamp and summary
        response["timestamp"] = datetime.utcnow().isoformat()

        if "allocate_explanation" in response:
            response["summary"] = {
                "allocation_status": response.get("allocate_explanation", "unknown"),
                "can_allocate": response.get("can_allocate", "unknown")
            }

        logger.debug(f"Retrieved cluster allocation explanation")
        return response

    except Exception as e:
        logger.error(f"Error getting allocation explanation: {str(e)}")
        return {"error": str(e), "explanation": {}}

@mcp.tool()
def get_cluster_pending_tasks(
    human: bool = True,
    detailed: bool = False,
    master_timeout: str = "30s"
) -> Dict[str, Any]:
    """
    Get cluster pending tasks.

    This tool retrieves information about tasks waiting to be executed
    by the cluster master node.

    Args:
        human: Return human readable values
        detailed: Return detailed task information
        master_timeout: Master node timeout

    Returns:
        Dictionary containing pending tasks information
    """
    try:
        params = {
            "master_timeout": master_timeout
        }

        if human:
            params["human"] = "true"
        if detailed:
            params["detailed"] = "true"

        endpoint = "/_cluster/pending_tasks"
        response = get_indexer_client()._make_request("GET", endpoint, params=params)

        # Add summary information
        tasks = response.get("tasks", [])
        response["summary"] = {
            "total_tasks": len(tasks),
            "timestamp": datetime.utcnow().isoformat()
        }

        # Categorize tasks by type
        if tasks:
            task_types = {}
            priorities = []

            for task in tasks:
                task_type = task.get("source", "unknown")
                task_types[task_type] = task_types.get(task_type, 0) + 1

                priority = task.get("priority")
                if priority is not None:
                    priorities.append(priority)

            response["summary"]["task_types"] = task_types
            if priorities:
                response["summary"]["priority_stats"] = {
                    "min_priority": min(priorities),
                    "max_priority": max(priorities),
                    "avg_priority": sum(priorities) / len(priorities)
                }

        logger.debug(f"Retrieved {len(tasks)} pending tasks")
        return response

    except Exception as e:
        logger.error(f"Error getting pending tasks: {str(e)}")
        return {"error": str(e), "tasks": []}