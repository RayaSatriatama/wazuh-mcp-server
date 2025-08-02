"""
Wazuh Indexer Monitoring Tools - MCP Tools for Compact System Monitoring

This module provides MCP tools for compact monitoring information using the
_cat API endpoints, providing human-readable system status and metrics.

Following best practices:
- Clean code and PEP 8 compliance
- Comprehensive parameter validation
- GET-only operations for safety
- Detailed error handling
- Type hints and documentation
"""

from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta

from fastmcp import FastMCP

from .tool_clients import get_indexer_client
import logging

# Create MCP server instance
mcp = FastMCP("wazuh_indexer_monitoring_mcp")

# Initialize logger
logger = logging.getLogger(__name__)

# Initialize Wazuh configuration

# Get singleton client instance
# Client will be obtained in tool functions
@mcp.tool()
def get_cat_indices(
    index: str = "*",
    format: str = "json",
    bytes: str = "b",
    health: Optional[str] = None,
    pri: bool = False,
    include_unloaded_segments: bool = False,
    expand_wildcards: str = "open",
    human: bool = True,
    sort: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get compact indices information using _cat API.

    This tool provides a compact, human-readable view of indices information
    including document counts, storage sizes, and health status.

    Args:
        index: Index pattern to filter (default: * for all)
        format: Output format (json, yaml, text, csv)
        bytes: Unit for byte values (b, kb, mb, gb, tb, pb)
        health: Filter by health status (green, yellow, red)
        pri: Show only primary shards
        include_unloaded_segments: Include unloaded segments
        expand_wildcards: Wildcard expansion (open, closed, hidden, none, all)
        human: Return human readable values
        sort: Sort by column (index, docs.count, store.size, etc.)

    Returns:
        Dictionary containing compact indices information
    """
    try:
        params = {
            "format": format,
            "bytes": bytes,
            "include_unloaded_segments": str(include_unloaded_segments).lower(),
            "expand_wildcards": expand_wildcards,
            "h": "index,health,status,uuid,pri,rep,docs.count,docs.deleted,store.size,pri.store.size",
            "v": "true" if human else "false"
        }

        if health:
            params["health"] = health
        if pri:
            params["pri"] = "true"
        if sort:
            params["s"] = sort

        endpoint = f"/_cat/indices/{index}"
        response = get_indexer_client()._make_request("GET", endpoint, params=params)

        # Process response and add metadata
        result = {
            "timestamp": datetime.utcnow().isoformat(),
            "requested_index": index,
            "format": format,
            "data": response
        }

        # Add analysis if JSON format
        if format == "json" and isinstance(response, list):
            analysis = {
                "total_indices": len(response),
                "green_indices": len([idx for idx in response if idx.get("health") == "green"]),
                "yellow_indices": len([idx for idx in response if idx.get("health") == "yellow"]),
                "red_indices": len([idx for idx in response if idx.get("health") == "red"]),
                "total_docs": sum([int(idx.get("docs.count", 0) or 0) for idx in response]),
                "total_size": sum([self._parse_size(idx.get("store.size", "0b")) for idx in response]),
                "wazuh_indices": len([idx for idx in response if "wazuh" in idx.get("index", "").lower()])
            }
            result["analysis"] = analysis

        logger.debug(f"Retrieved compact info for {index} indices")
        return result

    except Exception as e:
        logger.error(f"Error getting cat indices for {index}: {str(e)}")
        return {"error": str(e), "index": index}

@mcp.tool()
def get_cat_nodes(
    format: str = "json",
    bytes: str = "b",
    full_id: bool = False,
    master_timeout: str = "30s",
    human: bool = True,
    sort: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get compact nodes information using _cat API.

    This tool provides a compact view of cluster nodes including
    roles, load, memory usage, and disk usage.

    Args:
        format: Output format (json, yaml, text, csv)
        bytes: Unit for byte values (b, kb, mb, gb, tb, pb)
        full_id: Show full node IDs
        master_timeout: Master node timeout
        human: Return human readable values
        sort: Sort by column (name, heap.percent, ram.percent, etc.)

    Returns:
        Dictionary containing compact nodes information
    """
    try:
        params = {
            "format": format,
            "bytes": bytes,
            "full_id": str(full_id).lower(),
            "master_timeout": master_timeout,
            "h": "ip,heap.percent,ram.percent,cpu,load_1m,load_5m,load_15m,node.role,master,name",
            "v": "true" if human else "false"
        }

        if sort:
            params["s"] = sort

        endpoint = "/_cat/nodes"
        response = get_indexer_client()._make_request("GET", endpoint, params=params)

        # Process response and add metadata
        result = {
            "timestamp": datetime.utcnow().isoformat(),
            "format": format,
            "data": response
        }

        # Add analysis if JSON format
        if format == "json" and isinstance(response, list):
            analysis = {
                "total_nodes": len(response),
                "master_nodes": len([node for node in response if node.get("master") == "*"]),
                "data_nodes": len([node for node in response if "d" in node.get("node.role", "")]),
                "ingest_nodes": len([node for node in response if "i" in node.get("node.role", "")]),
                "avg_heap_percent": sum([float(node.get("heap.percent", 0) or 0) for node in response]) / max(len(response), 1),
                "avg_ram_percent": sum([float(node.get("ram.percent", 0) or 0) for node in response]) / max(len(response), 1),
                "high_memory_nodes": len([node for node in response if float(node.get("ram.percent", 0) or 0) > 80]),
                "high_heap_nodes": len([node for node in response if float(node.get("heap.percent", 0) or 0) > 80])
            }
            result["analysis"] = analysis

        logger.debug(f"Retrieved compact info for {len(response) if isinstance(response, list) else 'unknown'} nodes")
        return result

    except Exception as e:
        logger.error(f"Error getting cat nodes: {str(e)}")
        return {"error": str(e)}

@mcp.tool()
def get_cat_shards(
    index: str = "*",
    format: str = "json",
    bytes: str = "b",
    human: bool = True,
    sort: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get compact shards information using _cat API.

    This tool provides detailed information about shard distribution,
    sizes, and status across the cluster.

    Args:
        index: Index pattern to filter shards
        format: Output format (json, yaml, text, csv)
        bytes: Unit for byte values (b, kb, mb, gb, tb, pb)
        human: Return human readable values
        sort: Sort by column (index, shard, prirep, state, docs, store, etc.)

    Returns:
        Dictionary containing compact shards information
    """
    try:
        params = {
            "format": format,
            "bytes": bytes,
            "h": "index,shard,prirep,state,docs,store,ip,node",
            "v": "true" if human else "false"
        }

        if sort:
            params["s"] = sort

        endpoint = f"/_cat/shards/{index}"
        response = get_indexer_client()._make_request("GET", endpoint, params=params)

        # Process response and add metadata
        result = {
            "timestamp": datetime.utcnow().isoformat(),
            "requested_index": index,
            "format": format,
            "data": response
        }

        # Add analysis if JSON format
        if format == "json" and isinstance(response, list):
            analysis = {
                "total_shards": len(response),
                "primary_shards": len([shard for shard in response if shard.get("prirep") == "p"]),
                "replica_shards": len([shard for shard in response if shard.get("prirep") == "r"]),
                "started_shards": len([shard for shard in response if shard.get("state") == "STARTED"]),
                "relocating_shards": len([shard for shard in response if shard.get("state") == "RELOCATING"]),
                "initializing_shards": len([shard for shard in response if shard.get("state") == "INITIALIZING"]),
                "unassigned_shards": len([shard for shard in response if shard.get("state") == "UNASSIGNED"]),
                "total_docs": sum([int(shard.get("docs", 0) or 0) for shard in response]),
                "total_size": sum([self._parse_size(shard.get("store", "0b")) for shard in response])
            }
            
            # Node distribution analysis
            node_distribution = {}
            for shard in response:
                node = shard.get("node", "unknown")
                if node != "unknown":
                    node_distribution[node] = node_distribution.get(node, 0) + 1
            
            analysis["node_distribution"] = node_distribution
            analysis["nodes_with_shards"] = len(node_distribution)
            
            result["analysis"] = analysis

        logger.debug(f"Retrieved compact shard info for {index}")
        return result

    except Exception as e:
        logger.error(f"Error getting cat shards for {index}: {str(e)}")
        return {"error": str(e), "index": index}

@mcp.tool()
def get_cat_allocation(
    node_id: str = "*",
    format: str = "json",
    bytes: str = "b",
    human: bool = True,
    sort: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get compact disk allocation information using _cat API.

    This tool provides information about disk usage and allocation
    across cluster nodes.

    Args:
        node_id: Node ID or pattern to filter
        format: Output format (json, yaml, text, csv)
        bytes: Unit for byte values (b, kb, mb, gb, tb, pb)
        human: Return human readable values
        sort: Sort by column (shards, disk.indices, disk.used, disk.avail, etc.)

    Returns:
        Dictionary containing compact allocation information
    """
    try:
        params = {
            "format": format,
            "bytes": bytes,
            "h": "shards,disk.indices,disk.used,disk.avail,disk.total,disk.percent,host,ip,node",
            "v": "true" if human else "false"
        }

        if sort:
            params["s"] = sort

        endpoint = f"/_cat/allocation/{node_id}"
        response = get_indexer_client()._make_request("GET", endpoint, params=params)

        # Process response and add metadata
        result = {
            "timestamp": datetime.utcnow().isoformat(),
            "requested_node": node_id,
            "format": format,
            "data": response
        }

        # Add analysis if JSON format
        if format == "json" and isinstance(response, list):
            analysis = {
                "total_nodes": len(response),
                "total_shards": sum([int(node.get("shards", 0) or 0) for node in response]),
                "total_disk_used": sum([self._parse_size(node.get("disk.used", "0b")) for node in response]),
                "total_disk_available": sum([self._parse_size(node.get("disk.avail", "0b")) for node in response]),
                "total_disk_size": sum([self._parse_size(node.get("disk.total", "0b")) for node in response]),
                "avg_disk_percent": sum([float(node.get("disk.percent", 0) or 0) for node in response]) / max(len(response), 1),
                "high_disk_usage_nodes": len([node for node in response if float(node.get("disk.percent", 0) or 0) > 80]),
                "low_disk_space_nodes": len([node for node in response if float(node.get("disk.percent", 0) or 0) > 95])
            }
            result["analysis"] = analysis

        logger.debug(f"Retrieved compact allocation info for {node_id}")
        return result

    except Exception as e:
        logger.error(f"Error getting cat allocation for {node_id}: {str(e)}")
        return {"error": str(e), "node_id": node_id}

@mcp.tool()
def get_cat_health(
    format: str = "json",
    human: bool = True
) -> Dict[str, Any]:
    """
    Get compact cluster health information using _cat API.

    This tool provides a simple overview of cluster health status.

    Args:
        format: Output format (json, yaml, text, csv)
        human: Return human readable values

    Returns:
        Dictionary containing compact health information
    """
    try:
        params = {
            "format": format,
            "h": "epoch,timestamp,cluster,status,node.total,node.data,shards,pri,relo,init,unassign,pending_tasks,max_task_wait_time,active_shards_percent",
            "v": "true" if human else "false"
        }

        endpoint = "/_cat/health"
        response = get_indexer_client()._make_request("GET", endpoint, params=params)

        # Process response and add metadata
        result = {
            "timestamp": datetime.utcnow().isoformat(),
            "format": format,
            "data": response
        }

        # Add analysis if JSON format and response is list with data
        if format == "json" and isinstance(response, list) and len(response) > 0:
            health_data = response[0]  # Health returns single row
            
            analysis = {
                "cluster_status": health_data.get("status", "unknown"),
                "is_healthy": health_data.get("status") == "green",
                "has_issues": health_data.get("status") in ["yellow", "red"],
                "total_nodes": int(health_data.get("node.total", 0) or 0),
                "data_nodes": int(health_data.get("node.data", 0) or 0),
                "total_shards": int(health_data.get("shards", 0) or 0),
                "primary_shards": int(health_data.get("pri", 0) or 0),
                "relocating_shards": int(health_data.get("relo", 0) or 0),
                "initializing_shards": int(health_data.get("init", 0) or 0),
                "unassigned_shards": int(health_data.get("unassign", 0) or 0),
                "pending_tasks": int(health_data.get("pending_tasks", 0) or 0),
                "active_shards_percent": float(health_data.get("active_shards_percent", 0) or 0)
            }
            
            # Health assessment
            analysis["health_assessment"] = {
                "overall_status": "healthy" if analysis["is_healthy"] else "needs_attention",
                "has_unassigned_shards": analysis["unassigned_shards"] > 0,
                "has_pending_tasks": analysis["pending_tasks"] > 0,
                "shards_fully_active": analysis["active_shards_percent"] >= 100.0
            }
            
            result["analysis"] = analysis

        logger.debug(f"Retrieved compact cluster health information")
        return result

    except Exception as e:
        logger.error(f"Error getting cat health: {str(e)}")
        return {"error": str(e)}

@mcp.tool()
def get_cat_pending_tasks(
    format: str = "json",
    human: bool = True,
    sort: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get compact pending tasks information using _cat API.

    This tool shows cluster tasks that are pending execution.

    Args:
        format: Output format (json, yaml, text, csv)
        human: Return human readable values
        sort: Sort by column (insertOrder, timeInQueue, priority, source)

    Returns:
        Dictionary containing compact pending tasks information
    """
    try:
        params = {
            "format": format,
            "h": "insertOrder,timeInQueue,priority,source",
            "v": "true" if human else "false"
        }

        if sort:
            params["s"] = sort

        endpoint = "/_cat/pending_tasks"
        response = get_indexer_client()._make_request("GET", endpoint, params=params)

        # Process response and add metadata
        result = {
            "timestamp": datetime.utcnow().isoformat(),
            "format": format,
            "data": response
        }

        # Add analysis if JSON format
        if format == "json" and isinstance(response, list):
            analysis = {
                "total_pending_tasks": len(response),
                "has_pending_tasks": len(response) > 0,
                "high_priority_tasks": len([task for task in response if task.get("priority", "").lower() in ["urgent", "high"]]),
                "sources": list(set([task.get("source", "unknown") for task in response])),
                "longest_queue_time": max([task.get("timeInQueue", "0s") for task in response], default="0s"),
                "task_priorities": list(set([task.get("priority", "unknown") for task in response]))
            }
            result["analysis"] = analysis

        logger.debug(f"Retrieved {len(response) if isinstance(response, list) else 'unknown'} pending tasks")
        return result

    except Exception as e:
        logger.error(f"Error getting cat pending tasks: {str(e)}")
        return {"error": str(e)}

@mcp.tool()
def get_cat_plugins(
    format: str = "json",
    human: bool = True,
    sort: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get compact plugins information using _cat API.

    This tool shows installed plugins across cluster nodes.

    Args:
        format: Output format (json, yaml, text, csv)
        human: Return human readable values
        sort: Sort by column (name, component, version, type)

    Returns:
        Dictionary containing compact plugins information
    """
    try:
        params = {
            "format": format,
            "h": "name,component,version,type,description",
            "v": "true" if human else "false"
        }

        if sort:
            params["s"] = sort

        endpoint = "/_cat/plugins"
        response = get_indexer_client()._make_request("GET", endpoint, params=params)

        # Process response and add metadata
        result = {
            "timestamp": datetime.utcnow().isoformat(),
            "format": format,
            "data": response
        }

        # Add analysis if JSON format
        if format == "json" and isinstance(response, list):
            analysis = {
                "total_plugins": len(response),
                "unique_plugins": len(set([plugin.get("component", "unknown") for plugin in response])),
                "security_plugins": len([plugin for plugin in response if "security" in plugin.get("component", "").lower()]),
                "wazuh_plugins": len([plugin for plugin in response if "wazuh" in plugin.get("component", "").lower()]),
                "plugin_types": list(set([plugin.get("type", "unknown") for plugin in response])),
                "plugin_versions": list(set([plugin.get("version", "unknown") for plugin in response])),
                "nodes_with_plugins": list(set([plugin.get("name", "unknown") for plugin in response]))
            }
            result["analysis"] = analysis

        logger.debug(f"Retrieved {len(response) if isinstance(response, list) else 'unknown'} plugins")
        return result

    except Exception as e:
        logger.error(f"Error getting cat plugins: {str(e)}")
        return {"error": str(e)}

@mcp.tool()
def get_cat_thread_pool(
    thread_pool_patterns: str = "*",
    format: str = "json",
    human: bool = True,
    sort: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get compact thread pool information using _cat API.

    This tool shows thread pool statistics across cluster nodes
    for monitoring performance and resource usage.

    Args:
        thread_pool_patterns: Thread pool patterns to include
        format: Output format (json, yaml, text, csv)
        human: Return human readable values
        sort: Sort by column (node_name, name, active, queue, rejected)

    Returns:
        Dictionary containing compact thread pool information
    """
    try:
        params = {
            "format": format,
            "h": "node_name,name,active,queue,rejected,largest,completed,core,max,size,keep_alive",
            "v": "true" if human else "false"
        }

        if sort:
            params["s"] = sort

        endpoint = f"/_cat/thread_pool/{thread_pool_patterns}"
        response = get_indexer_client()._make_request("GET", endpoint, params=params)

        # Process response and add metadata
        result = {
            "timestamp": datetime.utcnow().isoformat(),
            "requested_patterns": thread_pool_patterns,
            "format": format,
            "data": response
        }

        # Add analysis if JSON format
        if format == "json" and isinstance(response, list):
            analysis = {
                "total_thread_pools": len(response),
                "nodes_count": len(set([tp.get("node_name", "unknown") for tp in response])),
                "thread_pool_types": list(set([tp.get("name", "unknown") for tp in response])),
                "total_active_threads": sum([int(tp.get("active", 0) or 0) for tp in response]),
                "total_queued_tasks": sum([int(tp.get("queue", 0) or 0) for tp in response]),
                "total_rejected_tasks": sum([int(tp.get("rejected", 0) or 0) for tp in response]),
                "pools_with_active_threads": len([tp for tp in response if int(tp.get("active", 0) or 0) > 0]),
                "pools_with_queued_tasks": len([tp for tp in response if int(tp.get("queue", 0) or 0) > 0]),
                "pools_with_rejections": len([tp for tp in response if int(tp.get("rejected", 0) or 0) > 0])
            }
            
            # High utilization analysis
            high_utilization_pools = []
            for tp in response:
                active = int(tp.get("active", 0) or 0)
                max_threads = int(tp.get("max", 0) or 0)
                if max_threads > 0 and (active / max_threads) > 0.8:
                    high_utilization_pools.append({
                        "node": tp.get("node_name"),
                        "pool": tp.get("name"),
                        "utilization_percent": round((active / max_threads) * 100, 2)
                    })
            
            analysis["high_utilization_pools"] = high_utilization_pools
            result["analysis"] = analysis

        logger.debug(f"Retrieved thread pool info for {thread_pool_patterns}")
        return result

    except Exception as e:
        logger.error(f"Error getting cat thread pool for {thread_pool_patterns}: {str(e)}")
        return {"error": str(e), "patterns": thread_pool_patterns}

def _parse_size(size_str: str) -> float:
    """Parse size string to bytes for calculations."""
    if not size_str or size_str == "-":
        return 0.0
    
    try:
        # Remove any spaces and convert to lowercase
        size_str = size_str.strip().lower()
        
        # Extract number and unit
        import re
        match = re.match(r'([0-9.]+)([a-z]*)', size_str)
        if not match:
            return 0.0
            
        number = float(match.group(1))
        unit = match.group(2) or 'b'
        
        # Convert to bytes
        multipliers = {
            'b': 1,
            'kb': 1024,
            'mb': 1024**2,
            'gb': 1024**3,
            'tb': 1024**4,
            'pb': 1024**5
        }
        
        return number * multipliers.get(unit, 1)
        
    except (ValueError, AttributeError):
        return 0.0 