"""
Wazuh Indexer Index Management Tools - MCP Tools for Index Operations

This module provides MCP tools for managing and monitoring Wazuh Indexer indices,
including metadata, statistics, mappings, settings, and templates.

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
mcp = FastMCP("wazuh_indexer_index_mcp")

# Initialize logger
logger = logging.getLogger(__name__)

# Initialize Wazuh configuration

# Get singleton client instance
# Client will be obtained in tool functions
@mcp.tool()
def get_index_info(
    index: str,
    allow_no_indices: bool = False,
    expand_wildcards: str = "open",
    flat_settings: bool = False,
    include_defaults: bool = False,
    ignore_unavailable: bool = False,
    human: bool = True
) -> Dict[str, Any]:
    """
    Get detailed information about one or more indices.

    This tool retrieves comprehensive information about Wazuh indices including
    settings, mappings, aliases, and metadata.

    Args:
        index: Index name or pattern (e.g., wazuh-alerts-*, wazuh-states-*)
        allow_no_indices: Whether to ignore if indices don't exist
        expand_wildcards: Whether to expand wildcards (open, closed, hidden, none, all)
        flat_settings: Return settings in flat format
        include_defaults: Include default settings
        ignore_unavailable: Whether to ignore unavailable indices
        human: Return human readable values

    Returns:
        Dictionary containing detailed index information
    """
    try:
        params = {
            "allow_no_indices": str(allow_no_indices).lower(),
            "expand_wildcards": expand_wildcards,
            "flat_settings": str(flat_settings).lower(),
            "include_defaults": str(include_defaults).lower(),
            "ignore_unavailable": str(ignore_unavailable).lower(),
            "human": str(human).lower()
        }

        endpoint = f"/{index}"
        response = get_indexer_client()._make_request("GET", endpoint, params=params)

        # Add metadata
        response["timestamp"] = datetime.utcnow().isoformat()
        response["requested_index"] = index
        response["indices_found"] = len(response) if isinstance(response, dict) else 0

        # Process each index for additional insights
        if isinstance(response, dict):
            for idx_name, idx_data in response.items():
                if idx_name not in ["timestamp", "requested_index", "indices_found"]:
                    # Add useful metadata
                    if "settings" in idx_data and "index" in idx_data["settings"]:
                        settings = idx_data["settings"]["index"]
                        idx_data["index_metadata"] = {
                            "creation_date": settings.get("creation_date"),
                            "number_of_shards": settings.get("number_of_shards"),
                            "number_of_replicas": settings.get("number_of_replicas"),
                            "uuid": settings.get("uuid")
                        }

        logger.debug(f"Retrieved information for index pattern: {index}")
        return response

    except Exception as e:
        logger.error(f"Error getting index info for {index}: {str(e)}")
        return {"error": str(e), "index": index}

@mcp.tool()
def get_index_stats(
    index: str = "_all",
    metric: Optional[str] = None,
    completion_fields: Optional[str] = None,
    fielddata_fields: Optional[str] = None,
    fields: Optional[str] = None,
    groups: Optional[str] = None,
    level: str = "indices",
    include_segment_file_sizes: bool = False,
    include_unloaded_segments: bool = False,
    expand_wildcards: str = "open",
    forbid_closed_indices: bool = True,
    human: bool = True
) -> Dict[str, Any]:
    """
    Get statistics for one or more indices.

    This tool provides detailed statistics about index performance, storage,
    and operational metrics for Wazuh indices.

    Args:
        index: Index name or pattern (default: _all)
        metric: Specific metrics to return (docs, store, indexing, search, etc.)
        completion_fields: Fields to include for completion stats
        fielddata_fields: Fields to include for fielddata stats
        fields: Specific fields to include in stats
        groups: Groups to include in search stats
        level: Level of detail (indices, cluster, shards)
        include_segment_file_sizes: Include segment file sizes
        include_unloaded_segments: Include unloaded segment stats
        expand_wildcards: Wildcard expansion (open, closed, hidden, none, all)
        forbid_closed_indices: Whether to forbid closed indices
        human: Return human readable values

    Returns:
        Dictionary containing index statistics
    """
    try:
        params = {
            "level": level,
            "include_segment_file_sizes": str(include_segment_file_sizes).lower(),
            "include_unloaded_segments": str(include_unloaded_segments).lower(),
            "expand_wildcards": expand_wildcards,
            "forbid_closed_indices": str(forbid_closed_indices).lower(),
            "human": str(human).lower()
        }

        # Add optional parameters
        if completion_fields:
            params["completion_fields"] = completion_fields
        if fielddata_fields:
            params["fielddata_fields"] = fielddata_fields
        if fields:
            params["fields"] = fields
        if groups:
            params["groups"] = groups

        endpoint = f"/{index}/_stats"
        if metric:
            endpoint = f"/{index}/_stats/{metric}"

        response = get_indexer_client()._make_request("GET", endpoint, params=params)

        # Add metadata and useful calculations
        response["timestamp"] = datetime.utcnow().isoformat()
        response["requested_index"] = index
        response["requested_metric"] = metric

        # Calculate useful metrics if available
        if "_all" in response:
            all_stats = response["_all"]
            if "primaries" in all_stats and "total" in all_stats:
                primaries = all_stats["primaries"]
                total = all_stats["total"]

                response["calculated_metrics"] = {
                    "total_docs": total.get("docs", {}).get("count", 0),
                    "primary_docs": primaries.get("docs", {}).get("count", 0),
                    "total_size_bytes": total.get("store", {}).get("size_in_bytes", 0),
                    "primary_size_bytes": primaries.get("store", {}).get("size_in_bytes", 0)
                }

        logger.debug(f"Retrieved statistics for index: {index}")
        return response

    except Exception as e:
        logger.error(f"Error getting index stats for {index}: {str(e)}")
        return {"error": str(e), "index": index}

@mcp.tool()
def get_index_mapping(
    index: str,
    allow_no_indices: bool = False,
    expand_wildcards: str = "open",
    ignore_unavailable: bool = False,
    master_timeout: str = "30s",
    timeout: str = "30s"
) -> Dict[str, Any]:
    """
    Get field mapping information for indices.

    This tool retrieves field mappings and data types for Wazuh indices,
    essential for understanding data structure and field capabilities.

    Args:
        index: Index name or pattern
        allow_no_indices: Whether to ignore if indices don't exist
        expand_wildcards: Wildcard expansion (open, closed, hidden, none, all)
        ignore_unavailable: Whether to ignore unavailable indices
        master_timeout: Master node timeout
        timeout: Request timeout

    Returns:
        Dictionary containing index field mappings
    """
    try:
        params = {
            "allow_no_indices": str(allow_no_indices).lower(),
            "expand_wildcards": expand_wildcards,
            "ignore_unavailable": str(ignore_unavailable).lower(),
            "master_timeout": master_timeout,
            "timeout": timeout
        }

        endpoint = f"/{index}/_mapping"
        response = get_indexer_client()._make_request("GET", endpoint, params=params)

        # Add metadata and field analysis
        response["timestamp"] = datetime.utcnow().isoformat()
        response["requested_index"] = index

        # Analyze mappings for useful insights
        field_summary = {}
        if isinstance(response, dict):
            for idx_name, idx_data in response.items():
                if idx_name not in ["timestamp", "requested_index"]:
                    mappings = idx_data.get("mappings", {})
                    properties = mappings.get("properties", {})

                    # Count field types
                    field_types = {}
                    field_count = 0
                    for field_name, field_def in properties.items():
                        field_type = field_def.get("type", "object")
                        field_types[field_type] = field_types.get(field_type, 0) + 1
                        field_count += 1

                    field_summary[idx_name] = {
                        "total_fields": field_count,
                        "field_types": field_types,
                        "has_nested_objects": "object" in field_types,
                        "has_text_fields": "text" in field_types,
                        "has_keyword_fields": "keyword" in field_types
                    }

        response["field_analysis"] = field_summary

        logger.debug(f"Retrieved mappings for index: {index}")
        return response

    except Exception as e:
        logger.error(f"Error getting index mapping for {index}: {str(e)}")
        return {"error": str(e), "index": index}

@mcp.tool()
def get_index_settings(
    index: str,
    name: Optional[str] = None,
    allow_no_indices: bool = False,
    expand_wildcards: str = "open",
    flat_settings: bool = False,
    ignore_unavailable: bool = False,
    include_defaults: bool = False,
    master_timeout: str = "30s",
    timeout: str = "30s"
) -> Dict[str, Any]:
    """
    Get settings for one or more indices.

    This tool retrieves configuration settings for Wazuh indices including
    shard configuration, refresh intervals, and other operational settings.

    Args:
        index: Index name or pattern
        name: Specific setting name to retrieve
        allow_no_indices: Whether to ignore if indices don't exist
        expand_wildcards: Wildcard expansion
        flat_settings: Return settings in flat format
        ignore_unavailable: Whether to ignore unavailable indices
        include_defaults: Include default settings
        master_timeout: Master node timeout
        timeout: Request timeout

    Returns:
        Dictionary containing index settings
    """
    try:
        params = {
            "allow_no_indices": str(allow_no_indices).lower(),
            "expand_wildcards": expand_wildcards,
            "flat_settings": str(flat_settings).lower(),
            "ignore_unavailable": str(ignore_unavailable).lower(),
            "include_defaults": str(include_defaults).lower(),
            "master_timeout": master_timeout,
            "timeout": timeout
        }

        endpoint = f"/{index}/_settings"
        if name:
            endpoint = f"/{index}/_settings/{name}"

        response = get_indexer_client()._make_request("GET", endpoint, params=params)

        # Add metadata and settings analysis
        response["timestamp"] = datetime.utcnow().isoformat()
        response["requested_index"] = index
        response["requested_setting"] = name

        # Analyze settings for key configurations
        settings_summary = {}
        if isinstance(response, dict):
            for idx_name, idx_data in response.items():
                if idx_name not in ["timestamp", "requested_index", "requested_setting"]:
                    settings = idx_data.get("settings", {})
                    index_settings = settings.get("index", {})

                    settings_summary[idx_name] = {
                        "number_of_shards": index_settings.get("number_of_shards"),
                        "number_of_replicas": index_settings.get("number_of_replicas"),
                        "refresh_interval": index_settings.get("refresh_interval"),
                        "max_result_window": index_settings.get("max_result_window"),
                        "creation_date": index_settings.get("creation_date"),
                        "uuid": index_settings.get("uuid"),
                        "version": index_settings.get("version")
                    }

        response["settings_summary"] = settings_summary

        logger.debug(f"Retrieved settings for index: {index}")
        return response

    except Exception as e:
        logger.error(f"Error getting index settings for {index}: {str(e)}")
        return {"error": str(e), "index": index}

@mcp.tool()
def list_indices(
    index: str = "*",
    allow_no_indices: bool = False,
    expand_wildcards: str = "open",
    flat_settings: bool = False,
    ignore_unavailable: bool = False,
    include_defaults: bool = False,
    human: bool = True
) -> Dict[str, Any]:
    """
    List all indices with basic information.

    This tool provides a comprehensive list of all Wazuh indices with
    essential metadata for inventory and monitoring purposes.

    Args:
        index: Index pattern to filter (default: * for all)
        allow_no_indices: Whether to ignore if indices don't exist
        expand_wildcards: Wildcard expansion
        flat_settings: Return settings in flat format
        ignore_unavailable: Whether to ignore unavailable indices
        include_defaults: Include default settings
        human: Return human readable values

    Returns:
        Dictionary containing list of indices with metadata
    """
    try:
        params = {
            "allow_no_indices": str(allow_no_indices).lower(),
            "expand_wildcards": expand_wildcards,
            "flat_settings": str(flat_settings).lower(),
            "ignore_unavailable": str(ignore_unavailable).lower(),
            "include_defaults": str(include_defaults).lower(),
            "human": str(human).lower()
        }

        endpoint = f"/{index}"
        response = get_indexer_client()._make_request("GET", endpoint, params=params)

        # Process response for better index listing
        indices_list = []
        indices_summary = {
            "total_indices": 0,
            "wazuh_alerts_indices": 0,
            "wazuh_states_indices": 0,
            "other_indices": 0,
            "total_shards": 0,
            "total_replicas": 0
        }

        if isinstance(response, dict):
            for idx_name, idx_data in response.items():
                if idx_name not in ["timestamp", "indices_summary", "indices_list"]:
                    # Extract key information
                    settings = idx_data.get("settings", {}).get("index", {})

                    index_info = {
                        "name": idx_name,
                        "uuid": settings.get("uuid"),
                        "creation_date": settings.get("creation_date"),
                        "number_of_shards": settings.get("number_of_shards", "1"),
                        "number_of_replicas": settings.get("number_of_replicas", "0"),
                        "status": "open" if "closed" not in settings else "closed",
                        "type": self._categorize_index(idx_name)
                    }

                    indices_list.append(index_info)
                    indices_summary["total_indices"] += 1

                    # Categorize indices
                    if "wazuh-alerts" in idx_name:
                        indices_summary["wazuh_alerts_indices"] += 1
                    elif "wazuh-states" in idx_name:
                        indices_summary["wazuh_states_indices"] += 1
                    else:
                        indices_summary["other_indices"] += 1

                    # Count shards and replicas
                    try:
                        indices_summary["total_shards"] += int(settings.get("number_of_shards", 1))
                        indices_summary["total_replicas"] += int(settings.get("number_of_replicas", 0))
                    except:
                        pass

        result = {
            "timestamp": datetime.utcnow().isoformat(),
            "requested_pattern": index,
            "indices_summary": indices_summary,
            "indices_list": sorted(indices_list, key=lambda x: x["name"])
        }

        logger.info(f"Listed {indices_summary['total_indices']} indices")
        return result

    except Exception as e:
        logger.error(f"Error listing indices: {str(e)}")
        return {"error": str(e), "pattern": index}

@mcp.tool()
def get_index_templates(
    name: Optional[str] = None,
    flat_settings: bool = False,
    master_timeout: str = "30s",
    timeout: str = "30s"
) -> Dict[str, Any]:
    """
    Get index templates.

    This tool retrieves index templates used for automatic index creation
    and configuration in Wazuh deployments.

    Args:
        name: Template name to retrieve (optional, gets all if not specified)
        flat_settings: Return settings in flat format
        master_timeout: Master node timeout
        timeout: Request timeout

    Returns:
        Dictionary containing index templates
    """
    try:
        params = {
            "flat_settings": str(flat_settings).lower(),
            "master_timeout": master_timeout,
            "timeout": timeout
        }

        endpoint = "/_template"
        if name:
            endpoint = f"/_template/{name}"

        response = get_indexer_client()._make_request("GET", endpoint, params=params)

        # Add metadata and template analysis
        response["timestamp"] = datetime.utcnow().isoformat()
        response["requested_template"] = name

        # Analyze templates
        template_summary = {
            "total_templates": 0,
            "wazuh_templates": 0,
            "other_templates": 0
        }

        if isinstance(response, dict):
            for template_name, template_data in response.items():
                if template_name not in ["timestamp", "requested_template", "template_summary"]:
                    template_summary["total_templates"] += 1

                    if "wazuh" in template_name.lower():
                        template_summary["wazuh_templates"] += 1
                    else:
                        template_summary["other_templates"] += 1

        response["template_summary"] = template_summary

        logger.debug(f"Retrieved {template_summary['total_templates']} index templates")
        return response

    except Exception as e:
        logger.error(f"Error getting index templates: {str(e)}")
        return {"error": str(e), "template": name}

@mcp.tool()
def get_index_aliases(
    index: str = "*",
    allow_no_indices: bool = False,
    expand_wildcards: str = "open",
    ignore_unavailable: bool = False,
    timeout: str = "30s"
) -> Dict[str, Any]:
    """
    Get index aliases.

    This tool retrieves aliases configured for Wazuh indices, which are used
    for simplified access and rollover management.

    Args:
        index: Index name or pattern
        allow_no_indices: Whether to ignore if indices don't exist
        expand_wildcards: Wildcard expansion
        ignore_unavailable: Whether to ignore unavailable indices
        timeout: Request timeout

    Returns:
        Dictionary containing index aliases
    """
    try:
        params = {
            "allow_no_indices": str(allow_no_indices).lower(),
            "expand_wildcards": expand_wildcards,
            "ignore_unavailable": str(ignore_unavailable).lower(),
            "timeout": timeout
        }

        endpoint = f"/{index}/_alias"
        response = get_indexer_client()._make_request("GET", endpoint, params=params)

        # Add metadata and alias analysis
        response["timestamp"] = datetime.utcnow().isoformat()
        response["requested_index"] = index

        # Analyze aliases
        alias_summary = {
            "total_indices_with_aliases": 0,
            "total_aliases": 0,
            "alias_list": []
        }

        if isinstance(response, dict):
            for idx_name, idx_data in response.items():
                if idx_name not in ["timestamp", "requested_index", "alias_summary"]:
                    aliases = idx_data.get("aliases", {})
                    if aliases:
                        alias_summary["total_indices_with_aliases"] += 1
                        for alias_name in aliases.keys():
                            alias_summary["total_aliases"] += 1
                            alias_summary["alias_list"].append({
                                "alias": alias_name,
                                "index": idx_name
                            })

        response["alias_summary"] = alias_summary

        logger.debug(f"Retrieved aliases for pattern: {index}")
        return response

    except Exception as e:
        logger.error(f"Error getting index aliases for {index}: {str(e)}")
        return {"error": str(e), "index": index}

def _categorize_index(index_name: str) -> str:
    """Categorize index by name pattern."""
    if "wazuh-alerts" in index_name:
        return "alerts"
    elif "wazuh-states-vulnerabilities" in index_name:
        return "vulnerabilities"
    elif "wazuh-states" in index_name:
        return "states"
    elif "wazuh" in index_name:
        return "wazuh"
    else:
        return "other"