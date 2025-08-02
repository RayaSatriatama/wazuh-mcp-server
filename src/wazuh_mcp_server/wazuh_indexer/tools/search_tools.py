"""
Wazuh Indexer Search Tools - MCP Tools for Search and Query Operations

This module provides MCP tools for searching alerts, vulnerabilities, and events
in the Wazuh Indexer (Elasticsearch/OpenSearch) with enhanced DSQL support.

Following best practices:
- Clean code and PEP 8 compliance
- Comprehensive parameter validation
- GET-only operations for safety
- Detailed error handling
- Type hints and documentation
- Enhanced DSQL support for flexible queries
"""

import json
import logging
from typing import Any, Dict, List, Optional, Union
from datetime import datetime, timedelta

from fastmcp import FastMCP

from .tool_clients import get_indexer_client

# Create MCP server instance
mcp = FastMCP("wazuh_indexer_search_mcp")

# Initialize logger
logger = logging.getLogger(__name__)


@mcp.tool()
def search_alerts(
        dsql_query: Optional[str] = None,
        index_pattern: str = "wazuh-alerts-*",
        size: int = 100,
        from_: int = 0,
        sort_field: str = "timestamp",
        sort_order: str = "desc",
        fields: Optional[str] = None,
        time_range: Optional[Dict[str, str]] = None,
        use_manager_api: bool = True,
        format_: str = "json"
) -> Dict[str, Any]:
    """
    Search for Wazuh security alerts with flexible field support.

    Supports any field in the alert structure through DSQL queries.
    Examples of flexible field queries:
    - "data.win.eventdata.subjectUserName=administrator"
    - "data.srcip=192.168.1.100 AND data.protocol=TCP"
    - "rule.mitre.id=T1055 OR rule.mitre.id=T1003"
    - "agent.labels.department=IT"
    - "location=/var/log/auth.log"
    """
    try:
        size = max(1, min(size, 10000))
        from_ = max(0, from_)

        if use_manager_api:
            return _search_alerts_manager_api(
                dsql_query, size, from_, sort_field, sort_order,
                fields, time_range
            )
        else:
            return _search_alerts_indexer_api(
                dsql_query, index_pattern, size, from_, sort_field,
                sort_order, fields, time_range
            )

    except Exception as e:
        logger.error(f"Error in search_alerts: {str(e)}")
        return {
            "error": str(e),
            "total_hits": 0,
            "alerts": [],
            "dsql_query_used": dsql_query or "error",
            "search_metadata": {
                "index_pattern": index_pattern,
                "timestamp": datetime.utcnow().isoformat(),
                "error_occurred": True,
                "api_used": "manager" if use_manager_api else "indexer"
            }
        }

@mcp.tool()
def build_dsql_query(
    rule_level_min: Optional[int] = None,
    rule_level_max: Optional[int] = None,
    rule_groups: Optional[List[str]] = None,
    agent_names: Optional[List[str]] = None,
    agent_ids: Optional[List[str]] = None,
    source_ips: Optional[List[str]] = None,
    destination_ips: Optional[List[str]] = None,
    mitre_techniques: Optional[List[str]] = None,
    rule_description_contains: Optional[str] = None,
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
    combine_with: str = "AND"
) -> Dict[str, Any]:
    """
    Build a DSQL query from common parameters for use with search_alerts.

    This helper tool constructs DSQL queries programmatically, making it easier
    to build complex queries without manual string construction.

    Args:
        rule_level_min: Minimum rule level (inclusive)
        rule_level_max: Maximum rule level (inclusive)
        rule_groups: List of rule groups to match
        agent_names: List of agent names to match
        agent_ids: List of agent IDs to match
        source_ips: List of source IP addresses to match
        destination_ips: List of destination IP addresses to match
        mitre_techniques: List of MITRE technique IDs to match
        rule_description_contains: Text to search in rule description
        time_from: Start time (ISO format or relative like "1h", "1d")
        time_to: End time (ISO format or relative like "now")
        combine_with: How to combine conditions ("AND" or "OR")

    Returns:
        Dictionary with generated DSQL query and metadata
    """
    try:
        conditions = []

        # Rule level range
        if rule_level_min is not None and rule_level_max is not None:
            conditions.append(f"rule.level>={rule_level_min} AND rule.level<={rule_level_max}")
        elif rule_level_min is not None:
            conditions.append(f"rule.level>={rule_level_min}")
        elif rule_level_max is not None:
            conditions.append(f"rule.level<={rule_level_max}")

        # Rule groups
        if rule_groups:
            if len(rule_groups) == 1:
                conditions.append(f"rule.groups={rule_groups[0]}")
            else:
                group_conditions = [f"rule.groups={group}" for group in rule_groups]
                conditions.append(f"({' OR '.join(group_conditions)})")

        # Agent names
        if agent_names:
            if len(agent_names) == 1:
                conditions.append(f"agent.name={agent_names[0]}")
            else:
                conditions.append(f"agent.name={','.join(agent_names)}")

        # Agent IDs
        if agent_ids:
            if len(agent_ids) == 1:
                conditions.append(f"agent.id={agent_ids[0]}")
            else:
                conditions.append(f"agent.id={','.join(agent_ids)}")

        # Source IPs
        if source_ips:
            if len(source_ips) == 1:
                conditions.append(f"data.srcip={source_ips[0]}")
            else:
                conditions.append(f"data.srcip={','.join(source_ips)}")

        # Destination IPs
        if destination_ips:
            if len(destination_ips) == 1:
                conditions.append(f"data.dstip={destination_ips[0]}")
            else:
                conditions.append(f"data.dstip={','.join(destination_ips)}")

        # MITRE techniques
        if mitre_techniques:
            if len(mitre_techniques) == 1:
                conditions.append(f"rule.mitre.technique={mitre_techniques[0]}")
            else:
                conditions.append(f"rule.mitre.technique={','.join(mitre_techniques)}")

        # Rule description contains
        if rule_description_contains:
            conditions.append(f"rule.description~{rule_description_contains}")

        # Time range
        if time_from and time_to:
            conditions.append(f"timestamp>={time_from} AND timestamp<={time_to}")
        elif time_from:
            conditions.append(f"timestamp>={time_from}")
        elif time_to:
            conditions.append(f"timestamp<={time_to}")

        # Combine conditions
        if conditions:
            dsql_query = f" {combine_with} ".join(conditions)
        else:
            dsql_query = "*"  # Match all if no conditions

        return {
            "dsql_query": dsql_query,
            "conditions_count": len(conditions),
            "combine_operator": combine_with,
            "usage_example": f"search_alerts(dsql_query='{dsql_query}')",
            "metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "parameters_used": {
                    "rule_level_min": rule_level_min,
                    "rule_level_max": rule_level_max,
                    "rule_groups": rule_groups,
                    "agent_names": agent_names,
                    "agent_ids": agent_ids,
                    "source_ips": source_ips,
                    "destination_ips": destination_ips,
                    "mitre_techniques": mitre_techniques,
                    "rule_description_contains": rule_description_contains,
                    "time_from": time_from,
                    "time_to": time_to
                }
            }
        }

    except Exception as e:
        logger.error(f"Error building DSQL query: {str(e)}")
        return {
            "error": str(e),
            "dsql_query": "*",
            "conditions_count": 0
        }

# Keep all other existing functions unchanged
@mcp.tool()
def search_vulnerabilities(
    index_pattern: str = "wazuh-states-vulnerabilities-*",
    cve_id: Optional[str] = None,
    severity: Optional[str] = None,
    agent_id: Optional[str] = None,
    package_name: Optional[str] = None,
    cvss_min_score: Optional[float] = None,
    cvss_max_score: Optional[float] = None,
    size: int = 100,
    from_: int = 0,
    sort_field: str = "vulnerability.score.base",
    sort_order: str = "desc"
) -> Dict[str, Any]:
    """
    Search for vulnerability data in the Wazuh indexer.

    This tool queries the vulnerability state indices to find security
    vulnerabilities affecting monitored systems.

    Args:
        index_pattern: Index pattern to search (default: wazuh-states-vulnerabilities-*)
        cve_id: Filter by specific CVE identifier (e.g., CVE-2023-1234)
        severity: Filter by vulnerability severity (Low, Medium, High, Critical)
        agent_id: Filter by specific agent ID
        package_name: Filter by affected package name
        cvss_min_score: Minimum CVSS score (0.0-10.0)
        cvss_max_score: Maximum CVSS score (0.0-10.0)
        size: Maximum number of results to return (1-10000)
        from_: Starting offset for pagination
        sort_field: Field to sort by
        sort_order: Sort order: asc or desc

    Returns:
        Dictionary containing vulnerability search results with metadata
    """
    try:
        # Input validation
        size = max(1, min(size, 10000))
        from_ = max(0, from_)

        search_body = {
            "size": size,
            "from": from_
        }

        filter_clauses = []

        # Add specific filters
        if cve_id:
            filter_clauses.append({"term": {"vulnerability.id": cve_id}})

        if severity:
            filter_clauses.append({"term": {"vulnerability.severity": severity}})

        if agent_id:
            filter_clauses.append({"term": {"agent.id": agent_id}})

        if package_name:
            filter_clauses.append({"term": {"vulnerability.package.name": package_name}})

        # Add CVSS score range filter
        if cvss_min_score is not None or cvss_max_score is not None:
            range_filter = {}
            if cvss_min_score is not None:
                range_filter["gte"] = cvss_min_score
            if cvss_max_score is not None:
                range_filter["lte"] = cvss_max_score
            filter_clauses.append({
                "range": {
                    "vulnerability.score.base": range_filter
                }
            })

        # Build query
        if filter_clauses:
            search_body["query"] = {"bool": {"filter": filter_clauses}}
        else:
            search_body["query"] = {"match_all": {}}

        # Add sorting
        search_body["sort"] = [{sort_field: {"order": sort_order}}]

        logger.info(f"Searching vulnerabilities with query: {json.dumps(search_body, indent=2)}")

        # Execute search
        endpoint = f"/{index_pattern}/_search"
        response = get_indexer_client()._make_request("GET", endpoint, json=search_body)

        # Process results
        hits = response.get("hits", {})
        total = hits.get("total", {})

        result = {
            "total_vulnerabilities": total.get("value", 0) if isinstance(total, dict) else total,
            "took": response.get("took"),
            "vulnerabilities": []
        }

        for hit in hits.get("hits", []):
            vuln = {
                "id": hit.get("_id"),
                "index": hit.get("_index"),
                "score": hit.get("_score"),
                "vulnerability": hit.get("_source", {})
            }
            result["vulnerabilities"].append(vuln)

        logger.info(f"Found {result['total_vulnerabilities']} vulnerabilities")
        return result

    except Exception as e:
        logger.error(f"Error searching vulnerabilities: {str(e)}")
        return {"error": str(e), "vulnerabilities": [], "total_vulnerabilities": 0}

@mcp.tool()
def search_events(
    index_pattern: str = "wazuh-*",
    event_type: Optional[str] = None,
    time_range: Optional[Dict[str, str]] = None,
    query: Optional[Union[str, Dict]] = None,
    size: int = 100,
    from_: int = 0,
    aggs: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Search for general events across Wazuh indices.

    This tool provides a general search capability across all Wazuh indices
    with support for aggregations for analytical queries.

    Args:
        index_pattern: Index pattern to search (default: wazuh-*)
        event_type: Filter by specific event type
        time_range: Time range filter
        query: Elasticsearch query string or a full query body
        size: Maximum number of results to return
        from_: Starting offset for pagination
        aggs: Elasticsearch aggregations

    Returns:
        Dictionary containing event search results and aggregations
    """
    try:
        # Input validation
        size = max(0, min(size, 10000))
        from_ = max(0, from_)

        search_body = {
            "size": size,
            "from": from_
        }

        # Build query components
        must_clauses = []
        filter_clauses = []

        # Add query string if provided
        if isinstance(query, str) and query:
            must_clauses.append({
                "query_string": {
                    "query": query,
                    "default_field": "*",
                    "analyze_wildcard": True
                }
            })
        elif isinstance(query, dict):
            # If query is a dict, assume it's a full query body
            search_body.update(query)

        # Add specific field filters
        if event_type:
            filter_clauses.append({"term": {"event.kind": event_type}})

        if time_range:
            filter_clauses.append({
                "range": {
                    "timestamp": time_range
                }
            })

        # Build bool query
        bool_query = {}
        if must_clauses:
            bool_query["must"] = must_clauses
        if filter_clauses:
            bool_query["filter"] = filter_clauses

        if bool_query:
            search_body["query"] = {"bool": bool_query}
        else:
            search_body["query"] = {"match_all": {}}

        # Add aggregations
        if aggs:
            search_body["aggs"] = aggs

        # Default sort
        search_body["sort"] = [{"timestamp": {"order": "desc"}}]

        logger.info(f"Searching events with query: {json.dumps(search_body, indent=2)}")

        # Execute search
        endpoint = f"/{index_pattern}/_search"
        response = get_indexer_client()._make_request("GET", endpoint, json=search_body)

        # Process results
        hits = response.get("hits", {})
        total = hits.get("total", {})

        result = {
            "total_events": total.get("value", 0) if isinstance(total, dict) else total,
            "took": response.get("took"),
            "events": [],
            "aggregations": response.get("aggregations", {})
        }

        for hit in hits.get("hits", []):
            event = {
                "id": hit.get("_id"),
                "index": hit.get("_index"),
                "score": hit.get("_score"),
                "event": hit.get("_source", {})
            }
            result["events"].append(event)

        logger.info(f"Found {result['total_events']} events")
        return result

    except Exception as e:
        logger.error(f"Error searching events: {str(e)}")
        return {"error": str(e), "events": [], "total_events": 0}

@mcp.tool()
def get_document_by_id(
    index: str,
    doc_id: str,
    fields: Optional[str] = None
) -> Dict[str, Any]:
    """
    Retrieve a specific document by its ID.

    This tool fetches a single document from the specified index using
    its unique document identifier.

    Args:
        index: Index name containing the document
        doc_id: Document ID to retrieve
        fields: Comma-separated list of specific fields to include in response

    Returns:
        Dictionary containing the document data and metadata
    """
    try:
        params = {}
        if fields:
            field_list = [f.strip() for f in fields.split(",") if f.strip()]
            if field_list:
                params["_source"] = ",".join(field_list)

        endpoint = f"/{index}/_doc/{doc_id}"
        response = get_indexer_client()._make_request("GET", endpoint, params=params)

        return {
            "found": response.get("found", False),
            "index": response.get("_index"),
            "id": response.get("_id"),
            "version": response.get("_version"),
            "source": response.get("_source", {})
        }

    except Exception as e:
        logger.error(f"Error retrieving document {doc_id}: {str(e)}")
        return {"error": str(e), "found": False, "source": {}}

@mcp.tool()
def count_documents(
    index_pattern: str,
    query: Optional[str] = None,
    filters: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Count documents matching specified criteria.

    This tool returns the count of documents matching the given query
    and filters without retrieving the actual documents.

    Args:
        index_pattern: Index pattern to count documents in
        query: Query string for filtering documents
        filters: Additional field-based filters

    Returns:
        Dictionary containing document count and shard information
    """
    try:
        count_body = {}

        # Build query components
        filter_clauses = []

        if query:
            count_body["query"] = {
                "query_string": {
                    "query": query,
                    "default_field": "*",
                    "analyze_wildcard": True
                }
            }

        if filters:
            for field, value in filters.items():
                if isinstance(value, list):
                    filter_clauses.append({"terms": {field: value}})
                else:
                    filter_clauses.append({"term": {field: value}})

        if filter_clauses:
            if "query" in count_body:
                count_body["query"] = {
                    "bool": {
                        "must": [count_body["query"]],
                        "filter": filter_clauses
                    }
                }
            else:
                count_body["query"] = {"bool": {"filter": filter_clauses}}

        endpoint = f"/{index_pattern}/_count"
        response = get_indexer_client()._make_request("GET", endpoint, json=count_body)

        return {
            "count": response.get("count", 0),
            "shards": response.get("_shards", {})
        }

    except Exception as e:
        logger.error(f"Error counting documents: {str(e)}")
        return {"error": str(e), "count": 0}

@mcp.tool()
def search_with_aggregations(
    index_pattern: str,
    aggs: Dict[str, Any],
    query: Optional[str] = None,
    filters: Optional[Dict[str, Any]] = None,
    size: int = 0
) -> Dict[str, Any]:
    """
    Perform search with aggregations for analytics.

    This tool executes analytical queries using Elasticsearch aggregations
    to generate statistics, histograms, and other analytical data.

    Args:
        index_pattern: Index pattern to search
        aggs: Aggregation configuration dictionary
        query: Optional query string for filtering
        filters: Optional field-based filters
        size: Number of documents to return (0 for aggregations only)

    Returns:
        Dictionary containing aggregation results and metadata
    """
    try:
        search_body = {
            "size": max(0, min(size, 1000)),  # Limit size for aggregation queries
            "aggs": aggs
        }

        # Build query components
        must_clauses = []
        filter_clauses = []

        if query:
            must_clauses.append({
                "query_string": {
                    "query": query,
                    "default_field": "*",
                    "analyze_wildcard": True
                }
            })

        if filters:
            for field, value in filters.items():
                if isinstance(value, list):
                    filter_clauses.append({"terms": {field: value}})
                else:
                    filter_clauses.append({"term": {field: value}})

        # Build bool query
        bool_query = {}
        if must_clauses:
            bool_query["must"] = must_clauses
        if filter_clauses:
            bool_query["filter"] = filter_clauses

        if bool_query:
            search_body["query"] = {"bool": bool_query}

        logger.info(f"Executing aggregation search: {json.dumps(search_body, indent=2)}")

        endpoint = f"/{index_pattern}/_search"
        response = get_indexer_client()._make_request("GET", endpoint, json=search_body)

        hits = response.get("hits", {})
        total = hits.get("total", {})

        return {
            "took": response.get("took"),
            "total_hits": total.get("value", 0) if isinstance(total, dict) else total,
            "aggregations": response.get("aggregations", {})
        }

    except Exception as e:
        logger.error(f"Error executing aggregation search: {str(e)}")
        return {"error": str(e), "aggregations": {}}

@mcp.tool()
def scroll_search(
    index_pattern: str,
    query: Optional[str] = None,
    scroll_size: int = 1000,
    scroll_time: str = "1m",
    fields: Optional[str] = None
) -> Dict[str, Any]:
    """
    Initiate a scroll search for large result sets.

    This tool starts a scroll search context for efficiently retrieving
    large numbers of documents in batches.

    Args:
        index_pattern: Index pattern to search
        query: Optional query string for filtering
        scroll_size: Number of documents per scroll batch (max 10000)
        scroll_time: How long to keep scroll context alive (e.g., 1m, 5m)
        fields: Comma-separated list of specific fields to include

    Returns:
        Dictionary containing initial scroll results and scroll ID
    """
    try:
        scroll_size = max(1, min(scroll_size, 10000))

        search_body = {
            "size": scroll_size
        }

        if query:
            search_body["query"] = {
                "query_string": {
                    "query": query,
                    "default_field": "*",
                    "analyze_wildcard": True
                }
            }
        else:
            search_body["query"] = {"match_all": {}}

        if fields:
            field_list = [f.strip() for f in fields.split(",") if f.strip()]
            if field_list:
                search_body["_source"] = field_list

        params = {"scroll": scroll_time}

        logger.info(f"Starting scroll search: {json.dumps(search_body, indent=2)}")

        endpoint = f"/{index_pattern}/_search"
        response = get_indexer_client()._make_request("GET", endpoint, params=params, json=search_body)

        hits = response.get("hits", {})
        total = hits.get("total", {})

        result = {
            "scroll_id": response.get("_scroll_id"),
            "total_hits": total.get("value", 0) if isinstance(total, dict) else total,
            "documents": [],
            "took": response.get("took"),
            "scroll_time": scroll_time,
            "scroll_size": scroll_size
        }

        for hit in hits.get("hits", []):
            doc = {
                "id": hit.get("_id"),
                "index": hit.get("_index"),
                "score": hit.get("_score"),
                "source": hit.get("_source", {})
            }
            result["documents"].append(doc)

        logger.info(f"Scroll search initiated: {len(result['documents'])} documents in first batch")
        return result

    except Exception as e:
        logger.error(f"Error initiating scroll search: {str(e)}")
        return {"error": str(e), "documents": [], "scroll_id": None}

@mcp.tool()
def multi_search_simple(
    index1: str,
    query1: str = "*",
    size1: int = 10,
    index2: Optional[str] = None,
    query2: Optional[str] = None,
    size2: int = 10
) -> Dict[str, Any]:
    """
    Execute up to 2 searches in a single request for performance.

    This tool allows executing multiple search queries simultaneously
    for improved performance when running related searches.

    Args:
        index1: First index to search
        query1: First query string (default: *)
        size1: Number of results for first search
        index2: Second index to search (optional)
        query2: Second query string (optional)
        size2: Number of results for second search

    Returns:
        Dictionary containing results for each search query
    """
    try:
        # Build search list
        searches = [{
            "index": index1,
            "query": query1 or "*",
            "size": max(1, min(size1, 1000))
        }]

        if index2 and query2:
            searches.append({
                "index": index2,
                "query": query2,
                "size": max(1, min(size2, 1000))
            })

        # Build multi-search body
        msearch_body = []

        for search in searches:
            # Header
            header = {"index": search["index"]}
            msearch_body.append(json.dumps(header))

            # Body
            body = {
                "query": {
                    "query_string": {
                        "query": search["query"],
                        "default_field": "*"
                    }
                },
                "size": search["size"]
            }
            msearch_body.append(json.dumps(body))

        # Join with newlines (ndjson format)
        msearch_data = "\n".join(msearch_body) + "\n"

        endpoint = "/_msearch"
        response = get_indexer_client()._make_request(
            "GET", endpoint, data=msearch_data,
            headers={"Content-Type": "application/x-ndjson"}
        )

        # Process responses
        results = []
        for i, resp in enumerate(response.get("responses", [])):
            if "error" in resp:
                results.append({
                    "search_index": i,
                    "error": resp["error"],
                    "hits": [],
                    "total_hits": 0
                })
            else:
                hits = resp.get("hits", {})
                total = hits.get("total", {})
                results.append({
                    "search_index": i,
                    "total_hits": total.get("value", 0) if isinstance(total, dict) else total,
                    "took": resp.get("took"),
                    "hits": [hit.get("_source", {}) for hit in hits.get("hits", [])]
                })

        return {
            "total_searches": len(searches),
            "successful_searches": sum(1 for r in results if "error" not in r),
            "results": results
        }

    except Exception as e:
        logger.error(f"Error executing multi-search: {str(e)}")
        return {"error": str(e), "results": []}
