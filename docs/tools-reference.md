# Tools Reference

Complete reference for all available tools in the Wazuh MCP Server.

## 📊 Wazuh Indexer Tools

### Search and Analytics Tools

#### `search_alerts`
Search for Wazuh security alerts with flexible field support.

**Description:** Advanced alert search with DSQL query support for complex filtering.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `dsql_query` | string | No | null | DSQL query string for filtering |
| `fields` | string | No | null | Comma-separated list of fields to include |
| `from_` | integer | No | 0 | Starting offset for pagination |
| `size` | integer | No | 100 | Number of results to return (max 10000) |
| `sort_field` | string | No | "timestamp" | Field to sort by |
| `sort_order` | string | No | "desc" | Sort order: "asc" or "desc" |
| `time_range` | object | No | null | Time range filter with "gte" and "lte" |
| `index_pattern` | string | No | "wazuh-alerts-*" | Index pattern to search |

**Example Usage:**
```bash
curl -X POST http://localhost:8001/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "search_alerts",
    "arguments": {
      "dsql_query": "rule.level>=10 AND agent.name=web-server",
      "size": 50,
      "time_range": {"gte": "now-1h", "lte": "now"}
    }
  }'
```

**Sample Output:**
```json
{
  "content": [{
    "type": "text",
    "text": "Found 25 alerts matching criteria:\n\n1. Rule 5715 - SSH authentication success\n   Agent: web-server-01\n   Time: 2025-08-02T10:30:00Z\n   Level: 3\n\n2. Rule 31100 - Login session opened\n   Agent: web-server-01  \n   Time: 2025-08-02T10:29:45Z\n   Level: 5"
  }],
  "isError": false
}
```

#### `search_vulnerabilities`
Search for vulnerability data in the Wazuh indexer.

**Description:** Query vulnerability state indices to find security vulnerabilities affecting monitored systems.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `cve_id` | string | No | null | Filter by specific CVE identifier |
| `severity` | string | No | null | Filter by severity: Low, Medium, High, Critical |
| `agent_id` | string | No | null | Filter by specific agent ID |
| `package_name` | string | No | null | Filter by affected package name |
| `cvss_min_score` | number | No | null | Minimum CVSS score (0.0-10.0) |
| `cvss_max_score` | number | No | null | Maximum CVSS score (0.0-10.0) |
| `size` | integer | No | 100 | Maximum number of results (1-10000) |
| `from_` | integer | No | 0 | Starting offset for pagination |
| `sort_field` | string | No | "vulnerability.score.base" | Field to sort by |
| `sort_order` | string | No | "desc" | Sort order: "asc" or "desc" |

**Example Usage:**
```bash
curl -X POST http://localhost:8001/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "search_vulnerabilities",
    "arguments": {
      "severity": "Critical",
      "cvss_min_score": 9.0,
      "size": 20
    }
  }'
```

#### `search_events`
Search for general events across Wazuh indices.

**Description:** General search capability across all Wazuh indices with aggregation support.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `index_pattern` | string | No | "wazuh-*" | Index pattern to search |
| `event_type` | string | No | null | Filter by specific event type |
| `query` | string/object | No | null | Elasticsearch query string or full query body |
| `time_range` | object | No | null | Time range filter |
| `size` | integer | No | 100 | Maximum number of results |
| `from_` | integer | No | 0 | Starting offset for pagination |
| `aggs` | object | No | null | Elasticsearch aggregations |

### Cluster Management Tools

#### `get_cluster_health`
Get cluster health information.

**Description:** Retrieve comprehensive health information about the Wazuh Indexer cluster.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `level` | string | No | "cluster" | Detail level: cluster, indices, shards |
| `wait_for_status` | string | No | null | Wait for specific status: green, yellow, red |
| `wait_for_nodes` | string | No | null | Wait for number of nodes (e.g., ">=2") |
| `timeout` | string | No | "30s" | Request timeout |

**Example Usage:**
```bash
curl -X POST http://localhost:8001/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "get_cluster_health",
    "arguments": {
      "level": "indices",
      "wait_for_status": "green"
    }
  }'
```

#### `get_cluster_stats`
Get cluster statistics and performance metrics.

**Description:** Retrieve comprehensive statistics about cluster performance, storage, and resource usage.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `node_id` | string | No | null | Comma-separated list of node IDs |
| `human` | boolean | No | true | Return human-readable values |
| `flat_settings` | boolean | No | false | Return settings in flat format |

#### `list_indices`
List all indices with basic information.

**Description:** Comprehensive list of all Wazuh indices with essential metadata.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `index` | string | No | "*" | Index pattern to filter |
| `human` | boolean | No | true | Return human-readable values |

### Index Management Tools

#### `get_index_info`
Get detailed information about one or more indices.

**Description:** Retrieve comprehensive information about Wazuh indices including settings, mappings, and metadata.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `index` | string | Yes | - | Index name or pattern |
| `human` | boolean | No | true | Return human-readable values |
| `include_defaults` | boolean | No | false | Include default settings |

#### `get_index_mapping`
Get field mapping information for indices.

**Description:** Retrieve field mappings and data types for understanding data structure.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `index` | string | Yes | - | Index name or pattern |
| `timeout` | string | No | "30s" | Request timeout |

#### `get_index_stats`
Get statistics for one or more indices.

**Description:** Detailed statistics about index performance, storage, and operational metrics.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `index` | string | No | "_all" | Index name or pattern |
| `metric` | string | No | null | Specific metrics (docs, store, indexing, search) |
| `human` | boolean | No | true | Return human-readable values |

## 👥 Wazuh Manager Tools

### Agent Management Tools

#### `get_agents`
Get list of Wazuh agents.

**Description:** Retrieve comprehensive list of agents with filtering and pagination support.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `limit` | integer | No | 100 | Maximum number of agents to return |
| `offset` | integer | No | 0 | Starting offset for pagination |
| `select` | string | No | null | Comma-separated list of fields to include |
| `sort` | string | No | null | Sort field |
| `search` | string | No | null | Search term |
| `status` | string | No | null | Filter by status: active, disconnected, never_connected |
| `group` | string | No | null | Filter by group name |
| `q` | string | No | null | Advanced query string |

**Example Usage:**
```bash
curl -X POST http://localhost:8002/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "get_agents",
    "arguments": {
      "status": "active",
      "limit": 20,
      "select": "id,name,ip,status,version"
    }
  }'
```

#### `get_agent_info`
Get detailed information about a specific agent.

**Description:** Retrieve comprehensive information about a single agent including configuration and statistics.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `agent_id` | string | Yes | - | Agent ID to query |
| `select` | string | No | null | Comma-separated list of fields |

#### `restart_agent`
Restart one or more Wazuh agents.

**Description:** Send restart command to specified agents.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `agent_list` | array | Yes | - | List of agent IDs to restart |

#### `add_agent`
Add a new agent to Wazuh.

**Description:** Register a new agent with the Wazuh manager.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `name` | string | Yes | - | Agent name |
| `ip` | string | No | "any" | Agent IP address |
| `groups` | array | No | ["default"] | List of groups to assign |
| `key` | string | No | null | Pre-shared key |

### Rules and Decoders Tools

#### `get_rules`
Get Wazuh detection rules.

**Description:** Retrieve detection rules with filtering and search capabilities.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `limit` | integer | No | 100 | Maximum number of rules |
| `offset` | integer | No | 0 | Starting offset |
| `search` | string | No | null | Search term |
| `level` | string | No | null | Filter by rule level |
| `group` | string | No | null | Filter by rule group |
| `pci_dss` | string | No | null | Filter by PCI DSS requirement |
| `gdpr` | string | No | null | Filter by GDPR requirement |

#### `get_rule_info`
Get detailed information about a specific rule.

**Description:** Retrieve comprehensive information about a single detection rule.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `rule_id` | string | Yes | - | Rule ID to query |

#### `get_decoders`
Get Wazuh log decoders.

**Description:** Retrieve log decoders used for parsing log messages.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `limit` | integer | No | 50 | Maximum number of decoders |
| `search` | string | No | null | Search term |
| `decoder_name` | string | No | null | Filter by decoder name |

### System Information Tools

#### `get_manager_info`
Get Wazuh manager information.

**Description:** Retrieve general information about the Wazuh manager.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `pretty` | boolean | No | true | Format output for readability |

#### `get_manager_stats`
Get manager statistics and performance metrics.

**Description:** Retrieve runtime statistics and performance metrics.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `pretty` | boolean | No | true | Format output for readability |
| `date` | string | No | null | Specific date for statistics |

#### `get_manager_logs`
Get manager log entries.

**Description:** Retrieve log entries from the Wazuh manager.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `limit` | integer | No | 100 | Maximum number of log entries |
| `offset` | integer | No | 0 | Starting offset |
| `level` | string | No | null | Filter by log level |
| `search` | string | No | null | Search term |

### Group Management Tools

#### `get_groups`
Get list of agent groups.

**Description:** Retrieve list of configured agent groups.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `limit` | integer | No | 50 | Maximum number of groups |
| `search` | string | No | null | Search term |

#### `create_group`
Create a new agent group.

**Description:** Create a new group for organizing agents.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `group_id` | string | Yes | - | Group name/ID |

#### `assign_group`
Assign agents to a group.

**Description:** Add agents to an existing group.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `group_id` | string | Yes | - | Target group ID |
| `agents_list` | array | Yes | - | List of agent IDs |

## 🔧 Utility Tools

### Connection and Health Tools

#### `health_check`
Perform health check for the MCP server.

**Description:** Comprehensive health check including connectivity to Wazuh services.

**Parameters:** None

#### `server_info`
Get Wazuh MCP server information.

**Description:** Retrieve information about the MCP server instance.

**Parameters:** None

### Query Building Tools

#### `build_dsql_query`
Build a DSQL query from common parameters for use with search_alerts.

**Description:** Helper tool to construct DSQL queries programmatically.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `rule_level_min` | integer | No | null | Minimum rule level (inclusive) |
| `rule_level_max` | integer | No | null | Maximum rule level (inclusive) |
| `rule_groups` | array | No | null | List of rule groups to match |
| `agent_names` | array | No | null | List of agent names to match |
| `agent_ids` | array | No | null | List of agent IDs to match |
| `source_ips` | array | No | null | List of source IP addresses |
| `destination_ips` | array | No | null | List of destination IP addresses |
| `mitre_techniques` | array | No | null | List of MITRE technique IDs |
| `rule_description_contains` | string | No | null | Text to search in rule description |
| `time_from` | string | No | null | Start time (ISO format or relative) |
| `time_to` | string | No | null | End time (ISO format or relative) |
| `combine_with` | string | No | "AND" | How to combine conditions: "AND" or "OR" |

**Example Usage:**
```bash
curl -X POST http://localhost:8001/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "build_dsql_query",
    "arguments": {
      "rule_level_min": 7,
      "agent_names": ["web-server", "db-server"],
      "time_from": "now-24h",
      "combine_with": "AND"
    }
  }'
```

## 🎯 Tool Usage Patterns

### Basic Information Gathering

```bash
# Get cluster overview
curl -X POST http://localhost:8001/tools/call \
  -d '{"name": "get_cluster_health", "arguments": {}}'

# List active agents
curl -X POST http://localhost:8002/tools/call \
  -d '{"name": "get_agents", "arguments": {"status": "active", "limit": 10}}'
```

### Security Alert Analysis

```bash
# High-severity alerts from last hour
curl -X POST http://localhost:8001/tools/call \
  -d '{
    "name": "search_alerts",
    "arguments": {
      "dsql_query": "rule.level>=10",
      "time_range": {"gte": "now-1h"},
      "size": 50
    }
  }'

# Authentication-related alerts
curl -X POST http://localhost:8001/tools/call \
  -d '{
    "name": "search_alerts",
    "arguments": {
      "dsql_query": "rule.groups:authentication",
      "size": 100
    }
  }'
```

### Vulnerability Management

```bash
# Critical vulnerabilities
curl -X POST http://localhost:8001/tools/call \
  -d '{
    "name": "search_vulnerabilities",
    "arguments": {
      "severity": "Critical",
      "size": 50
    }
  }'

# Vulnerabilities by agent
curl -X POST http://localhost:8001/tools/call \
  -d '{
    "name": "search_vulnerabilities",
    "arguments": {
      "agent_id": "001",
      "size": 100
    }
  }'
```

### Agent Management

```bash
# Add new agent
curl -X POST http://localhost:8002/tools/call \
  -d '{
    "name": "add_agent",
    "arguments": {
      "name": "new-server",
      "ip": "192.168.1.100",
      "groups": ["web-servers"]
    }
  }'

# Restart agents
curl -X POST http://localhost:8002/tools/call \
  -d '{
    "name": "restart_agent",
    "arguments": {
      "agent_list": ["001", "002"]
    }
  }'
```

## 📊 Tool Categories

### **Search Tools**
- `search_alerts` - Alert search and analysis
- `search_vulnerabilities` - Vulnerability detection
- `search_events` - General event search

### **Cluster Tools**
- `get_cluster_health` - Cluster status
- `get_cluster_stats` - Performance metrics
- `list_indices` - Index inventory

### **Agent Tools**
- `get_agents` - Agent inventory
- `get_agent_info` - Agent details
- `restart_agent` - Agent control
- `add_agent` - Agent registration

### **Rules Tools**
- `get_rules` - Rule management
- `get_rule_info` - Rule details
- `get_decoders` - Decoder management

### **System Tools**
- `get_manager_info` - Manager information
- `get_manager_stats` - Manager statistics
- `health_check` - System health

For API endpoint documentation, see the [API Reference](./api-reference.md).
