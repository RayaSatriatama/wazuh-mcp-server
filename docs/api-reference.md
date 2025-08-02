# API Reference

Complete API documentation for the Wazuh MCP Server endpoints and tools.

## 🌐 Base URLs

| Service | HTTP Mode | SSE Mode | Purpose |
|---------|-----------|----------|---------|
| Wazuh Indexer | `http://localhost:8001` | `http://localhost:8003/sse/` | Search, alerts, analytics |
| Wazuh Manager | `http://localhost:8002` | `http://localhost:8004/sse/` | Agents, rules, management |

## 🔧 HTTP API Endpoints

### Health Check

**GET** `/health`

Check server health and connectivity to Wazuh services.

**Response:**
```json
{
  "status": "healthy",
  "server_name": "Wazuh Indexer MCP Server",
  "cluster_status": "green",
  "timestamp": "2025-08-02T12:00:00Z"
}
```

### Tools Execution

**POST** `/tools/call`

Execute MCP tools with specified parameters.

**Request:**
```json
{
  "name": "tool_name",
  "arguments": {
    "param1": "value1",
    "param2": "value2"
  }
}
```

**Response:**
```json
{
  "content": [
    {
      "type": "text",
      "text": "Tool execution result"
    }
  ],
  "isError": false
}
```

### List Available Tools

**GET** `/tools/list`

Get list of all available MCP tools.

**Response:**
```json
{
  "tools": [
    {
      "name": "get_agents",
      "description": "Get list of Wazuh agents",
      "inputSchema": {
        "type": "object",
        "properties": {
          "limit": {"type": "integer"},
          "offset": {"type": "integer"}
        }
      }
    }
  ]
}
```

## 🔍 Wazuh Indexer Tools

### Search and Analytics

#### `search_alerts`
Search for Wazuh security alerts with flexible field support.

**Parameters:**
```json
{
  "dsql_query": "rule.level>=10 AND agent.name=web-server",
  "size": 100,
  "from_": 0,
  "time_range": {
    "gte": "now-1h",
    "lte": "now"
  },
  "sort_field": "timestamp",
  "sort_order": "desc"
}
```

**Example:**
```bash
curl -X POST http://localhost:8001/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "search_alerts",
    "arguments": {
      "dsql_query": "rule.level>=7",
      "size": 50
    }
  }'
```

#### `search_vulnerabilities`
Search for vulnerability data in the Wazuh indexer.

**Parameters:**
```json
{
  "cve_id": "CVE-2023-1234",
  "severity": "High",
  "agent_id": "001",
  "cvss_min_score": 7.0,
  "size": 100
}
```

#### `search_events`
Search for general events across Wazuh indices.

**Parameters:**
```json
{
  "index_pattern": "wazuh-*",
  "query": "event.type:authentication",
  "time_range": {
    "gte": "now-24h"
  },
  "size": 200
}
```

### Cluster Management

#### `get_cluster_health`
Get cluster health information.

**Parameters:**
```json
{
  "level": "cluster",
  "wait_for_status": "green",
  "timeout": "30s"
}
```

#### `get_cluster_stats`
Get cluster statistics and performance metrics.

**Parameters:**
```json
{
  "human": true,
  "node_id": "all"
}
```

#### `list_indices`
List all indices with basic information.

**Parameters:**
```json
{
  "index": "*",
  "human": true
}
```

### Index Operations

#### `get_index_info`
Get detailed information about indices.

**Parameters:**
```json
{
  "index": "wazuh-alerts-*",
  "include_defaults": false,
  "human": true
}
```

#### `get_index_mapping`
Get field mapping information for indices.

**Parameters:**
```json
{
  "index": "wazuh-alerts-4.x-2025.08.02"
}
```

#### `get_index_stats`
Get statistics for indices.

**Parameters:**
```json
{
  "index": "wazuh-alerts-*",
  "metric": "docs,store,indexing",
  "human": true
}
```

## 👥 Wazuh Manager Tools

### Agent Management

#### `get_agents`
Get list of Wazuh agents.

**Parameters:**
```json
{
  "limit": 100,
  "offset": 0,
  "select": "id,name,ip,status",
  "sort": "name",
  "search": "web"
}
```

**Example:**
```bash
curl -X POST http://localhost:8002/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "get_agents",
    "arguments": {
      "limit": 10,
      "status": "active"
    }
  }'
```

#### `get_agent_info`
Get detailed information about a specific agent.

**Parameters:**
```json
{
  "agent_id": "001",
  "select": "all"
}
```

#### `restart_agent`
Restart a specific Wazuh agent.

**Parameters:**
```json
{
  "agent_list": ["001", "002"]
}
```

#### `add_agent`
Add a new agent to Wazuh.

**Parameters:**
```json
{
  "name": "new-server",
  "ip": "192.168.1.100",
  "groups": ["default", "web-servers"]
}
```

### Rules and Decoders

#### `get_rules`
Get Wazuh detection rules.

**Parameters:**
```json
{
  "limit": 100,
  "offset": 0,
  "search": "ssh",
  "level": "7",
  "group": "authentication"
}
```

#### `get_rule_info`
Get detailed information about a specific rule.

**Parameters:**
```json
{
  "rule_id": "5716"
}
```

#### `get_decoders`
Get Wazuh log decoders.

**Parameters:**
```json
{
  "limit": 50,
  "search": "ssh",
  "decoder_name": "sshd"
}
```

### System Configuration

#### `get_manager_info`
Get Wazuh manager information.

**Parameters:**
```json
{
  "pretty": true
}
```

#### `get_manager_stats`
Get manager statistics and performance metrics.

**Parameters:**
```json
{
  "pretty": true,
  "date": "2025-08-02"
}
```

#### `get_manager_logs`
Get manager log entries.

**Parameters:**
```json
{
  "limit": 100,
  "offset": 0,
  "level": "error",
  "search": "connection"
}
```

### Group Management

#### `get_groups`
Get list of agent groups.

**Parameters:**
```json
{
  "limit": 50,
  "search": "web"
}
```

#### `create_group`
Create a new agent group.

**Parameters:**
```json
{
  "group_id": "web-servers"
}
```

#### `assign_group`
Assign agents to a group.

**Parameters:**
```json
{
  "group_id": "web-servers",
  "agents_list": ["001", "002", "003"]
}
```

## 🔒 Security and Authentication

### API Authentication

The MCP servers inherit authentication from the underlying Wazuh services:

- **Wazuh Manager**: Uses Wazuh API credentials
- **Wazuh Indexer**: Uses OpenSearch/Elasticsearch credentials

### Error Handling

**Error Response Format:**
```json
{
  "content": [
    {
      "type": "text",
      "text": "Error message describing what went wrong"
    }
  ],
  "isError": true,
  "error_code": "WAZUH_API_ERROR",
  "details": {
    "status_code": 400,
    "message": "Invalid parameter"
  }
}
```

**Common Error Codes:**
- `WAZUH_API_ERROR`: Wazuh API returned an error
- `CONNECTION_ERROR`: Cannot connect to Wazuh services
- `AUTHENTICATION_ERROR`: Invalid credentials
- `VALIDATION_ERROR`: Invalid request parameters
- `TIMEOUT_ERROR`: Request timed out

## 📊 Response Formats

### Success Response

```json
{
  "content": [
    {
      "type": "text",
      "text": "Success message or data"
    }
  ],
  "isError": false,
  "metadata": {
    "total_items": 100,
    "returned_items": 10,
    "execution_time": "0.245s"
  }
}
```

### Paginated Response

```json
{
  "content": [
    {
      "type": "text", 
      "text": "Results data"
    }
  ],
  "pagination": {
    "total": 1000,
    "limit": 100,
    "offset": 0,
    "has_next": true,
    "has_prev": false
  }
}
```

## 🔄 Rate Limiting

Default rate limits:
- **HTTP Mode**: 100 requests/minute per IP
- **SSE Mode**: 10 connections per IP
- **STDIO Mode**: No limits (local only)

## 📝 Request Examples

### Python Example

```python
import requests

# Get agents
response = requests.post(
    "http://localhost:8002/tools/call",
    json={
        "name": "get_agents",
        "arguments": {"limit": 5, "status": "active"}
    }
)

if response.status_code == 200:
    result = response.json()
    if not result["isError"]:
        print(result["content"][0]["text"])
    else:
        print(f"Error: {result['content'][0]['text']}")
```

### JavaScript Example

```javascript
async function getAlerts() {
    try {
        const response = await fetch('http://localhost:8001/tools/call', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                name: 'search_alerts',
                arguments: {
                    dsql_query: 'rule.level>=10',
                    size: 20
                }
            })
        });
        
        const result = await response.json();
        
        if (!result.isError) {
            console.log(result.content[0].text);
        } else {
            console.error('Error:', result.content[0].text);
        }
    } catch (error) {
        console.error('Request failed:', error);
    }
}
```

### cURL Examples

```bash
# Get cluster health
curl -X POST http://localhost:8001/tools/call \
  -H "Content-Type: application/json" \
  -d '{"name": "get_cluster_health", "arguments": {}}'

# Search high-severity alerts
curl -X POST http://localhost:8001/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "search_alerts",
    "arguments": {
      "dsql_query": "rule.level>=12",
      "size": 10,
      "time_range": {"gte": "now-1h"}
    }
  }'

# Get active agents
curl -X POST http://localhost:8002/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "get_agents", 
    "arguments": {
      "limit": 20,
      "select": "id,name,ip,status",
      "sort": "name"
    }
  }'
```

This API reference covers the core functionality. For complete tool documentation with all parameters, use the `/tools/list` endpoint or see the [Tools Reference](./tools-reference.md).
