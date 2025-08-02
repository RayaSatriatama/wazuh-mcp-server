# Configuration Reference

Comprehensive configuration guide for the Wazuh MCP Server.

## 📁 Configuration Structure

```
wazuh-mcp-server/
├── wazuh_indexer/
│   ├── .env                    # Indexer environment config
│   └── config/
│       ├── base_config.py      # Base configuration class
│       └── indexer_config.py   # Indexer-specific config
├── wazuh_manager/
│   ├── .env                    # Manager environment config
│   └── config/
│       ├── base_config.py      # Base configuration class
│       └── manager_config.py   # Manager-specific config
├── docker-compose.yml          # Docker orchestration
└── mcp_config.json            # MCP client configuration
```

## 🔧 Environment Configuration

### Wazuh Indexer Configuration

**File:** `wazuh_indexer/.env`

```env
# Wazuh Indexer Connection Settings
INDEXER_HOST=your-wazuh-indexer.domain.com
INDEXER_PORT=9200
INDEXER_USERNAME=admin
INDEXER_PASSWORD=your-secure-password
INDEXER_USE_SSL=true
INDEXER_VERIFY_CERTS=false

# Authentication Configuration
INDEXER_AUTH_TYPE=basic
INDEXER_API_KEY=
INDEXER_BEARER_TOKEN=

# Connection Pool Settings
INDEXER_MAX_CONNECTIONS=10
INDEXER_TIMEOUT=30
INDEXER_RETRY_COUNT=3
INDEXER_RETRY_DELAY=1

# SSL/TLS Configuration
INDEXER_SSL_CERT_PATH=
INDEXER_SSL_KEY_PATH=
INDEXER_SSL_CA_PATH=
INDEXER_SSL_CIPHER_SUITES=
INDEXER_SSL_PROTOCOLS=TLSv1.2,TLSv1.3

# MCP Server Settings
MCP_SERVER_NAME=Wazuh Indexer MCP Server
MCP_SERVER_VERSION=1.0.0
MCP_SERVER_DESCRIPTION=Wazuh Indexer integration for Model Context Protocol

# Transport Configuration
HTTP_ENABLED=true
HTTP_PORT=8001
HTTP_HOST=0.0.0.0

SSE_ENABLED=true
SSE_PORT=8003
SSE_HOST=0.0.0.0

STDIO_ENABLED=true

# Logging Configuration
LOG_LEVEL=INFO
LOG_FORMAT=detailed
LOG_FILE_PATH=logs/mcp_server.log
LOG_MAX_SIZE=10MB
LOG_BACKUP_COUNT=5
LOG_ROTATION=time
LOG_ROTATION_INTERVAL=midnight

# Performance Settings
MAX_SEARCH_SIZE=10000
DEFAULT_SEARCH_SIZE=100
SCROLL_SIZE=1000
SCROLL_TIMEOUT=1m
BULK_SIZE=500

# Cache Configuration
CACHE_ENABLED=true
CACHE_TTL=300
CACHE_MAX_SIZE=1000

# Index Patterns
DEFAULT_ALERT_INDEX=wazuh-alerts-*
DEFAULT_STATE_INDEX=wazuh-states-*
DEFAULT_VULNERABILITY_INDEX=wazuh-states-vulnerabilities-*

# Query Limits
MAX_QUERY_TIME=60
MAX_AGGREGATION_SIZE=1000
MAX_SCROLL_TIME=5m
```

### Wazuh Manager Configuration

**File:** `wazuh_manager/.env`

```env
# Wazuh Manager Connection Settings
MANAGER_HOST=your-wazuh-manager.domain.com
MANAGER_PORT=55000
MANAGER_USERNAME=wazuh
MANAGER_PASSWORD=your-api-password
MANAGER_USE_SSL=true
MANAGER_VERIFY_CERTS=false

# API Configuration
MANAGER_API_VERSION=v1
MANAGER_AUTH_TYPE=basic
MANAGER_API_TOKEN=
MANAGER_LOGIN_ENDPOINT=/security/user/authenticate

# Connection Settings
MANAGER_TIMEOUT=30
MANAGER_RETRY_COUNT=3
MANAGER_RETRY_DELAY=2
MANAGER_MAX_CONNECTIONS=5

# SSL/TLS Configuration
MANAGER_SSL_CERT_PATH=
MANAGER_SSL_KEY_PATH=
MANAGER_SSL_CA_PATH=
MANAGER_SSL_VERIFY_MODE=CERT_REQUIRED

# MCP Server Settings
MCP_SERVER_NAME=Wazuh Manager MCP Server
MCP_SERVER_VERSION=1.0.0
MCP_SERVER_DESCRIPTION=Wazuh Manager API integration for Model Context Protocol

# Transport Configuration
HTTP_ENABLED=true
HTTP_PORT=8002
HTTP_HOST=0.0.0.0

SSE_ENABLED=true
SSE_PORT=8004
SSE_HOST=0.0.0.0

STDIO_ENABLED=true

# Logging Configuration
LOG_LEVEL=INFO
LOG_FORMAT=detailed
LOG_FILE_PATH=logs/mcp_server.log
LOG_MAX_SIZE=10MB
LOG_BACKUP_COUNT=5

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=60
RATE_LIMIT_BURST=20

# Cache Configuration
CACHE_ENABLED=true
CACHE_TTL=180
CACHE_MAX_SIZE=500

# Default Limits
DEFAULT_LIMIT=100
MAX_LIMIT=1000
DEFAULT_OFFSET=0

# Agent Management
AUTO_RESTART_AGENTS=false
AGENT_TIMEOUT=30
BULK_AGENT_OPERATIONS=true
```

## 🐳 Docker Configuration

### Docker Compose Configuration

**File:** `docker-compose.yml`

```yaml
version: '3.8'

x-common-environment: &common-env
  LOG_LEVEL: ${LOG_LEVEL:-INFO}
  PYTHONPATH: /app

x-common-restart: &common-restart
  restart: unless-stopped

x-common-healthcheck: &common-healthcheck
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 40s

services:
  # Wazuh Indexer Services
  wazuh-indexer-http:
    build:
      context: .
      dockerfile: deployment/docker/Dockerfile
      target: indexer
    container_name: wazuh-indexer-mcp-http
    environment:
      <<: *common-env
      TRANSPORT_MODE: http
      HTTP_PORT: 8001
    env_file:
      - wazuh_indexer/.env
    ports:
      - "8001:8001"
    volumes:
      - ./wazuh_indexer/logs:/app/logs
      - ./wazuh_indexer/.env:/app/.env:ro
    healthcheck:
      <<: *common-healthcheck
      test: ["CMD", "curl", "-f", "http://localhost:8001/health"]
    profiles:
      - http
      - all
    <<: *common-restart
    networks:
      - wazuh-mcp

  wazuh-indexer-sse:
    build:
      context: .
      dockerfile: deployment/docker/Dockerfile
      target: indexer
    container_name: wazuh-indexer-mcp-sse
    environment:
      <<: *common-env
      TRANSPORT_MODE: sse
      SSE_PORT: 8003
    env_file:
      - wazuh_indexer/.env
    ports:
      - "8003:8003"
    volumes:
      - ./wazuh_indexer/logs:/app/logs
      - ./wazuh_indexer/.env:/app/.env:ro
    healthcheck:
      <<: *common-healthcheck
      test: ["CMD", "curl", "-f", "http://localhost:8003/health"]
    profiles:
      - sse
      - all
    <<: *common-restart
    networks:
      - wazuh-mcp

  # Wazuh Manager Services
  wazuh-manager-http:
    build:
      context: .
      dockerfile: deployment/docker/Dockerfile
      target: manager
    container_name: wazuh-manager-mcp-http
    environment:
      <<: *common-env
      TRANSPORT_MODE: http
      HTTP_PORT: 8002
    env_file:
      - wazuh_manager/.env
    ports:
      - "8002:8002"
    volumes:
      - ./wazuh_manager/logs:/app/logs
      - ./wazuh_manager/.env:/app/.env:ro
    healthcheck:
      <<: *common-healthcheck
      test: ["CMD", "curl", "-f", "http://localhost:8002/health"]
    profiles:
      - http
      - all
    <<: *common-restart
    networks:
      - wazuh-mcp

networks:
  wazuh-mcp:
    driver: bridge
    name: wazuh-mcp-network

volumes:
  indexer_logs:
    driver: local
  manager_logs:
    driver: local
```

### Environment Override

Create a `.env` file in the project root for global overrides:

```env
# Global Configuration
COMPOSE_PROJECT_NAME=wazuh-mcp
COMPOSE_PROFILES=http,sse

# Global Logging
LOG_LEVEL=DEBUG
LOG_FORMAT=json

# Global Network
NETWORK_NAME=wazuh-mcp-network

# Global Restart Policy
RESTART_POLICY=unless-stopped
```

## 🛠️ Advanced Configuration

### Custom Port Configuration

```env
# Custom port mapping
HTTP_PORT_INDEXER=9001
HTTP_PORT_MANAGER=9002
SSE_PORT_INDEXER=9003
SSE_PORT_MANAGER=9004
```

**Docker Compose Override:**

```yaml
# docker-compose.override.yml
version: '3.8'

services:
  wazuh-indexer-http:
    ports:
      - "${HTTP_PORT_INDEXER:-9001}:8001"
  
  wazuh-manager-http:
    ports:
      - "${HTTP_PORT_MANAGER:-9002}:8002"
```

### SSL/TLS Configuration

#### Certificate-Based Authentication

```env
# Indexer SSL Configuration
INDEXER_USE_SSL=true
INDEXER_VERIFY_CERTS=true
INDEXER_SSL_CERT_PATH=/certs/client.pem
INDEXER_SSL_KEY_PATH=/certs/client-key.pem
INDEXER_SSL_CA_PATH=/certs/ca.pem

# Manager SSL Configuration
MANAGER_USE_SSL=true
MANAGER_VERIFY_CERTS=true
MANAGER_SSL_CERT_PATH=/certs/manager-client.pem
MANAGER_SSL_KEY_PATH=/certs/manager-client-key.pem
MANAGER_SSL_CA_PATH=/certs/manager-ca.pem
```

#### Docker Volume Mapping

```yaml
services:
  wazuh-indexer-http:
    volumes:
      - ./certs:/certs:ro
      - ./wazuh_indexer/.env:/app/.env:ro
```

### Logging Configuration

#### Structured Logging

```env
# JSON logging for better parsing
LOG_FORMAT=json
LOG_STRUCTURED=true
LOG_INCLUDE_TIMESTAMP=true
LOG_INCLUDE_LEVEL=true
LOG_INCLUDE_LOGGER=true
LOG_INCLUDE_THREAD=true
```

#### Log Aggregation

```env
# Syslog configuration
LOG_SYSLOG_ENABLED=true
LOG_SYSLOG_HOST=your-syslog-server.com
LOG_SYSLOG_PORT=514
LOG_SYSLOG_FACILITY=local0

# External logging service
LOG_EXTERNAL_ENABLED=true
LOG_EXTERNAL_ENDPOINT=https://logs.example.com/api/logs
LOG_EXTERNAL_API_KEY=your-api-key
```

### Performance Tuning

#### Connection Pool Optimization

```env
# Indexer connection tuning
INDEXER_MAX_CONNECTIONS=20
INDEXER_CONNECTION_POOL_SIZE=10
INDEXER_CONNECTION_TIMEOUT=60
INDEXER_READ_TIMEOUT=300
INDEXER_KEEP_ALIVE=true

# Manager connection tuning
MANAGER_MAX_CONNECTIONS=10
MANAGER_CONNECTION_POOL_SIZE=5
MANAGER_SESSION_REUSE=true
```

#### Memory Management

```env
# Memory optimization
MEMORY_LIMIT=512MB
WORKER_PROCESSES=2
WORKER_CONNECTIONS=1000
PRELOAD_APP=true
```

#### Caching Configuration

```env
# Redis cache configuration
CACHE_TYPE=redis
CACHE_REDIS_HOST=redis-server
CACHE_REDIS_PORT=6379
CACHE_REDIS_DB=0
CACHE_REDIS_PASSWORD=cache-password

# Memory cache configuration
CACHE_TYPE=memory
CACHE_MEMORY_SIZE=100MB
CACHE_MEMORY_CLEANUP_INTERVAL=300
```

### Security Configuration

#### API Key Authentication

```env
# API key authentication
INDEXER_AUTH_TYPE=api_key
INDEXER_API_KEY=your-base64-encoded-api-key

MANAGER_AUTH_TYPE=token
MANAGER_API_TOKEN=your-jwt-token
```

#### IP Restrictions

```env
# Access control
ALLOWED_IPS=192.168.1.0/24,10.0.0.0/8
BLOCKED_IPS=192.168.1.100
RATE_LIMIT_BY_IP=true
```

#### Request Validation

```env
# Input validation
VALIDATE_REQUESTS=true
MAX_REQUEST_SIZE=10MB
MAX_QUERY_COMPLEXITY=1000
SANITIZE_INPUTS=true
```

## 📊 Monitoring Configuration

### Health Check Configuration

```env
# Health check settings
HEALTH_CHECK_ENABLED=true
HEALTH_CHECK_INTERVAL=30
HEALTH_CHECK_TIMEOUT=10
HEALTH_CHECK_RETRIES=3

# Dependency health checks
CHECK_INDEXER_HEALTH=true
CHECK_MANAGER_HEALTH=true
CHECK_DATABASE_HEALTH=false
```

### Metrics Collection

```env
# Prometheus metrics
METRICS_ENABLED=true
METRICS_PORT=9090
METRICS_PATH=/metrics
METRICS_NAMESPACE=wazuh_mcp

# Custom metrics
TRACK_REQUEST_DURATION=true
TRACK_ERROR_RATES=true
TRACK_CACHE_PERFORMANCE=true
```

### Alerting Configuration

```env
# Alert thresholds
ALERT_ERROR_RATE_THRESHOLD=5
ALERT_RESPONSE_TIME_THRESHOLD=5000
ALERT_MEMORY_THRESHOLD=80
ALERT_CPU_THRESHOLD=85

# Notification channels
ALERT_EMAIL_ENABLED=true
ALERT_EMAIL_SMTP_HOST=smtp.example.com
ALERT_EMAIL_RECIPIENTS=admin@example.com

ALERT_SLACK_ENABLED=false
ALERT_SLACK_WEBHOOK_URL=https://hooks.slack.com/...
```

## 🔄 Configuration Validation

### Validation Scripts

```bash
# Validate configuration
python -c "
import os
from wazuh_indexer.config.indexer_config import IndexerConfig
from wazuh_manager.config.manager_config import ManagerConfig

# Validate indexer config
try:
    indexer_config = IndexerConfig()
    print('✓ Indexer configuration valid')
except Exception as e:
    print(f'✗ Indexer configuration error: {e}')

# Validate manager config
try:
    manager_config = ManagerConfig()
    print('✓ Manager configuration valid')
except Exception as e:
    print(f'✗ Manager configuration error: {e}')
"
```

### Configuration Testing

```bash
# Test connectivity
python -c "
from wazuh_indexer.services.indexer_service import IndexerService
from wazuh_manager.services.manager_service import ManagerService

# Test indexer connection
try:
    indexer = IndexerService()
    health = indexer.get_cluster_health()
    print(f'✓ Indexer connection successful: {health[\"cluster_name\"]}')
except Exception as e:
    print(f'✗ Indexer connection failed: {e}')

# Test manager connection
try:
    manager = ManagerService()
    info = manager.get_manager_info()
    print(f'✓ Manager connection successful: {info[\"name\"]}')
except Exception as e:
    print(f'✗ Manager connection failed: {e}')
"
```

## 🔧 Configuration Examples

### Development Environment

```env
# Development settings
LOG_LEVEL=DEBUG
INDEXER_VERIFY_CERTS=false
MANAGER_VERIFY_CERTS=false
CACHE_ENABLED=false
RATE_LIMIT_ENABLED=false
METRICS_ENABLED=true
```

### Production Environment

```env
# Production settings
LOG_LEVEL=WARNING
INDEXER_VERIFY_CERTS=true
MANAGER_VERIFY_CERTS=true
CACHE_ENABLED=true
RATE_LIMIT_ENABLED=true
METRICS_ENABLED=true
HEALTH_CHECK_ENABLED=true
```

### High Availability Setup

```env
# HA configuration
INDEXER_HOST=indexer-cluster.internal,indexer-backup.internal
MANAGER_HOST=manager-primary.internal,manager-backup.internal
CONNECTION_FAILOVER=true
RETRY_COUNT=5
HEALTH_CHECK_INTERVAL=15
```

For troubleshooting configuration issues, see the [Troubleshooting Guide](./troubleshooting.md).
