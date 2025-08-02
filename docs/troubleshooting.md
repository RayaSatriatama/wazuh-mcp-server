# Troubleshooting Guide

Comprehensive troubleshooting guide for resolving common issues with the Wazuh MCP Server.

## 🩺 Quick Diagnosis

### Health Check Commands

```bash
# Basic health checks
curl http://localhost:8001/health
curl http://localhost:8002/health

# Service status checks
docker compose ps
docker compose logs --tail=50

# System resource checks
docker stats --no-stream
netstat -tlnp | grep 800[1-4]
```

### Log Analysis

```bash
# Real-time log monitoring
docker compose logs -f wazuh-indexer-http
docker compose logs -f wazuh-manager-http

# Application logs
tail -f wazuh_indexer/logs/mcp_server.log
tail -f wazuh_manager/logs/mcp_server.log

# Error pattern search
grep -i error wazuh_*/logs/*.log
grep -i "connection" wazuh_*/logs/*.log
```

## 🚨 Common Issues and Solutions

### 1. Connection Issues

#### Issue: Cannot Connect to Wazuh Indexer

**Symptoms:**
- HTTP 500 errors from indexer service
- "Connection refused" errors in logs
- Health check failures

**Diagnosis:**
```bash
# Test direct connection
curl -k "https://your-indexer:9200/_cluster/health" \
  -u "username:password"

# Check network connectivity
ping your-indexer-host
telnet your-indexer-host 9200
```

**Solutions:**

1. **Verify Indexer Configuration:**
```env
# Check wazuh_indexer/.env
INDEXER_HOST=correct-hostname-or-ip
INDEXER_PORT=9200
INDEXER_USERNAME=correct-username
INDEXER_PASSWORD=correct-password
```

2. **Check SSL Settings:**
```env
# For self-signed certificates
INDEXER_VERIFY_CERTS=false

# For proper certificates
INDEXER_VERIFY_CERTS=true
INDEXER_SSL_CA_PATH=/path/to/ca.pem
```

3. **Network Troubleshooting:**
```bash
# Check Docker network
docker network ls
docker network inspect wazuh-mcp-network

# Test from container
docker exec -it wazuh-indexer-mcp-http curl -k https://indexer-host:9200
```

#### Issue: Cannot Connect to Wazuh Manager

**Symptoms:**
- Authentication errors
- API endpoint not found
- Timeout errors

**Diagnosis:**
```bash
# Test manager API
curl -k "https://your-manager:55000/" \
  -u "username:password"

# Check API version
curl -k "https://your-manager:55000/manager/info" \
  -u "username:password"
```

**Solutions:**

1. **Verify API Credentials:**
```bash
# Test authentication
curl -k -X POST "https://manager:55000/security/user/authenticate" \
  -H "Content-Type: application/json" \
  -d '{"user":"username", "password":"password"}'
```

2. **Check API Version Compatibility:**
```env
# Ensure correct API version
MANAGER_API_VERSION=v1
MANAGER_PORT=55000
```

3. **Enable Manager API (if needed):**
```xml
<!-- In manager's ossec.conf -->
<ossec_config>
  <api>
    <host>0.0.0.0</host>
    <port>55000</port>
    <use_only_authd>no</use_only_authd>
    <drop_privileges>no</drop_privileges>
    <experimental_features>no</experimental_features>
  </api>
</ossec_config>
```

### 2. Authentication Issues

#### Issue: Invalid Credentials

**Symptoms:**
- 401 Unauthorized errors
- "Authentication failed" messages
- Credential validation errors

**Solutions:**

1. **Indexer Credential Reset:**
```bash
# Generate new password hash
docker exec -it wazuh-indexer bash
cd /usr/share/wazuh-indexer/plugins/opensearch-security/tools
./hash.sh -p newpassword

# Update internal_users.yml
nano /etc/wazuh-indexer/opensearch-security/internal_users.yml
```

2. **Manager Credential Reset:**
```bash
# Reset manager user password
/var/ossec/api/scripts/wazuh-apid-wpk.py -u username -p newpassword
```

3. **API Key Authentication:**
```env
# Use API key instead of basic auth
INDEXER_AUTH_TYPE=api_key
INDEXER_API_KEY=base64_encoded_key
```

#### Issue: SSL Certificate Problems

**Symptoms:**
- SSL verification errors
- Certificate validation failures
- TLS handshake errors

**Solutions:**

1. **Disable Certificate Verification (Development):**
```env
INDEXER_VERIFY_CERTS=false
MANAGER_VERIFY_CERTS=false
```

2. **Provide Certificate Authority:**
```env
INDEXER_SSL_CA_PATH=/certs/root-ca.pem
MANAGER_SSL_CA_PATH=/certs/root-ca.pem
```

3. **Check Certificate Validity:**
```bash
# Verify certificate
openssl x509 -in certificate.pem -text -noout
openssl verify -CAfile ca.pem certificate.pem

# Check certificate expiration
openssl x509 -in certificate.pem -enddate -noout
```

### 3. Performance Issues

#### Issue: Slow Response Times

**Symptoms:**
- High response times (>5 seconds)
- Timeout errors
- Resource exhaustion

**Diagnosis:**
```bash
# Monitor resource usage
docker stats --no-stream
top -p $(pgrep -f "python.*server.py")

# Check connection pools
curl "http://localhost:8001/metrics" | grep connection
```

**Solutions:**

1. **Optimize Connection Settings:**
```env
# Increase connection pool
INDEXER_MAX_CONNECTIONS=20
MANAGER_MAX_CONNECTIONS=10

# Adjust timeouts
INDEXER_TIMEOUT=60
MANAGER_TIMEOUT=45
```

2. **Enable Caching:**
```env
CACHE_ENABLED=true
CACHE_TTL=300
CACHE_MAX_SIZE=1000
```

3. **Optimize Query Limits:**
```env
# Reduce default search size
DEFAULT_SEARCH_SIZE=50
MAX_SEARCH_SIZE=1000
```

#### Issue: Memory Usage Issues

**Symptoms:**
- Out of memory errors
- Container restarts
- Slow performance

**Solutions:**

1. **Increase Memory Limits:**
```yaml
# docker-compose.yml
services:
  wazuh-indexer-http:
    deploy:
      resources:
        limits:
          memory: 1G
        reservations:
          memory: 512M
```

2. **Optimize Memory Usage:**
```env
# Reduce cache size
CACHE_MAX_SIZE=500

# Limit concurrent connections
MAX_CONNECTIONS=10
```

### 4. Docker Issues

#### Issue: Container Won't Start

**Symptoms:**
- Container exits immediately
- "Unable to start container" errors
- Port binding failures

**Diagnosis:**
```bash
# Check container logs
docker logs wazuh-indexer-mcp-http
docker logs wazuh-manager-mcp-http

# Check port conflicts
netstat -tlnp | grep :8001
lsof -i :8001
```

**Solutions:**

1. **Port Conflicts:**
```yaml
# Use different ports
services:
  wazuh-indexer-http:
    ports:
      - "8101:8001"  # External:Internal
```

2. **Permission Issues:**
```bash
# Fix file permissions
sudo chown -R 1000:1000 wazuh_indexer/logs
sudo chown -R 1000:1000 wazuh_manager/logs
```

3. **Environment File Issues:**
```bash
# Validate .env file format
cat -A wazuh_indexer/.env | head -10
dos2unix wazuh_indexer/.env  # Fix line endings
```

#### Issue: Health Checks Failing

**Symptoms:**
- Container marked as unhealthy
- Constant restart loops
- Service unavailable

**Solutions:**

1. **Adjust Health Check Settings:**
```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:8001/health"]
  interval: 60s
  timeout: 30s
  retries: 5
  start_period: 120s
```

2. **Debug Health Check:**
```bash
# Test health check manually
docker exec wazuh-indexer-mcp-http curl -f http://localhost:8001/health
```

### 5. API and Tool Issues

#### Issue: Tools Not Working

**Symptoms:**
- Empty tool responses
- Tool execution errors
- "Tool not found" errors

**Diagnosis:**
```bash
# List available tools
curl http://localhost:8001/tools/list | jq '.tools[] | .name'

# Test specific tool
curl -X POST http://localhost:8001/tools/call \
  -H "Content-Type: application/json" \
  -d '{"name": "get_cluster_health", "arguments": {}}'
```

**Solutions:**

1. **Verify Tool Registration:**
```python
# Check if tools are properly loaded
from wazuh_indexer.server import app
print([tool.name for tool in app.list_tools()])
```

2. **Check Tool Parameters:**
```bash
# Get tool schema
curl http://localhost:8001/tools/list | jq '.tools[] | select(.name=="search_alerts")'
```

#### Issue: Invalid Parameters

**Symptoms:**
- Parameter validation errors
- "Required parameter missing"
- Type conversion errors

**Solutions:**

1. **Parameter Validation:**
```bash
# Check parameter types and requirements
curl -X POST http://localhost:8001/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "name": "search_alerts",
    "arguments": {
      "dsql_query": "rule.level>=10",
      "size": 10
    }
  }' | jq
```

2. **Use Correct Data Types:**
```json
{
  "name": "search_alerts",
  "arguments": {
    "size": 10,           // integer, not "10"
    "from_": 0,           // integer
    "dsql_query": "rule.level>=5"  // string
  }
}
```

### 6. Network and Firewall Issues

#### Issue: External Access Problems

**Symptoms:**
- Cannot access from other machines
- Firewall blocking connections
- Network routing issues

**Solutions:**

1. **Check Firewall Rules:**
```bash
# Ubuntu/Debian
sudo ufw allow 8001:8004/tcp

# CentOS/RHEL
sudo firewall-cmd --add-port=8001-8004/tcp --permanent
sudo firewall-cmd --reload
```

2. **Docker Network Configuration:**
```yaml
# Bind to all interfaces
services:
  wazuh-indexer-http:
    ports:
      - "0.0.0.0:8001:8001"
```

3. **Check Docker Bridge Network:**
```bash
# Inspect Docker networking
docker network inspect bridge
iptables -L -n | grep 8001
```

## 🔧 Advanced Troubleshooting

### Debug Mode

Enable detailed debugging:

```env
# Maximum debug output
LOG_LEVEL=DEBUG
LOG_FORMAT=detailed

# Enable request/response logging
LOG_REQUESTS=true
LOG_RESPONSES=true
```

### Performance Profiling

```bash
# Monitor with system tools
htop
iotop
nethogs

# Docker performance monitoring
docker stats --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}"

# Application profiling
python -m cProfile -o profile.stats run_server.py
```

### Network Debugging

```bash
# Packet capture
sudo tcpdump -i any port 8001 -w capture.pcap

# Network connectivity matrix test
for port in 8001 8002 8003 8004; do
  echo "Testing port $port:"
  nc -zv localhost $port
done
```

### SSL/TLS Debugging

```bash
# Test SSL connection
openssl s_client -connect indexer-host:9200 -verify_return_error

# Check cipher suites
nmap --script ssl-enum-ciphers -p 9200 indexer-host

# Verify certificate chain
openssl verify -verbose -CAfile ca.pem certificate.pem
```

## 📋 Issue Resolution Checklist

### Pre-Resolution Checklist

- [ ] Check service health endpoints
- [ ] Review recent configuration changes
- [ ] Verify Wazuh infrastructure status
- [ ] Check system resources (CPU, memory, disk)
- [ ] Review recent logs for error patterns
- [ ] Test network connectivity
- [ ] Verify authentication credentials

### Post-Resolution Checklist

- [ ] Confirm issue resolution
- [ ] Test related functionality
- [ ] Monitor for recurring issues
- [ ] Update documentation if needed
- [ ] Implement preventive measures
- [ ] Schedule follow-up monitoring

## 🆘 Getting Help

### Collecting Diagnostic Information

```bash
#!/bin/bash
# Diagnostic information collection script

echo "=== Wazuh MCP Server Diagnostic Report ===" > diagnostic.txt
echo "Date: $(date)" >> diagnostic.txt
echo "" >> diagnostic.txt

echo "=== System Information ===" >> diagnostic.txt
uname -a >> diagnostic.txt
docker --version >> diagnostic.txt
docker compose version >> diagnostic.txt
echo "" >> diagnostic.txt

echo "=== Container Status ===" >> diagnostic.txt
docker compose ps >> diagnostic.txt
echo "" >> diagnostic.txt

echo "=== Container Logs ===" >> diagnostic.txt
docker compose logs --tail=100 >> diagnostic.txt
echo "" >> diagnostic.txt

echo "=== Health Checks ===" >> diagnostic.txt
curl -s http://localhost:8001/health >> diagnostic.txt 2>&1
curl -s http://localhost:8002/health >> diagnostic.txt 2>&1
echo "" >> diagnostic.txt

echo "=== Network Status ===" >> diagnostic.txt
netstat -tlnp | grep 800[1-4] >> diagnostic.txt
echo "" >> diagnostic.txt

echo "Diagnostic report saved to diagnostic.txt"
```

### Support Channels

1. **GitHub Issues**: Report bugs and feature requests
2. **Documentation**: Check the latest documentation
3. **Community Forums**: Ask questions and share experiences
4. **Professional Support**: Contact for enterprise support

### When Reporting Issues

Include the following information:

- Wazuh MCP Server version
- Wazuh infrastructure versions
- Operating system and Docker versions
- Complete error messages and logs
- Steps to reproduce the issue
- Configuration files (sanitized)
- Diagnostic report output

This helps ensure faster resolution of your issues.
