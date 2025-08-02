# Security Policy

## Supported Versions

We actively support and provide security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take the security of the Wazuh MCP Server seriously. If you discover a security vulnerability, please follow these steps:

### 🔒 **Private Disclosure**

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead, please report security vulnerabilities by:

1. **Email**: Send details to [security@rayasatriatama.dev](mailto:security@rayasatriatama.dev)
2. **Subject**: Include "SECURITY" in the subject line
3. **Details**: Provide as much information as possible

### 📋 **What to Include**

Please include the following information in your report:

- **Description** of the vulnerability
- **Steps to reproduce** the issue
- **Potential impact** assessment
- **Suggested fix** (if you have one)
- **Your contact information**

### ⏱️ **Response Timeline**

- **Initial Response**: Within 48 hours of receiving your report
- **Triage**: Within 5 business days we'll provide a detailed response
- **Resolution**: Security fixes will be prioritized and released as soon as possible

### 🛡️ **Security Best Practices**

When deploying Wazuh MCP Server:

#### **Authentication & Authorization**
- Use strong passwords for Wazuh Manager API access
- Regularly rotate API credentials
- Implement proper network segmentation
- Use HTTPS/TLS for all communications

#### **Container Security**
- Keep Docker images updated
- Use non-root users in containers
- Implement resource limits
- Scan images for vulnerabilities

#### **Network Security**
- Restrict access to MCP server ports (8001-8004)
- Use firewalls to limit network access
- Consider VPN access for remote connections
- Monitor network traffic for anomalies

#### **Environment Security**
- Secure environment variable files (.env)
- Use secrets management systems in production
- Regularly audit access logs
- Keep dependencies updated

### 🔍 **Security Scanning**

We recommend regular security scanning:

```bash
# Dependency vulnerability scanning
pip-audit

# Container image scanning
docker scan wazuh-mcp-server:latest

# Code security analysis
bandit -r src/
```

### 🚨 **Known Security Considerations**

#### **MCP Protocol Security**
- MCP servers have access to Wazuh data
- Implement proper access controls
- Monitor MCP client connections
- Audit tool usage and data access

#### **Wazuh Integration Security**
- Secure Wazuh Manager API access
- Protect Wazuh Indexer credentials
- Monitor API usage patterns
- Implement rate limiting

### 📚 **Security Resources**

- [Wazuh Security Guide](https://documentation.wazuh.com/current/user-manual/manager/manual-integration.html)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [Python Security Guidelines](https://python-security.readthedocs.io/)
- [MCP Security Considerations](https://modelcontextprotocol.io/docs/concepts/security)

### 🤝 **Responsible Disclosure**

We follow responsible disclosure practices:

1. **Investigation**: We'll investigate all reported vulnerabilities
2. **Communication**: We'll keep you informed of our progress
3. **Credit**: We'll provide credit for valid vulnerability reports (if desired)
4. **Coordination**: We'll coordinate disclosure timeline with you

### 🏆 **Security Hall of Fame**

We recognize security researchers who help improve our security:

*No reports yet - be the first!*

---

Thank you for helping keep Wazuh MCP Server secure! 🛡️

**Last Updated**: August 2, 2025
