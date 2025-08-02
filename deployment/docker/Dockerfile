# Production-ready Dockerfile for Wazuh MCP Servers
FROM python:3.11-slim

# Set environment variables for optimization
ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install minimal system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create app directory
WORKDIR /app

# Copy requirements first for better Docker layer caching
COPY deployment/requirements-mcp.txt .

# Install Python dependencies with timeout and retry settings
RUN pip install --upgrade pip --timeout 300 && \
    pip install --no-cache-dir -r requirements-mcp.txt --timeout 300 --retries 3

# Copy only necessary application files
COPY wazuh_indexer/ ./wazuh_indexer/
COPY wazuh_manager/ ./wazuh_manager/
COPY __init__.py ./__init__.py

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash --uid 1000 mcp && \
    chown -R mcp:mcp /app

USER mcp

# Expose ports for both servers
EXPOSE 8001 8002

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8001/health || curl -f http://localhost:8002/health || exit 1
