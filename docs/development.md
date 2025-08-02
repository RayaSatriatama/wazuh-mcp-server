# Development Guide

Guide for developers working on the Wazuh MCP Server project.

## 🏗️ Development Environment Setup

### Prerequisites

- **Python 3.9+** with pip and venv
- **Git** for version control
- **Docker** and Docker Compose for testing
- **IDE** with Python support (VS Code, PyCharm, etc.)

### Initial Setup

```bash
# Clone the repository
git clone https://github.com/your-org/wazuh-mcp-server.git
cd wazuh-mcp-server

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# Install development dependencies
pip install -r requirements-dev.txt
pip install -e .

# Install pre-commit hooks
pre-commit install
```

### Development Dependencies

Create `requirements-dev.txt`:

```txt
# Core framework
fastmcp==2.11.0

# Wazuh integrations
requests>=2.31.0
elasticsearch>=8.10.0
python-dotenv>=1.0.0

# Development tools
pytest>=7.4.0
pytest-asyncio>=0.21.0
pytest-cov>=4.1.0
black>=23.0.0
isort>=5.12.0
flake8>=6.0.0
mypy>=1.5.0

# Documentation
mkdocs>=1.5.0
mkdocs-material>=9.2.0
mkdocs-mermaid2-plugin>=1.1.0

# Testing and mocking
requests-mock>=1.11.0
httpx>=0.24.0
```

## 🔧 Project Structure

### Code Organization

```
wazuh-mcp-server/
├── wazuh_indexer/           # Indexer MCP server
│   ├── __init__.py
│   ├── server.py            # Main server entry point
│   ├── run_server.py        # Server runner script
│   ├── config/              # Configuration modules
│   │   ├── base_config.py   # Base configuration class
│   │   └── indexer_config.py # Indexer-specific config
│   ├── services/            # Service layer
│   │   └── indexer_service.py # Core business logic
│   ├── tools/               # MCP tool implementations
│   │   ├── search_tools.py  # Search and query tools
│   │   ├── cluster_tools.py # Cluster management tools
│   │   └── monitoring_tools.py # Monitoring tools
│   └── utils/               # Utility modules
│       └── logger.py        # Logging utilities
├── wazuh_manager/           # Manager MCP server (similar structure)
├── common/                  # Shared components
│   ├── __init__.py
│   ├── base_mcp_server.py   # Base MCP server class
│   ├── exceptions.py        # Custom exceptions
│   └── validators.py        # Input validation
├── tests/                   # Test suite
│   ├── unit/                # Unit tests
│   ├── integration/         # Integration tests
│   └── fixtures/            # Test fixtures
├── docs/                    # Documentation
└── deployment/              # Deployment configurations
```

### Architecture Patterns

#### 1. Service Layer Pattern

```python
# wazuh_indexer/services/indexer_service.py
from typing import Dict, Any, Optional, List
from elasticsearch import Elasticsearch
from ..config.indexer_config import IndexerConfig

class IndexerService:
    """Service class for Wazuh Indexer operations."""
    
    def __init__(self, config: IndexerConfig):
        self.config = config
        self.client = self._create_client()
    
    def _create_client(self) -> Elasticsearch:
        """Create configured Elasticsearch client."""
        return Elasticsearch(
            hosts=[f"{self.config.host}:{self.config.port}"],
            http_auth=(self.config.username, self.config.password),
            use_ssl=self.config.use_ssl,
            verify_certs=self.config.verify_certs
        )
    
    async def search_alerts(
        self,
        query: Optional[str] = None,
        size: int = 100,
        from_: int = 0,
        **kwargs
    ) -> Dict[str, Any]:
        """Search for alerts in Wazuh indices."""
        # Implementation here
        pass
```

#### 2. Tool Registration Pattern

```python
# wazuh_indexer/tools/search_tools.py
from fastmcp import Tool
from pydantic import BaseModel
from typing import Optional

class SearchAlertsParams(BaseModel):
    dsql_query: Optional[str] = None
    size: int = 100
    from_: int = 0
    time_range: Optional[dict] = None

@Tool(name="search_alerts", description="Search for Wazuh security alerts")
async def search_alerts(params: SearchAlertsParams) -> str:
    """Search for alerts with flexible field support."""
    service = get_indexer_service()
    results = await service.search_alerts(
        query=params.dsql_query,
        size=params.size,
        from_=params.from_,
        time_range=params.time_range
    )
    return format_search_results(results)
```

#### 3. Configuration Management

```python
# common/base_config.py
from pydantic import BaseSettings
from typing import Optional

class BaseConfig(BaseSettings):
    """Base configuration class."""
    
    log_level: str = "INFO"
    log_format: str = "detailed"
    mcp_server_name: str = "Wazuh MCP Server"
    mcp_server_version: str = "1.0.0"
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

# wazuh_indexer/config/indexer_config.py
class IndexerConfig(BaseConfig):
    """Wazuh Indexer specific configuration."""
    
    indexer_host: str = "localhost"
    indexer_port: int = 9200
    indexer_username: str = "admin"
    indexer_password: str
    indexer_use_ssl: bool = True
    indexer_verify_certs: bool = False
    
    class Config:
        env_prefix = "INDEXER_"
```

## 🧪 Testing

### Test Structure

```
tests/
├── unit/                    # Unit tests
│   ├── test_indexer_service.py
│   ├── test_manager_service.py
│   └── test_tools.py
├── integration/             # Integration tests
│   ├── test_indexer_integration.py
│   └── test_manager_integration.py
├── fixtures/                # Test data
│   ├── sample_alerts.json
│   └── sample_agents.json
└── conftest.py             # Pytest configuration
```

### Unit Testing

```python
# tests/unit/test_indexer_service.py
import pytest
from unittest.mock import Mock, patch
from wazuh_indexer.services.indexer_service import IndexerService
from wazuh_indexer.config.indexer_config import IndexerConfig

@pytest.fixture
def mock_config():
    return IndexerConfig(
        indexer_host="test-host",
        indexer_port=9200,
        indexer_username="test",
        indexer_password="test",
        indexer_use_ssl=False
    )

@pytest.fixture
def indexer_service(mock_config):
    with patch('wazuh_indexer.services.indexer_service.Elasticsearch'):
        return IndexerService(mock_config)

@pytest.mark.asyncio
async def test_search_alerts_basic(indexer_service):
    """Test basic alert search functionality."""
    # Mock Elasticsearch response
    mock_response = {
        "hits": {
            "total": {"value": 10},
            "hits": [
                {"_source": {"rule": {"level": 5}, "agent": {"name": "test"}}}
            ]
        }
    }
    
    indexer_service.client.search.return_value = mock_response
    
    result = await indexer_service.search_alerts(query="test", size=10)
    
    assert result["total"] == 10
    assert len(result["alerts"]) == 1
    indexer_service.client.search.assert_called_once()
```

### Integration Testing

```python
# tests/integration/test_indexer_integration.py
import pytest
import httpx
from testcontainers.elasticsearch import ElasticSearchContainer

@pytest.fixture(scope="session")
def elasticsearch_container():
    """Start Elasticsearch container for testing."""
    with ElasticSearchContainer() as es:
        yield es

@pytest.fixture
def indexer_client(elasticsearch_container):
    """Create indexer client connected to test container."""
    config = IndexerConfig(
        indexer_host=elasticsearch_container.get_container_host_ip(),
        indexer_port=elasticsearch_container.get_exposed_port(9200),
        indexer_use_ssl=False,
        indexer_verify_certs=False
    )
    return IndexerService(config)

@pytest.mark.integration
async def test_real_search(indexer_client):
    """Test search against real Elasticsearch instance."""
    # This test requires actual Wazuh indices
    result = await indexer_client.search_alerts(size=1)
    assert "alerts" in result
```

### Running Tests

```bash
# Run all tests
pytest

# Run unit tests only
pytest tests/unit/

# Run with coverage
pytest --cov=wazuh_indexer --cov=wazuh_manager

# Run integration tests (requires Docker)
pytest -m integration

# Run specific test file
pytest tests/unit/test_indexer_service.py

# Run with verbose output
pytest -v

# Run tests matching pattern
pytest -k "search_alerts"
```

## 🔍 Code Quality

### Code Formatting

```bash
# Format code with Black
black wazuh_indexer/ wazuh_manager/ common/

# Sort imports with isort
isort wazuh_indexer/ wazuh_manager/ common/

# Lint with flake8
flake8 wazuh_indexer/ wazuh_manager/ common/

# Type checking with mypy
mypy wazuh_indexer/ wazuh_manager/ common/
```

### Pre-commit Configuration

Create `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/psf/black
    rev: 23.7.0
    hooks:
      - id: black
        language_version: python3.9

  - repo: https://github.com/pycqa/isort
    rev: 5.12.0
    hooks:
      - id: isort

  - repo: https://github.com/pycqa/flake8
    rev: 6.0.0
    hooks:
      - id: flake8

  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.5.1
    hooks:
      - id: mypy
        additional_dependencies: [types-requests]
```

### Code Style Guidelines

#### Python Style

- Follow **PEP 8** style guide
- Use **type hints** for all function signatures
- Maximum line length: **88 characters** (Black default)
- Use **docstrings** for all public functions and classes

```python
async def search_alerts(
    self,
    query: Optional[str] = None,
    size: int = 100,
    from_: int = 0,
    time_range: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """
    Search for Wazuh security alerts.
    
    Args:
        query: DSQL query string for filtering
        size: Number of results to return (max 10000)
        from_: Starting offset for pagination
        time_range: Time range filter with 'gte' and 'lte' keys
        
    Returns:
        Dictionary containing search results and metadata
        
    Raises:
        ConnectionError: If unable to connect to Wazuh Indexer
        ValidationError: If parameters are invalid
    """
```

#### Error Handling

```python
# common/exceptions.py
class WazuhMCPError(Exception):
    """Base exception for Wazuh MCP Server."""
    pass

class ConnectionError(WazuhMCPError):
    """Raised when connection to Wazuh services fails."""
    pass

class ValidationError(WazuhMCPError):
    """Raised when input validation fails."""
    pass

# Usage in services
try:
    result = await self.client.search(index="wazuh-alerts-*", body=query)
except Exception as e:
    raise ConnectionError(f"Failed to search alerts: {str(e)}") from e
```

## 🐛 Debugging

### Local Debugging

```python
# Add debug logging
import logging
logging.basicConfig(level=logging.DEBUG)

# Use debugger
import pdb; pdb.set_trace()

# Or with breakpoint() in Python 3.7+
breakpoint()
```

### Docker Debugging

```bash
# Run container with debug mode
docker compose -f docker-compose.debug.yml up

# Execute commands in running container
docker exec -it wazuh-indexer-mcp-http bash

# View detailed logs
docker logs -f wazuh-indexer-mcp-http

# Debug with Python debugger in container
docker exec -it wazuh-indexer-mcp-http python -m pdb server.py
```

### Debug Configuration

Create `docker-compose.debug.yml`:

```yaml
version: '3.8'

services:
  wazuh-indexer-http:
    build:
      context: .
      dockerfile: deployment/docker/Dockerfile.debug
    environment:
      - LOG_LEVEL=DEBUG
      - PYTHONPATH=/app
    volumes:
      - .:/app
    ports:
      - "8001:8001"
      - "5678:5678"  # Debug port
    command: python -m debugpy --listen 0.0.0.0:5678 --wait-for-client server.py
```

## 📖 Documentation

### API Documentation

Use **docstrings** and **type hints** for automatic documentation generation:

```python
from typing import Dict, Any, Optional, List

async def search_alerts(
    self,
    dsql_query: Optional[str] = None,
    size: int = 100,
    fields: Optional[str] = None
) -> Dict[str, Any]:
    """
    Search for Wazuh security alerts with flexible field support.
    
    Supports any field in the alert structure through DSQL queries.
    Examples:
        - "rule.level>=10 AND agent.name=web-server"
        - "data.srcip=192.168.1.100 AND data.protocol=TCP"
        - "rule.mitre.id=T1055 OR rule.mitre.id=T1003"
    
    Args:
        dsql_query: DSQL query string for filtering alerts
        size: Maximum number of results to return (1-10000)
        fields: Comma-separated list of specific fields to include
        
    Returns:
        Dictionary containing:
            - alerts: List of matching alert documents
            - total: Total number of matching alerts
            - metadata: Search execution metadata
            
    Raises:
        ConnectionError: If unable to connect to Wazuh Indexer
        ValidationError: If query parameters are invalid
        QueryError: If DSQL query syntax is invalid
        
    Example:
        >>> results = await search_alerts(
        ...     dsql_query="rule.level>=7",
        ...     size=50
        ... )
        >>> print(f"Found {results['total']} alerts")
    """
```

### README Updates

When adding new features, update relevant documentation:

```bash
# Update main README
nano README.md

# Update specific documentation
nano docs/api-reference.md
nano docs/tools-reference.md
```

## 🚀 Deployment

### Development Deployment

```bash
# Quick development start
docker compose --profile http up -d

# Development with hot reload
docker compose -f docker-compose.dev.yml up -d
```

### Production Deployment

```bash
# Build production images
docker build -t wazuh-mcp-indexer:latest -f deployment/docker/Dockerfile .

# Deploy with production configuration
docker compose -f deployment/docker/docker-compose.yml up -d
```

### CI/CD Pipeline

Create `.github/workflows/ci.yml`:

```yaml
name: CI/CD Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'
        
    - name: Install dependencies
      run: |
        pip install -r requirements-dev.txt
        
    - name: Run tests
      run: |
        pytest --cov=wazuh_indexer --cov=wazuh_manager
        
    - name: Upload coverage
      uses: codecov/codecov-action@v3
      
  lint:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'
        
    - name: Lint code
      run: |
        pip install black isort flake8 mypy
        black --check .
        isort --check-only .
        flake8 .
        mypy .
```

## 🔄 Contributing Workflow

### Feature Development

```bash
# Create feature branch
git checkout -b feature/new-search-tool

# Make changes and commit
git add .
git commit -m "feat: add advanced search tool with aggregations"

# Push and create pull request
git push origin feature/new-search-tool
```

### Commit Message Format

Follow **Conventional Commits**:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Adding/updating tests
- `chore`: Maintenance tasks

**Examples:**
```
feat(indexer): add vulnerability search tool
fix(manager): resolve agent restart timeout issue
docs: update API reference for new tools
test: add integration tests for search functionality
```

### Pull Request Template

Create `.github/pull_request_template.md`:

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests added/updated
```

## 🏆 Best Practices

### Performance

- Use **async/await** for I/O operations
- Implement **connection pooling** for external services
- Add **caching** for frequently accessed data
- Use **pagination** for large result sets

### Security

- **Validate all inputs** before processing
- **Sanitize** user-provided queries
- Use **environment variables** for secrets
- Implement **rate limiting** for public APIs

### Monitoring

- Add **structured logging** with correlation IDs
- Implement **health checks** for all services
- Export **metrics** for monitoring systems
- Set up **alerting** for critical errors

### Error Handling

- Use **specific exception types** for different error conditions
- Provide **meaningful error messages** to users
- Log **detailed error information** for debugging
- Implement **graceful degradation** when possible

This development guide provides the foundation for contributing to the Wazuh MCP Server project. For additional questions, refer to the project documentation or reach out to the development team.
