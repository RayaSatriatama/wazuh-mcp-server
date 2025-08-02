# Wazuh MCP Server Tests

This folder contains tests specifically for Wazuh MCP server functionality and registration.

## Test Files

### `test_mcp_registration_fix.py`
- Tests MCP tool registration for both Wazuh Manager and Wazuh Indexer servers
- Verifies tool count: 108 tools for Manager, 35 tools for Indexer
- Validates that tools are properly registered with FastMCP for UI visibility
- Tests centralized service integration

### `test_registration_fix.py`
- Simplified registration test
- Basic validation of server startup and tool loading
- Quick verification of MCP tool registration

## Running Tests

### Individual Test Files
```bash
# Run MCP registration tests
python test_mcp_registration_fix.py

# Run basic registration test
python test_registration_fix.py
```

### From Project Root
```bash
# Run all MCP server tests
python -m pytest tests/ -v

# Run specific test
python -m pytest tests/test_mcp_registration_fix.py -v
```

## Test Coverage

These tests specifically verify:
- ✅ MCP tool registration (not just function creation)
- ✅ Correct tool counts for each server
- ✅ Centralized service integration
- ✅ Server startup and initialization
- ✅ FastMCP compatibility for UI visibility

## Prerequisites

Ensure you have:
1. Environment variables configured (see `../deployment/.env.production.example`)
2. Wazuh API access (for integration tests)
3. Required dependencies installed (`pip install -r ../deployment/requirements-mcp.txt`)

## Notes

These tests complement the main test suite in `/tests/` but focus specifically on MCP server functionality rather than general agent behavior. 