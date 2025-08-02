#!/usr/bin/env python3
"""
Simple script to test FastMCP SSE endpoints.
This can be used to verify that the MCP servers are running correctly.
"""

import asyncio
import httpx
import sys
from typing import Optional

async def test_sse_endpoint(base_url: str, port: int, timeout: float = 10.0) -> bool:
    """Test if FastMCP SSE endpoint is accessible."""
    sse_url = f"{base_url}:{port}/mcp"
    
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(sse_url)
            print(f"✓ FastMCP SSE endpoint {sse_url} - Status: {response.status_code}")
            return response.status_code in [200, 307]  # 307 is redirect, also OK
    except Exception as e:
        print(f"✗ FastMCP SSE endpoint {sse_url} - Error: {e}")
        return False

async def test_messages_endpoint(base_url: str, port: int, timeout: float = 10.0) -> bool:
    """Test if FastMCP messages endpoint accepts POST requests."""
    messages_url = f"{base_url}:{port}/messages"
    
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            # Send a minimal JSON-RPC ping to test the endpoint
            test_request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "ping"
            }
            response = await client.post(messages_url, json=test_request)
            print(f"✓ FastMCP Messages endpoint {messages_url} - Status: {response.status_code}")
            return response.status_code in [200, 400, 405]  # 400/405 means endpoint exists but wrong request
    except Exception as e:
        print(f"✗ FastMCP Messages endpoint {messages_url} - Error: {e}")
        return False

async def main():
    """Test both MCP server endpoints."""
    print("Testing FastMCP SSE Endpoints\n" + "="*40)
    
    base_url = "http://localhost"
    servers = [
        ("Wazuh Manager MCP", 8002),
        ("Wazuh Indexer MCP", 8001)
    ]
    
    all_passed = True
    
    for server_name, port in servers:
        print(f"\nTesting {server_name} (Port {port}):")
        
        sse_ok = await test_sse_endpoint(base_url, port)
        messages_ok = await test_messages_endpoint(base_url, port)
        
        server_ok = sse_ok and messages_ok
        all_passed &= server_ok
        
        status = "✓ PASS" if server_ok else "✗ FAIL"
        print(f"  {server_name}: {status}")
    
    print(f"\n{'='*40}")
    if all_passed:
        print("✓ All endpoints are accessible!")
        sys.exit(0)
    else:
        print("✗ Some endpoints failed. Check server status.")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main()) 