"""
Test script to verify proper tool registration
"""
import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from fastmcp import FastMCP

def test_tool_registration():
    """Test if tools are properly registered using the correct method"""
    
    # Create a test MCP server
    mcp = FastMCP("Test Server")
    
    # Test the different registration methods
    print("Testing tool registration methods...")
    
    # Method 1: Direct decorator (should work)
    @mcp.tool
    def test_function_1(x: int) -> int:
        """Test function 1"""
        return x * 2
    
    # Method 2: Using mcp.tool() as function (recommended approach)
    def test_function_2(x: int) -> int:
        """Test function 2"""
        return x * 3
    
    mcp.tool(test_function_2)
    
    # Check how many tools are registered
    if hasattr(mcp, '_tool_manager') and hasattr(mcp._tool_manager, '_tools'):
        tools_count = len(mcp._tool_manager._tools)
        print(f"Total tools registered: {tools_count}")
        
        # List tool names
        tool_names = list(mcp._tool_manager._tools.keys())
        print(f"Tool names: {tool_names}")
        
        # Check if tools have proper structure
        for name, tool in mcp._tool_manager._tools.items():
            print(f"Tool '{name}': {type(tool)} - has fn: {hasattr(tool, 'fn')}")
            if hasattr(tool, 'fn'):
                print(f"  Function: {tool.fn}")
                print(f"  Description: {getattr(tool, 'description', 'No description')}")
    
    return mcp

if __name__ == "__main__":
    test_mcp = test_tool_registration()
    print("\nRegistration test completed!") 