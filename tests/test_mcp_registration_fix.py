"""
Test script to verify that tool registration fix works correctly
"""
import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_registration_method():
    """Test the proper tool registration method"""
    from fastmcp import FastMCP
    
    # Create test server
    test_mcp = FastMCP("Registration Test Server")
    
    # Test function to register
    def sample_function(x: int, y: int) -> int:
        """Sample function for testing"""
        return x + y
    
    # Method 1: Using decorator (should work)
    @test_mcp.tool
    def decorated_function(a: int, b: int) -> int:
        """Decorated function"""
        return a * b
    
    # Method 2: Using mcp.tool() as function call (recommended for importing)
    test_mcp.tool(sample_function)
    
    # Check registration results
    if hasattr(test_mcp, '_tool_manager') and hasattr(test_mcp._tool_manager, '_tools'):
        tools_count = len(test_mcp._tool_manager._tools)
        tool_names = list(test_mcp._tool_manager._tools.keys())
        
        print(f"✅ Successfully registered {tools_count} tools")
        print(f"   Tool names: {tool_names}")
        
        # Verify tool structure
        for name, tool in test_mcp._tool_manager._tools.items():
            has_fn = hasattr(tool, 'fn')
            print(f"   - {name}: has_fn={has_fn}, type={type(tool)}")
    else:
        print("❌ No tools registered or tool manager not found")
    
    return test_mcp

def test_wazuh_tools_import():
    """Test if Wazuh tools can be imported successfully"""
    try:
        print("\n🔍 Testing Wazuh tools import...")
        from tools.wazuh_tools.wazuh_manager_api_tools.agents import mcp as agents_mcp
        
        if hasattr(agents_mcp, '_tool_manager'):
            tools_count = len(agents_mcp._tool_manager._tools)
            print(f"✅ Agents module has {tools_count} tools")
            
            # Show first few tool names
            tool_names = list(agents_mcp._tool_manager._tools.keys())[:3]
            print(f"   Sample tools: {tool_names}")
        else:
            print("❌ Agents module has no tool manager")
            
    except ImportError as e:
        print(f"❌ Failed to import Wazuh tools: {e}")

if __name__ == "__main__":
    print("🧪 Testing MCP Tool Registration Fix")
    print("=" * 50)
    
    # Test basic registration
    test_mcp = test_registration_method()
    
    # Test Wazuh tools import
    test_wazuh_tools_import()
    
    print("\n✅ Registration test completed!") 