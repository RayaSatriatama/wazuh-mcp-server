# tools/wazuh_tools/wazuh_indexer_api_tools/__init__.py

"""
Wazuh Indexer API Tools Aggregator

This module discovers and aggregates all available tools for the Wazuh Indexer API.
"""
import inspect
import logging

# Attempt to import the Tool class from fastmcp
try:
    from fastmcp.tools.tool import Tool
    _fastmcp_available = True
except ImportError:
    Tool = type(None)  # Define a dummy class if fastmcp is not available
    _fastmcp_available = False
    logging.getLogger(__name__).warning(
        "fastmcp.tools.tool.Tool could not be imported. "
        "Tool discovery will not work correctly."
    )

# Import all submodules from which to collect tools
from . import cluster_tools, index_tools, monitoring_tools, search_tools, security_tools

# A list of all modules to scan for tool functions
_modules_to_scan = [
    cluster_tools,
    index_tools,
    monitoring_tools,
    search_tools,
    security_tools
]

# This list will hold the actual function objects for the tool registry
wazuh_indexer_tools_list = []

# __all__ will contain the names (strings) of all public functions for `import *`
__all__ = []

for module in _modules_to_scan:
    # Iterate over all members of the module that are functions
    for member_name, member_obj in inspect.getmembers(module, inspect.isfunction):
        # Ensure the function is defined in the module, is public, and has a docstring.
        # This filters out helper functions that shouldn't be exposed as tools.
        if (member_obj.__module__ == module.__name__ and 
            not member_name.startswith('_') and 
            inspect.getdoc(member_obj)):

            # Add the function name to __all__ if not already present
            if member_name not in __all__:
                __all__.append(member_name)

            # Add the function object to our list of tools if not already present
            if member_obj not in wazuh_indexer_tools_list:
                wazuh_indexer_tools_list.append(member_obj)
            
            # Make the function available for `from . import function_name` and `import *`
            globals()[member_name] = member_obj

# For debugging purposes
# import logging
# logging.getLogger(__name__).info(
#     f"Loaded {len(wazuh_indexer_tools_list)} tools from wazuh_indexer_api_tools"
# ) 