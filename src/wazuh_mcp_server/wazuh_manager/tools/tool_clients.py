"""
Centralized Client Provider for Wazuh Manager Tools

This module ensures that all tools within the Wazuh Manager MCP server
share a single, properly configured API client instance.
"""
import logging
from ..config.manager_config import WazuhManagerConfig
from .wazuh_manager_base_api import WazuhAPIBase

_client_instance = None
logger = logging.getLogger(__name__)

def get_manager_client() -> WazuhAPIBase:
    """
    Returns a singleton instance of the WazuhAPIBase client.
    Initializes the client on the first call.
    """
    global _client_instance
    
    if _client_instance is None:
        try:
            logger.info("Initializing centralized Wazuh Manager API client for tools...")
            config = WazuhManagerConfig()
            
            _client_instance = WazuhAPIBase(
                base_url=config.api_url,
                username=config.username,
                password=config.password,
                verify_ssl=config.verify_ssl
            )
            logger.info("Centralized Wazuh Manager API client initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to initialize Wazuh Manager API client: {e}", exc_info=True)
            # Return a dummy client or raise an error to prevent tools from failing silently
            raise RuntimeError("Could not create the API client for tools.") from e
            
    return _client_instance 