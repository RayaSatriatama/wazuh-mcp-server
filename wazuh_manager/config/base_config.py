"""Base configuration module for Wazuh Manager MCP Server."""
import os
from typing import Dict, Any, Optional


class BaseConfig:
    """Base class for MCP server configurations."""

    def __init__(self, config_prefix: str):
        """Initialize with environment prefix.

        Args:
            config_prefix: Prefix for environment variables
        """
        self.config_prefix = config_prefix

    def get_env(self, key: str, default: Optional[Any] = None) -> Any:
        """Get environment variable with prefix.

        Args:
            key: Environment variable key (without prefix)
            default: Default value if environment variable is not set

        Returns:
            Environment variable value or default
        """
        return os.environ.get(f"{self.config_prefix}_{key}", default)

    def get_connection_params(self) -> Dict[str, Any]:
        """Return connection parameters as a dictionary.

        Returns:
            Dictionary of connection parameters
        """
        raise NotImplementedError("Subclasses must implement get_connection_params()") 