"""Configuration for Wazuh Indexer MCP Server"""
import os
from typing import Optional, Dict, Any
from dotenv import load_dotenv
from .base_config import BaseConfig

# Load environment variables
load_dotenv()

class WazuhIndexerConfig(BaseConfig):
    """Configuration for Wazuh Indexer MCP Server connections"""

    def __init__(self):
        super().__init__("WAZUH")

        # Indexer configuration
        self.indexer_host = self.get_env("INDEXER_HOST", "localhost")
        self.indexer_port = int(self.get_env("INDEXER_PORT", "9200"))
        self.indexer_user = self.get_env("INDEXER_USER", "admin")
        self.indexer_password = self.get_env("INDEXER_PASS", "admin")
        
        # Alternative naming for compatibility
        self.indexer_username = self.get_env("INDEXER_USERNAME", self.indexer_user)
        if self.get_env("INDEXER_PASSWORD"):
            self.indexer_password = self.get_env("INDEXER_PASSWORD")

        # SSL and connection settings
        self.verify_ssl = self.get_env("INDEXER_VERIFY_SSL", "false").lower() == "true"
        self.request_timeout = int(self.get_env("INDEXER_REQUEST_TIMEOUT", "30"))
        self.connection_timeout = int(self.get_env("INDEXER_CONNECTION_TIMEOUT", "10"))
        self.max_retries = int(self.get_env("INDEXER_MAX_RETRIES", "3"))
        self.retry_delay = int(self.get_env("INDEXER_RETRY_DELAY", "1"))

        # MCP Server settings
        self.server_port = int(self.get_env("INDEXER_PORT_MCP", "8001"))
        self.server_host = self.get_env("INDEXER_HOST_MCP", "0.0.0.0")
        self.log_level = self.get_env("INDEXER_LOG_LEVEL", "INFO")
        self.debug = self.get_env("INDEXER_DEBUG", "false").lower() == "true"

        # Index settings
        self.alerts_index_pattern = self.get_env("ALERTS_INDEX", "wazuh-alerts-*")
        self.alerts_limit = int(self.get_env("ALERTS_LIMIT", "20"))

        # SSL certificate paths
        self.ca_cert_path = self.get_env("INDEXER_CA_CERT_PATH", "")
        self.client_cert_path = self.get_env("INDEXER_CLIENT_CERT_PATH", "")
        self.client_key_path = self.get_env("INDEXER_CLIENT_KEY_PATH", "")

    @property
    def indexer_url(self) -> str:
        """Base URL for the Wazuh Indexer (Elasticsearch/OpenSearch)"""
        # Check for explicit URL configuration first
        explicit_url = self.get_env("INDEXER_URL")
        if explicit_url:
            return explicit_url
        
        # Default to HTTPS protocol regardless of verify_ssl setting
        # verify_ssl=false just disables certificate verification, not HTTPS itself
        protocol = "https"
        return f"{protocol}://{self.indexer_host}:{self.indexer_port}"

    @property
    def alerts_endpoint(self) -> str:
        """Endpoint for retrieving alerts from the indexer"""
        return f"/{self.alerts_index_pattern}/_search"

    def get_connection_params(self) -> Dict[str, Any]:
        """Return connection parameters as a dictionary."""
        return {
            "host": self.indexer_host,
            "port": self.indexer_port,
            "username": self.indexer_username,
            "password": self.indexer_password,
            "verify_ssl": self.verify_ssl,
            "timeout": self.request_timeout,
            "url": self.indexer_url,
            "ca_cert": self.ca_cert_path if self.ca_cert_path else None,
            "client_cert": self.client_cert_path if self.client_cert_path else None,
            "client_key": self.client_key_path if self.client_key_path else None,
        }

    def get_auth_header(self) -> Dict[str, str]:
        """Get basic auth header for requests"""
        import base64
        credentials = f"{self.indexer_username}:{self.indexer_password}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        return {"Authorization": f"Basic {encoded_credentials}"}

    def __str__(self) -> str:
        """String representation for debugging (hide sensitive data)"""
        return f"WazuhIndexerConfig(url={self.indexer_url}, user={self.indexer_username}, ssl={self.verify_ssl})" 