"""Configuration for Wazuh Manager MCP Server"""
import os
from typing import Optional, Dict, Any
from dotenv import load_dotenv
from .base_config import BaseConfig

# Load environment variables
load_dotenv()

class WazuhManagerConfig(BaseConfig):
    """Configuration for Wazuh Manager MCP Server connections"""

    def __init__(self):
        super().__init__("WAZUH")

        # API configuration
        self.api_host = self.get_env("API_HOST", "localhost")
        self.api_port = int(self.get_env("API_PORT", "55000"))
        self.api_user = self.get_env("API_USER", "wazuh")
        self.api_password = self.get_env("API_PASS", "wazuh")
        
        # Legacy naming for compatibility
        if self.get_env("MANAGER_URL"):
            # Extract host and port from URL if provided
            url = self.get_env("MANAGER_URL")
            if "://" in url:
                url = url.split("://")[1]  # Remove protocol
            if ":" in url:
                self.api_host, port_str = url.split(":")
                self.api_port = int(port_str)
            else:
                self.api_host = url
                
        if self.get_env("MANAGER_USERNAME"):
            self.api_user = self.get_env("MANAGER_USERNAME")
        if self.get_env("MANAGER_PASSWORD"):
            self.api_password = self.get_env("MANAGER_PASSWORD")

        # SSL and connection settings
        self.verify_ssl = self.get_env("VERIFY_SSL", "false").lower() == "true"
        if self.get_env("MANAGER_VERIFY_SSL"):
            self.verify_ssl = self.get_env("MANAGER_VERIFY_SSL", "false").lower() == "true"
            
        self.request_timeout = int(self.get_env("REQUEST_TIMEOUT", "30"))
        self.connection_timeout = int(self.get_env("CONNECTION_TIMEOUT", "10"))
        self.max_retries = int(self.get_env("MAX_RETRIES", "3"))
        self.retry_delay = int(self.get_env("RETRY_DELAY", "1"))

        # MCP Server settings
        self.server_port = int(self.get_env("MANAGER_PORT", "8002"))
        self.server_host = self.get_env("MANAGER_HOST", "0.0.0.0")
        self.log_level = self.get_env("LOG_LEVEL", "INFO")
        self.debug = self.get_env("DEBUG", "false").lower() == "true"

        # JWT token settings
        self.token_refresh_threshold = int(self.get_env("TOKEN_REFRESH_THRESHOLD", "300"))  # 5 minutes
        self.max_token_retries = int(self.get_env("MAX_TOKEN_RETRIES", "3"))

    @property
    def api_url(self) -> str:
        """Base URL for the Wazuh API"""
        return f"https://{self.api_host}:{self.api_port}"

    @property
    def base_url(self) -> str:
        """Base URL for the Wazuh API (alias for api_url)"""
        return self.api_url
    
    @property
    def username(self) -> str:
        """Username for Wazuh API (alias for api_user)"""
        return self.api_user
    
    @property
    def password(self) -> str:
        """Password for Wazuh API (alias for api_password)"""
        return self.api_password

    def get_connection_params(self) -> Dict[str, Any]:
        """Return connection parameters as a dictionary."""
        return {
            "host": self.api_host,
            "port": self.api_port,
            "username": self.api_user,
            "password": self.api_password,
            "verify_ssl": self.verify_ssl,
            "timeout": self.request_timeout,
            "url": self.api_url,
        }

    def get_auth_payload(self) -> Dict[str, str]:
        """Get authentication payload for JWT token request"""
        return {
            "user": self.api_user,
            "password": self.api_password
        }

    def __str__(self) -> str:
        """String representation for debugging (hide sensitive data)"""
        return f"WazuhManagerConfig(url={self.api_url}, user={self.api_user}, ssl={self.verify_ssl})" 