"""
Wazuh Manager Service for MCP Server

This service provides a direct client interface for interacting with the Wazuh Manager API
without relying on deprecated global services.
"""

import json
import requests
import logging
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urljoin
import urllib3
from datetime import datetime, timedelta, timezone

# Disable SSL warnings for development (remove in production)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logger = logging.getLogger(__name__)

class WazuhManagerMCPService:
    """
    Direct Wazuh Manager service for MCP Server
    
    Provides direct HTTP client for Wazuh Manager API operations without external dependencies.
    """

    def __init__(self, config):
        """
        Initialize the Wazuh Manager service
        
        Args:
            config: WazuhManagerConfig instance with connection parameters
        """
        self.config = config
        self.base_url = config.api_url
        self.username = config.api_user
        self.password = config.api_password
        self.verify_ssl = config.verify_ssl
        self.timeout = config.request_timeout
        
        # JWT token management
        self._jwt_token = None
        self._token_expires_at = None
        
        # Setup session for connection pooling
        self.session = requests.Session()
        self.session.verify = self.verify_ssl
        
        # Setup headers
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        
        logger.info(f"Initialized Wazuh Manager service for {self.base_url}")

    def _get_jwt_token(self) -> str:
        """
        Get or refresh JWT token for API authentication
        
        Returns:
            str: Valid JWT token
            
        Raises:
            requests.RequestException: If token request fails
        """
        # Check if we have a valid token
        if (self._jwt_token and self._token_expires_at and 
            datetime.now() < self._token_expires_at - timedelta(seconds=self.config.token_refresh_threshold)):
            return self._jwt_token
        
        # Request new token
        auth_url = urljoin(self.base_url, "/security/user/authenticate")
        
        try:
            # Use Basic Authentication as required by Wazuh API
            from requests.auth import HTTPBasicAuth
            response = requests.post(
                auth_url,
                auth=HTTPBasicAuth(self.username, self.password),
                verify=self.verify_ssl,
                timeout=self.timeout,
                params={"raw": "true"}
            )
            response.raise_for_status()
            
            # Extract token from response
            # Check if response is plain text (raw=true) or JSON
            response_text = response.text.strip()
            if response_text.startswith('ey'):  # JWT tokens start with 'ey'
                # Plain text token response (raw=true)
                self._jwt_token = response_text
                # Set expiration (Wazuh tokens typically last 15 minutes)
                self._token_expires_at = datetime.now() + timedelta(minutes=15)
                return self._jwt_token
            else:
                # Try JSON response format
                response_data = response.json()
                if 'data' in response_data and 'token' in response_data['data']:
                    self._jwt_token = response_data['data']['token']
                    # Set expiration (Wazuh tokens typically last 15 minutes)
                    self._token_expires_at = datetime.now() + timedelta(minutes=15)
                    return self._jwt_token
                else:
                    raise ValueError("Invalid token response format")
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Could not obtain JWT token: {e}")
            raise
        except (json.JSONDecodeError, ValueError, KeyError) as e:
            logger.error(f"Invalid token response: {e}")
            raise

    def _make_request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """
        Make authenticated HTTP request to Wazuh Manager API
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint
            **kwargs: Additional arguments for requests
            
        Returns:
            Dict containing the API response
            
        Raises:
            requests.RequestException: If request fails
        """
        url = urljoin(self.base_url, endpoint)
        
        try:
            # Get valid JWT token
            token = self._get_jwt_token()
            
            # Add authorization header
            headers = kwargs.get('headers', {})
            headers['Authorization'] = f'Bearer {token}'
            kwargs['headers'] = headers
            
            # Set default timeout if not provided
            if 'timeout' not in kwargs:
                kwargs['timeout'] = self.timeout
                
            # Make request
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            
            # Handle different content types
            content_type = response.headers.get('content-type', '')
            if 'application/json' in content_type:
                return response.json()
            else:
                return {'content': response.text, 'status_code': response.status_code}
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed for {method} {url}: {e}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON response from {url}: {e}")
            raise

    def check_connection(self) -> bool:
        """
        Test connection to Wazuh Manager API
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            # Try to get basic API info
            response = self._make_request('GET', '/')
            title = response.get('data', {}).get('title', '')
            # Check if title contains 'Wazuh API' (could be 'Wazuh API' or 'Wazuh API REST')
            return 'Wazuh API' in title
        except Exception as e:
            logger.error(f"Connection check failed: {e}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            return False

    def get_api_info(self) -> Dict[str, Any]:
        """Get API information"""
        return self._make_request('GET', '/')

    def get_agents(self, **params) -> Dict[str, Any]:
        """
        Get agents information
        
        Args:
            **params: Query parameters for filtering agents
            
        Returns:
            Dict containing agents data
        """
        return self._make_request('GET', '/agents', params=params)

    def get_agent_details(self, agent_id: str) -> Dict[str, Any]:
        """
        Get details of a specific agent
        
        Args:
            agent_id: ID of the agent
            
        Returns:
            Dict containing agent details
        """
        return self._make_request('GET', f'/agents/{agent_id}')

    def get_manager_info(self) -> Dict[str, Any]:
        """Get manager information"""
        return self._make_request('GET', '/manager/info')

    def get_manager_status(self) -> Dict[str, Any]:
        """Get manager status"""
        return self._make_request('GET', '/manager/status')

    def get_rules(self, **params) -> Dict[str, Any]:
        """
        Get rules information
        
        Args:
            **params: Query parameters for filtering rules
            
        Returns:
            Dict containing rules data
        """
        return self._make_request('GET', '/rules', params=params)

    def get_decoders(self, **params) -> Dict[str, Any]:
        """
        Get decoders information
        
        Args:
            **params: Query parameters for filtering decoders
            
        Returns:
            Dict containing decoders data
        """
        return self._make_request('GET', '/decoders', params=params)

    def get_security_config(self) -> Dict[str, Any]:
        """Get security configuration"""
        return self._make_request('GET', '/security/config')

    def close(self):
        """Close the session"""
        if hasattr(self, 'session'):
            self.session.close()

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close() 