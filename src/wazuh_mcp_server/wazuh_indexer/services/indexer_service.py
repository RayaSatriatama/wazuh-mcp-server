"""
Wazuh Indexer Service for MCP Server

This service provides a direct client interface for interacting with the Wazuh Indexer
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

class WazuhIndexerMCPService:
    """
    Direct Wazuh Indexer service for MCP Server
    
    Provides direct HTTP client for Wazuh Indexer operations without external dependencies.
    """

    def __init__(self, config):
        """
        Initialize the Wazuh Indexer service
        
        Args:
            config: WazuhIndexerConfig instance with connection parameters
        """
        self.config = config
        self.base_url = config.indexer_url
        self.username = config.indexer_username
        self.password = config.indexer_password
        self.verify_ssl = config.verify_ssl
        self.timeout = config.request_timeout
        
        # Setup session for connection pooling
        self.session = requests.Session()
        self.session.auth = (self.username, self.password)
        self.session.verify = self.verify_ssl
        
        # Setup headers
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        
        logger.info(f"Initialized Wazuh Indexer service for {self.base_url}")

    def _make_request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """
        Make HTTP request to Wazuh Indexer
        
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
            # Set default timeout if not provided
            if 'timeout' not in kwargs:
                kwargs['timeout'] = self.timeout
                
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
        Test connection to Wazuh Indexer
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            health = self.get_cluster_health()
            return health.get('status') in ['green', 'yellow']
        except Exception as e:
            logger.error(f"Connection check failed: {e}")
            return False

    def get_cluster_health(self) -> Dict[str, Any]:
        """Get cluster health information"""
        return self._make_request('GET', '_cluster/health')

    def get_cluster_stats(self) -> Dict[str, Any]:
        """Get cluster statistics"""
        return self._make_request('GET', '_cluster/stats')

    def get_nodes_info(self) -> Dict[str, Any]:
        """Get nodes information"""
        return self._make_request('GET', '_nodes')

    def get_nodes_stats(self) -> Dict[str, Any]:
        """Get nodes statistics"""
        return self._make_request('GET', '_nodes/stats')

    def list_indices(self, index_pattern: str = None) -> Dict[str, Any]:
        """
        List indices
        
        Args:
            index_pattern: Optional pattern to filter indices
            
        Returns:
            Dict containing indices information
        """
        endpoint = '_cat/indices'
        if index_pattern:
            endpoint += f'/{index_pattern}'
        endpoint += '?format=json'
        
        return self._make_request('GET', endpoint)

    def get_index_info(self, index_name: str) -> Dict[str, Any]:
        """
        Get information about a specific index
        
        Args:
            index_name: Name of the index
            
        Returns:
            Dict containing index information
        """
        return self._make_request('GET', f'{index_name}')

    def get_index_stats(self, index_name: str = None) -> Dict[str, Any]:
        """
        Get index statistics
        
        Args:
            index_name: Optional specific index name
            
        Returns:
            Dict containing index statistics
        """
        endpoint = '_stats'
        if index_name:
            endpoint = f'{index_name}/_stats'
            
        return self._make_request('GET', endpoint)

    def search(self, index: str, query: Dict[str, Any], size: int = 10, 
               from_: int = 0, sort: List[Dict] = None) -> Dict[str, Any]:
        """
        Perform search operation
        
        Args:
            index: Index name or pattern
            query: Elasticsearch query DSL
            size: Number of results to return
            from_: Starting offset
            sort: Sort configuration
            
        Returns:
            Dict containing search results
        """
        search_body = {
            'query': query,
            'size': size,
            'from': from_
        }
        
        if sort:
            search_body['sort'] = sort
            
        return self._make_request('POST', f'{index}/_search', json=search_body)

    def get_alerts(self, limit: int = None, time_range: str = "24h", 
                   filters: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Get recent alerts from Wazuh indices
        
        Args:
            limit: Maximum number of alerts to return
            time_range: Time range for alerts (e.g., "24h", "7d")
            filters: Additional filters to apply
            
        Returns:
            Dict containing alert data
        """
        if limit is None:
            limit = self.config.alerts_limit

        # Build time filter
        time_filter = {
            "range": {
                "@timestamp": {
                    "gte": f"now-{time_range}"
                }
            }
        }

        # Build query
        query = {
            "bool": {
                "must": [time_filter]
            }
        }

        # Add additional filters
        if filters:
            for key, value in filters.items():
                query["bool"]["must"].append({
                    "term": {key: value}
                })

        # Sort by timestamp (newest first)
        sort = [{"@timestamp": {"order": "desc"}}]

        return self.search(
            index=self.config.alerts_index_pattern,
            query=query,
            size=limit,
            sort=sort
        )

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