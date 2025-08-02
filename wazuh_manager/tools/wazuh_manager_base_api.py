"""
Base class for Wazuh Manager API Tools.

This module provides a base class that eliminates code duplication
across all Wazuh Manager API tool modules.
"""

import logging
import datetime
import json
from typing import Dict, List, Optional, Union, Any
import requests
from requests.auth import HTTPBasicAuth

# Set up logging
logger = logging.getLogger(__name__)

class WazuhAPIBase:
    """
    Base class for Wazuh Manager API interactions.

    This class handles common functionality shared across all Wazuh API endpoints:
    - API connection and authentication
    - Common parameter processing
    - HTTP request handling
    - Error handling and logging
    - Response formatting
    """

    def __init__(self, base_url: str, username: str, password: str, verify_ssl: bool = True):
        """
        Initialize Wazuh API base connection.

        Args:
            base_url: Base URL of the Wazuh Manager API
            username: Username for authentication
            password: Password for authentication
            verify_ssl: Whether to verify SSL certificates
        """
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.session = requests.Session()

        # JWT token management
        self.jwt_token: Optional[str] = None
        self.jwt_expiration: Optional[datetime.datetime] = None

        logger.info(f"Initialized Wazuh API connection to {self.base_url}")

    def _is_jwt_valid(self) -> bool:
        """Check if the current JWT token is still valid"""
        if not self.jwt_token or not self.jwt_expiration:
            return False
        return (self.jwt_expiration - datetime.datetime.now(datetime.timezone.utc)).total_seconds() > 60

    def get_jwt(self) -> str:
        """Get a valid JWT token, either cached or new"""
        if self._is_jwt_valid():
            return self.jwt_token

        auth_url = f"{self.base_url}/security/user/authenticate?raw=true"
        try:
            logger.info("Requesting new JWT token from Wazuh API")
            response = requests.post(
                auth_url,
                auth=(self.username, self.password),
                verify=self.verify_ssl,
                timeout=60
            )

            response.raise_for_status()

            # Try to parse as JSON if not raw format
            try:
                data = response.json()
                token = None
                if isinstance(data, dict):
                    # Try direct token key first
                    token = data.get("token")
                    # Then try nested under 'data'
                    if not token and "data" in data:
                        token = data["data"].get("token")
                # If not found in JSON, try raw text
                if not token:
                    token = response.text
                if not token:
                    raise ValueError("JWT token not found in response")

                self.jwt_token = token
                self.jwt_expiration = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)
                logger.info("Obtained new JWT token valid until %s", self.jwt_expiration.isoformat())
                return self.jwt_token
            except json.JSONDecodeError:
                # Response might be raw token already
                token = response.text
                if token:
                    self.jwt_token = token
                    self.jwt_expiration = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)
                    logger.info("Obtained new JWT token (raw) valid until %s", self.jwt_expiration.isoformat())
                    return self.jwt_token
                else:
                    raise ValueError("JWT token not found in response")
        except Exception as e:
            logger.error(f"JWT auth failed: {str(e)}")
            raise

    def _build_common_params(self,
                           limit: Optional[int] = None,
                           offset: Optional[int] = None,
                           sort: Optional[str] = None,
                           search: Optional[str] = None,
                           select: Optional[str] = None,
                           q: Optional[str] = None,
                           pretty: Optional[bool] = None,
                           wait_for_complete: Optional[bool] = None,
                           **kwargs) -> Dict[str, Any]:
        """
        Build common parameters used across many Wazuh API endpoints.

        Args:
            limit: Maximum number of items to return
            offset: First item to return (pagination)
            sort: Sort criteria (+field for ascending, -field for descending)
            search: Search term to filter results
            select: Fields to return (comma-separated)
            q: WQL query string for advanced filtering
            pretty: Pretty print JSON response
            wait_for_complete: Wait for operation to complete
            **kwargs: Additional endpoint-specific parameters

        Returns:
            Dictionary of processed parameters
        """
        params = {}

        # Standard pagination parameters
        if limit is not None:
            params['limit'] = limit
        if offset is not None:
            params['offset'] = offset

        # Sorting and filtering
        if sort is not None:
            params['sort'] = sort
        if search is not None:
            params['search'] = search
        if select is not None:
            params['select'] = select
        if q is not None:
            params['q'] = q

        # Output formatting
        if pretty is not None:
            params['pretty'] = 'true' if pretty else 'false'
        if wait_for_complete is not None:
            params['wait_for_complete'] = 'true' if wait_for_complete else 'false'

        # Add any additional parameters
        params.update(kwargs)

        # Remove None values
        return {k: v for k, v in params.items() if v is not None}

    def _make_request(self,
                     method: str,
                     endpoint: str,
                     params: Optional[Dict[str, Any]] = None,
                     data: Optional[Dict[str, Any]] = None,
                     json_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Make HTTP request to Wazuh API endpoint with JWT authentication.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint path (without base URL)
            params: URL parameters
            data: Form data for request body
            json_data: JSON data for request body

        Returns:
            API response as dictionary

        Raises:
            requests.RequestException: On HTTP errors
            ValueError: On invalid response format
        """
        url = f"{self.base_url}/{endpoint.lstrip('/')}"

        try:
            # Get JWT token for authentication
            jwt_token = self.get_jwt()
            headers = {"Authorization": f"Bearer {jwt_token}"}

            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                data=data,
                json=json_data,
                verify=self.verify_ssl,
                timeout=30
            )

            # Handle JWT expiration
            if response.status_code == 401:
                logger.warning("JWT expired. Re-authenticating and retrying request.")
                self.jwt_token = None
                jwt_token = self.get_jwt()
                headers["Authorization"] = f"Bearer {jwt_token}"
                response = requests.request(
                    method=method,
                    url=url,
                    headers=headers,
                    params=params,
                    data=data,
                    json=json_data,
                    verify=self.verify_ssl,
                    timeout=30
                )

            response.raise_for_status()

            try:
                result = response.json()
                return result
            except ValueError as e:
                logger.error(f"Failed to parse JSON response: {e}")
                raise ValueError(f"Invalid JSON response from API: {e}")

        except requests.RequestException as e:
            logger.error(f"API request failed: {e}")
            raise

    def get(self, endpoint: str, **kwargs) -> Dict[str, Any]:
        """
        Make GET request to API endpoint.

        Args:
            endpoint: API endpoint path
            **kwargs: Parameters for request (will be processed through _build_common_params)

        Returns:
            API response dictionary
        """
        params = self._build_common_params(**kwargs)
        return self._make_request('GET', endpoint, params=params)

    def post(self, endpoint: str, data: Optional[Dict[str, Any]] = None, **kwargs) -> Dict[str, Any]:
        """
        Make POST request to API endpoint.

        Args:
            endpoint: API endpoint path
            data: JSON data to send in request body
            **kwargs: Parameters for request

        Returns:
            API response dictionary
        """
        params = self._build_common_params(**kwargs)
        return self._make_request('POST', endpoint, params=params, json_data=data)

    def put(self, endpoint: str, data: Optional[Dict[str, Any]] = None, **kwargs) -> Dict[str, Any]:
        """
        Make PUT request to API endpoint.

        Args:
            endpoint: API endpoint path
            data: JSON data to send in request body
            **kwargs: Parameters for request

        Returns:
            API response dictionary
        """
        params = self._build_common_params(**kwargs)
        return self._make_request('PUT', endpoint, params=params, json_data=data)

    def delete(self, endpoint: str, **kwargs) -> Dict[str, Any]:
        """
        Make DELETE request to API endpoint.

        Args:
            endpoint: API endpoint path
            **kwargs: Parameters for request

        Returns:
            API response dictionary
        """
        params = self._build_common_params(**kwargs)
        return self._make_request('DELETE', endpoint, params=params)

    def close(self):
        """Close the session and clean up resources."""
        if self.session:
            self.session.close()
            logger.info("Wazuh API session closed")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()