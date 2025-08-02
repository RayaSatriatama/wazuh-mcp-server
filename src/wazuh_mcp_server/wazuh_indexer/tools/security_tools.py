"""
Wazuh Indexer Security Tools - MCP Tools for Security and User Management

This module provides MCP tools for security configuration, user management,
role management, and authentication operations in Wazuh Indexer.

Following best practices:
- Clean code and PEP 8 compliance
- Comprehensive parameter validation
- GET-only operations for safety
- Detailed error handling
- Type hints and documentation
"""

from typing import Any, Dict, List, Optional
from datetime import datetime

from fastmcp import FastMCP

from .tool_clients import get_indexer_client
import logging

# Create MCP server instance
mcp = FastMCP("wazuh_indexer_security_mcp")

# Initialize logger
logger = logging.getLogger(__name__)

# Initialize Wazuh configuration

# Get singleton client instance
# Client will be obtained in tool functions
@mcp.tool()
def get_security_config(
    config_type: str = "config",
    human: bool = True
) -> Dict[str, Any]:
    """
    Get security configuration from Wazuh Indexer.

    This tool retrieves the current security configuration including
    authentication backends, authorization settings, and security policies.

    Args:
        config_type: Type of config to retrieve (config, roles, rolesmapping,
                    internalusers, actiongroups, tenants)
        human: Return human readable format

    Returns:
        Dictionary containing security configuration
    """
    try:
        params = {}
        if human:
            params["human"] = "true"

        endpoint = f"/_plugins/_security/api/securityconfig/{config_type}"
        response = get_indexer_client()._make_request("GET", endpoint, params=params)

        # Add metadata and analysis
        response["timestamp"] = datetime.utcnow().isoformat()
        response["config_type"] = config_type

        # Analyze security configuration
        if config_type == "config" and "config" in response:
            config_data = response["config"]
            dynamic_config = config_data.get("dynamic", {})

            # Analyze authentication backends
            authc_analysis = {}
            if "authc" in dynamic_config:
                authc = dynamic_config["authc"]
                authc_analysis = {
                    "total_auth_domains": len(authc),
                    "enabled_domains": len([d for d in authc.values() if d.get("http_enabled", False)]),
                    "auth_types": list(set([
                        d.get("http_authenticator", {}).get("type", "unknown")
                        for d in authc.values()
                    ])),
                    "has_ldap": any("ldap" in d.get("authentication_backend", {}).get("type", "")
                                  for d in authc.values()),
                    "has_internal": any("intern" in d.get("authentication_backend", {}).get("type", "")
                                      for d in authc.values()),
                    "has_jwt": any("jwt" in d.get("http_authenticator", {}).get("type", "")
                                 for d in authc.values())
                }

            # Analyze authorization backends
            authz_analysis = {}
            if "authz" in dynamic_config:
                authz = dynamic_config["authz"]
                authz_analysis = {
                    "total_authz_domains": len(authz),
                    "enabled_authz_domains": len([d for d in authz.values() if d.get("http_enabled", False)])
                }

            response["security_analysis"] = {
                "authentication": authc_analysis,
                "authorization": authz_analysis,
                "multitenancy_enabled": dynamic_config.get("kibana", {}).get("multitenancy_enabled", False),
                "anonymous_auth_enabled": dynamic_config.get("http", {}).get("anonymous_auth_enabled", False)
            }

        logger.debug(f"Retrieved security config: {config_type}")
        return response

    except Exception as e:
        logger.error(f"Error getting security config {config_type}: {str(e)}")
        return {"error": str(e), "config_type": config_type}

@mcp.tool()
def get_users_info(
    username: Optional[str] = None,
    human: bool = True
) -> Dict[str, Any]:
    """
    Get user information from Wazuh Indexer.

    This tool retrieves information about internal users including
    roles, attributes, and account status.

    Args:
        username: Specific username to retrieve (optional, gets all if not specified)
        human: Return human readable format

    Returns:
        Dictionary containing user information
    """
    try:
        params = {}
        if human:
            params["human"] = "true"

        endpoint = "/_plugins/_security/api/internalusers"
        if username:
            endpoint = f"/_plugins/_security/api/internalusers/{username}"

        response = get_indexer_client()._make_request("GET", endpoint, params=params)

        # Add metadata and user analysis
        response["timestamp"] = datetime.utcnow().isoformat()
        response["requested_user"] = username

        # Analyze users
        user_summary = {
            "total_users": 0,
            "users_with_roles": 0,
            "admin_users": 0,
            "readonly_users": 0,
            "user_list": []
        }

        if isinstance(response, dict):
            for user_name, user_data in response.items():
                if user_name not in ["timestamp", "requested_user", "user_summary"]:
                    user_summary["total_users"] += 1

                    # Analyze user roles
                    backend_roles = user_data.get("backend_roles", [])
                    opendistro_roles = user_data.get("opendistro_security_roles", [])
                    all_roles = backend_roles + opendistro_roles

                    if all_roles:
                        user_summary["users_with_roles"] += 1

                    # Check for admin privileges
                    is_admin = any("admin" in str(role).lower() for role in all_roles)
                    is_readonly = any("read" in str(role).lower() and "only" in str(role).lower()
                                    for role in all_roles)

                    if is_admin:
                        user_summary["admin_users"] += 1
                    elif is_readonly:
                        user_summary["readonly_users"] += 1

                    user_info = {
                        "username": user_name,
                        "backend_roles": backend_roles,
                        "security_roles": opendistro_roles,
                        "attributes": user_data.get("attributes", {}),
                        "is_admin": is_admin,
                        "is_readonly": is_readonly,
                        "is_reserved": user_data.get("reserved", False)
                    }
                    user_summary["user_list"].append(user_info)

        response["user_summary"] = user_summary

        logger.debug(f"Retrieved information for {user_summary['total_users']} users")
        return response

    except Exception as e:
        logger.error(f"Error getting users info: {str(e)}")
        return {"error": str(e), "username": username}

@mcp.tool()
def get_roles_info(
    role_name: Optional[str] = None,
    human: bool = True
) -> Dict[str, Any]:
    """
    Get role information from Wazuh Indexer.

    This tool retrieves information about security roles including
    permissions, index patterns, and action groups.

    Args:
        role_name: Specific role name to retrieve (optional, gets all if not specified)
        human: Return human readable format

    Returns:
        Dictionary containing role information
    """
    try:
        params = {}
        if human:
            params["human"] = "true"

        endpoint = "/_plugins/_security/api/roles"
        if role_name:
            endpoint = f"/_plugins/_security/api/roles/{role_name}"

        response = get_indexer_client()._make_request("GET", endpoint, params=params)

        # Add metadata and role analysis
        response["timestamp"] = datetime.utcnow().isoformat()
        response["requested_role"] = role_name

        # Analyze roles
        role_summary = {
            "total_roles": 0,
            "roles_with_cluster_permissions": 0,
            "roles_with_index_permissions": 0,
            "admin_roles": 0,
            "readonly_roles": 0,
            "role_list": []
        }

        if isinstance(response, dict):
            for role_name_key, role_data in response.items():
                if role_name_key not in ["timestamp", "requested_role", "role_summary"]:
                    role_summary["total_roles"] += 1

                    # Analyze permissions
                    cluster_permissions = role_data.get("cluster_permissions", [])
                    index_permissions = role_data.get("index_permissions", [])

                    if cluster_permissions:
                        role_summary["roles_with_cluster_permissions"] += 1
                    if index_permissions:
                        role_summary["roles_with_index_permissions"] += 1

                    # Check role type
                    is_admin = any("admin" in str(perm).lower() for perm in cluster_permissions)
                    is_readonly = any("read" in str(perm).lower() for perm in cluster_permissions)

                    if is_admin:
                        role_summary["admin_roles"] += 1
                    elif is_readonly:
                        role_summary["readonly_roles"] += 1

                    # Analyze index patterns
                    index_patterns = []
                    for idx_perm in index_permissions:
                        patterns = idx_perm.get("index_patterns", [])
                        index_patterns.extend(patterns)

                    role_info = {
                        "role_name": role_name_key,
                        "cluster_permissions": cluster_permissions,
                        "index_permissions_count": len(index_permissions),
                        "index_patterns": list(set(index_patterns)),
                        "is_admin": is_admin,
                        "is_readonly": is_readonly,
                        "is_reserved": role_data.get("reserved", False),
                        "tenant_permissions": role_data.get("tenant_permissions", {})
                    }
                    role_summary["role_list"].append(role_info)

        response["role_summary"] = role_summary

        logger.debug(f"Retrieved information for {role_summary['total_roles']} roles")
        return response

    except Exception as e:
        logger.error(f"Error getting roles info: {str(e)}")
        return {"error": str(e), "role_name": role_name}

@mcp.tool()
def get_permissions_info(
    human: bool = True
) -> Dict[str, Any]:
    """
    Get permissions and action groups information.

    This tool retrieves information about available action groups,
    permissions, and their mappings in the security system.

    Args:
        human: Return human readable format

    Returns:
        Dictionary containing permissions information
    """
    try:
        params = {}
        if human:
            params["human"] = "true"

        endpoint = "/_plugins/_security/api/actiongroups"
        response = get_indexer_client()._make_request("GET", endpoint, params=params)

        # Add metadata and permissions analysis
        response["timestamp"] = datetime.utcnow().isoformat()

        # Analyze action groups
        permissions_summary = {
            "total_action_groups": 0,
            "cluster_action_groups": 0,
            "index_action_groups": 0,
            "read_action_groups": 0,
            "write_action_groups": 0,
            "admin_action_groups": 0,
            "action_group_list": []
        }

        if isinstance(response, dict):
            for group_name, group_data in response.items():
                if group_name not in ["timestamp", "permissions_summary"]:
                    permissions_summary["total_action_groups"] += 1

                    # Analyze action group type
                    allowed_actions = group_data.get("allowed_actions", [])
                    group_type = group_data.get("type", "unknown")

                    # Categorize by scope
                    has_cluster_actions = any("cluster:" in str(action) for action in allowed_actions)
                    has_index_actions = any("indices:" in str(action) for action in allowed_actions)

                    if has_cluster_actions:
                        permissions_summary["cluster_action_groups"] += 1
                    if has_index_actions:
                        permissions_summary["index_action_groups"] += 1

                    # Categorize by permission type
                    has_read = any("read" in str(action).lower() for action in allowed_actions)
                    has_write = any("write" in str(action).lower() or "create" in str(action).lower()
                                  for action in allowed_actions)
                    has_admin = any("admin" in str(action).lower() or "all" in str(action).lower()
                                  for action in allowed_actions)

                    if has_read:
                        permissions_summary["read_action_groups"] += 1
                    if has_write:
                        permissions_summary["write_action_groups"] += 1
                    if has_admin:
                        permissions_summary["admin_action_groups"] += 1

                    group_info = {
                        "name": group_name,
                        "type": group_type,
                        "allowed_actions_count": len(allowed_actions),
                        "has_cluster_actions": has_cluster_actions,
                        "has_index_actions": has_index_actions,
                        "has_read_permissions": has_read,
                        "has_write_permissions": has_write,
                        "has_admin_permissions": has_admin,
                        "is_reserved": group_data.get("reserved", False),
                        "description": group_data.get("description", "")
                    }
                    permissions_summary["action_group_list"].append(group_info)

        response["permissions_summary"] = permissions_summary

        logger.debug(f"Retrieved {permissions_summary['total_action_groups']} action groups")
        return response

    except Exception as e:
        logger.error(f"Error getting permissions info: {str(e)}")
        return {"error": str(e)}

@mcp.tool()
def get_security_audit_log(
    category: Optional[str] = None,
    origin: Optional[str] = None,
    compliance_config: bool = False,
    human: bool = True
) -> Dict[str, Any]:
    """
    Get security audit log configuration.

    This tool retrieves security audit log settings and configuration
    for monitoring authentication and authorization events.

    Args:
        category: Audit category to filter
        origin: Audit origin to filter
        compliance_config: Include compliance configuration
        human: Return human readable format

    Returns:
        Dictionary containing audit log configuration
    """
    try:
        params = {}
        if human:
            params["human"] = "true"
        if category:
            params["category"] = category
        if origin:
            params["origin"] = origin
        if compliance_config:
            params["compliance_config"] = "true"

        endpoint = "/_plugins/_security/api/audit"
        response = get_indexer_client()._make_request("GET", endpoint, params=params)

        # Add metadata and audit analysis
        response["timestamp"] = datetime.utcnow().isoformat()
        response["requested_category"] = category
        response["requested_origin"] = origin

        # Analyze audit configuration
        if "config" in response:
            config = response["config"]
            audit_analysis = {
                "audit_enabled": config.get("enabled", False),
                "audit_type": config.get("audit", {}).get("type", "unknown"),
                "exclude_sensitive_headers": config.get("audit", {}).get("exclude_sensitive_headers", False),
                "resolve_bulk_requests": config.get("audit", {}).get("resolve_bulk_requests", False),
                "log_request_body": config.get("audit", {}).get("log_request_body", False),
                "resolve_indices": config.get("audit", {}).get("resolve_indices", False),
                "enable_transport": config.get("audit", {}).get("enable_transport", False),
                "enable_rest": config.get("audit", {}).get("enable_rest", False)
            }

            # Analyze compliance settings if available
            compliance = config.get("compliance", {})
            if compliance:
                audit_analysis["compliance"] = {
                    "enabled": compliance.get("enabled", False),
                    "write_log_diffs": compliance.get("write_log_diffs", False),
                    "read_metadata_only": compliance.get("read_metadata_only", False),
                    "write_metadata_only": compliance.get("write_metadata_only", False),
                    "external_config": compliance.get("external_config", False),
                    "internal_config": compliance.get("internal_config", False)
                }

            response["audit_analysis"] = audit_analysis

        logger.debug(f"Retrieved security audit configuration")
        return response

    except Exception as e:
        logger.error(f"Error getting audit log config: {str(e)}")
        return {"error": str(e), "category": category}

@mcp.tool()
def get_authentication_info(
    domain: Optional[str] = None,
    human: bool = True
) -> Dict[str, Any]:
    """
    Get authentication backend information.

    This tool retrieves information about configured authentication
    backends and their current status.

    Args:
        domain: Specific authentication domain to retrieve
        human: Return human readable format

    Returns:
        Dictionary containing authentication information
    """
    try:
        # First get the security config to analyze auth backends
        security_config = get_security_config("config", human)

        if "error" in security_config:
            return security_config

        # Extract authentication information
        auth_info = {
            "timestamp": datetime.utcnow().isoformat(),
            "requested_domain": domain,
            "authentication_backends": {}
        }

        if "config" in security_config and "dynamic" in security_config["config"]:
            dynamic_config = security_config["config"]["dynamic"]
            authc = dynamic_config.get("authc", {})

            # Analyze each authentication domain
            for domain_name, domain_config in authc.items():
                if domain and domain != domain_name:
                    continue

                auth_backend = domain_config.get("authentication_backend", {})
                http_auth = domain_config.get("http_authenticator", {})

                backend_info = {
                    "domain_name": domain_name,
                    "enabled": domain_config.get("http_enabled", False),
                    "order": domain_config.get("order", 0),
                    "description": domain_config.get("description", ""),
                    "authentication_backend": {
                        "type": auth_backend.get("type", "unknown"),
                        "config": auth_backend.get("config", {})
                    },
                    "http_authenticator": {
                        "type": http_auth.get("type", "unknown"),
                        "challenge": http_auth.get("challenge", False),
                        "config": http_auth.get("config", {})
                    }
                }

                # Add specific analysis for different backend types
                if auth_backend.get("type") == "ldap":
                    ldap_config = auth_backend.get("config", {})
                    backend_info["ldap_analysis"] = {
                        "ssl_enabled": ldap_config.get("enable_ssl", False),
                        "start_tls": ldap_config.get("enable_start_tls", False),
                        "hosts": ldap_config.get("hosts", []),
                        "userbase": ldap_config.get("userbase", ""),
                        "verify_hostnames": ldap_config.get("verify_hostnames", False)
                    }

                elif auth_backend.get("type") == "jwt":
                    jwt_config = http_auth.get("config", {})
                    backend_info["jwt_analysis"] = {
                        "jwt_header": jwt_config.get("jwt_header", "Authorization"),
                        "roles_key": jwt_config.get("roles_key", ""),
                        "subject_key": jwt_config.get("subject_key", ""),
                        "clock_skew_tolerance": jwt_config.get("jwt_clock_skew_tolerance_seconds", 0)
                    }

                auth_info["authentication_backends"][domain_name] = backend_info

        # Add summary
        backends = auth_info["authentication_backends"]
        auth_info["summary"] = {
            "total_domains": len(backends),
            "enabled_domains": len([b for b in backends.values() if b["enabled"]]),
            "backend_types": list(set([b["authentication_backend"]["type"] for b in backends.values()])),
            "authenticator_types": list(set([b["http_authenticator"]["type"] for b in backends.values()])),
            "has_ldap": any(b["authentication_backend"]["type"] == "ldap" for b in backends.values()),
            "has_internal": any(b["authentication_backend"]["type"] == "intern" for b in backends.values()),
            "has_jwt": any(b["http_authenticator"]["type"] == "jwt" for b in backends.values())
        }

        logger.debug(f"Retrieved authentication info for {len(backends)} domains")
        return auth_info

    except Exception as e:
        logger.error(f"Error getting authentication info: {str(e)}")
        return {"error": str(e), "domain": domain}