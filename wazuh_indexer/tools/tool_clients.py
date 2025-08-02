"""
Centralized client management for Wazuh Indexer tools.
"""

# Global instance will be set by the server
_indexer_client_instance = None

def get_indexer_client():
    """
    Returns the indexer client instance set by the server.
    """
    global _indexer_client_instance
    if _indexer_client_instance is None:
        raise RuntimeError("Indexer client not initialized by server")
    return _indexer_client_instance 