#!/usr/bin/env python3
"""
Startup script for Wazuh Indexer MCP Server

This script provides a convenient way to start the Wazuh Indexer MCP server
with custom configuration options.
"""
import os
import sys
import argparse
from pathlib import Path

from .server import WazuhIndexerMCPServer
from .config import WazuhIndexerConfig
from .utils.logger import logger
import logging
logger = logging.getLogger(__name__)



def load_env_file(env_file: Path):
    """Load environment variables from file"""
    if env_file.exists():
        logger.info(f"Loading environment from {env_file}")
        with open(env_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key.strip()] = value.strip()


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Start Wazuh Indexer MCP Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Environment Variables:
  WAZUH_INDEXER_URL          Wazuh Indexer URL (default: https://localhost:9200)
  WAZUH_INDEXER_USERNAME     Username for authentication (default: admin)
  WAZUH_INDEXER_PASSWORD     Password for authentication (default: admin)
  WAZUH_INDEXER_VERIFY_SSL   Verify SSL certificates (default: false)
  WAZUH_INDEXER_PORT         MCP server port (default: 8001)
  WAZUH_INDEXER_HOST         MCP server host (default: 0.0.0.0)
  WAZUH_INDEXER_LOG_LEVEL    Log level (default: INFO)
  WAZUH_INDEXER_DEBUG        Enable debug mode (default: false)

Examples:
  python run_server.py
  python run_server.py --port 8080 --host 127.0.0.1
  python run_server.py --env-file .env --debug
        """
    )
    
    parser.add_argument(
        '--port', 
        type=int, 
        default=None,
        help='Server port (overrides env variable)'
    )
    
    parser.add_argument(
        '--host', 
        type=str, 
        default=None,
        help='Server host (overrides env variable)'
    )
    
    parser.add_argument(
        '--log-level', 
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default=None,
        help='Log level (overrides env variable)'
    )
    
    parser.add_argument(
        '--debug', 
        action='store_true',
        help='Enable debug mode'
    )
    
    parser.add_argument(
        '--env-file', 
        type=Path,
        default=Path('.env'),
        help='Environment file to load (default: .env)'
    )
    
    parser.add_argument(
        '--indexer-url',
        type=str,
        default=None,
        help='Wazuh Indexer URL (overrides env variable)'
    )
    
    parser.add_argument(
        '--indexer-username',
        type=str,
        default=None,
        help='Wazuh Indexer username (overrides env variable)'
    )
    
    parser.add_argument(
        '--indexer-password',
        type=str,
        default=None,
        help='Wazuh Indexer password (overrides env variable)'
    )
    
    parser.add_argument(
        '--verify-ssl',
        action='store_true',
        help='Verify SSL certificates'
    )
    
    parser.add_argument(
        '--no-verify-ssl',
        action='store_true',
        help='Do not verify SSL certificates'
    )
    
    parser.add_argument(
        '--status',
        action='store_true',
        help='Show server status and exit'
    )
    
    args = parser.parse_args()
    
    try:
        # Load environment file if specified
        if args.env_file:
            load_env_file(args.env_file)
        
        # Override environment variables with command line arguments
        if args.port:
            os.environ['WAZUH_INDEXER_PORT'] = str(args.port)
        if args.host:
            os.environ['WAZUH_INDEXER_HOST'] = args.host
        if args.log_level:
            os.environ['WAZUH_INDEXER_LOG_LEVEL'] = args.log_level
        if args.debug:
            os.environ['WAZUH_INDEXER_DEBUG'] = 'true'
        if args.indexer_url:
            os.environ['WAZUH_INDEXER_URL'] = args.indexer_url
        if args.indexer_username:
            os.environ['WAZUH_INDEXER_USERNAME'] = args.indexer_username
        if args.indexer_password:
            os.environ['WAZUH_INDEXER_PASSWORD'] = args.indexer_password
        if args.verify_ssl:
            os.environ['WAZUH_INDEXER_VERIFY_SSL'] = 'true'
        if args.no_verify_ssl:
            os.environ['WAZUH_INDEXER_VERIFY_SSL'] = 'false'
        
        # Create server configuration
        config = WazuhIndexerConfig()
        
        # Show status if requested
        if args.status:
            print("Wazuh Indexer MCP Server Configuration:")
            print("=" * 50)
            config_dict = config.to_dict()
            for key, value in config_dict.items():
                if 'password' in key.lower():
                    value = '***' if value else None
                print(f"{key}: {value}")
            return
        
        # Create and run server
        logger.info("Starting Wazuh Indexer MCP Server...")
        logger.info(f"Configuration: {config.config.server_name} v{config.server_version}")
        logger.info(f"Listening on {config.host}:{config.port}")
        logger.info(f"Indexer URL: {config.custom_config.get('wazuh_indexer_url')}")
        logger.info(f"SSL Verification: {config.custom_config.get('verify_ssl')}")
        
        server = WazuhIndexerMCPServer(config)
        server.run()
        
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server startup failed: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main() 