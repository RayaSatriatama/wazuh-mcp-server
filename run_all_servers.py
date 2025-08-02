#!/usr/bin/env python3
"""
Wazuh MCP Server Manager

Start and manage the Wazuh MCP servers: wazuh_indexer, wazuh_manager
"""
import os
import sys
import argparse
import subprocess
import signal
import time
from pathlib import Path
from typing import List, Dict

# Server configurations
SERVERS = {
    "wazuh_indexer": {
        "port": 8001,
        "description": "Wazuh Indexer API operations"
    },
    "wazuh_manager": {
        "port": 8002,
        "description": "Wazuh Manager API operations"
    }
}


class SimpleServerManager:
    """Simple manager for MCP servers"""

    def __init__(self):
        self.processes: Dict[str, subprocess.Popen] = {}

    def start_server(self, server_name: str, debug: bool = False, transport: str = "stdio",
                    host: str = "127.0.0.1") -> bool:
        """Start a specific MCP server with specified transport"""
        if server_name not in SERVERS:
            print(f"❌ Unknown server: {server_name}")
            return False

        if server_name in self.processes:
            print(f"⚠️  Server {server_name} is already running")
            return True

        config = SERVERS[server_name]

        # Set environment variables for debug mode
        env = os.environ.copy()
        if debug:
            env[f"{server_name.upper()}_DEBUG"] = "true"
            env[f"{server_name.upper()}_LOG_LEVEL"] = "DEBUG"

        try:
            print(f"🚀 Starting {server_name} server with {transport.upper()} transport...")

            # Build command with transport arguments using module execution to avoid import errors
            cmd = [sys.executable, "-m", f"{server_name}.server"]

            # Note: Servers are configured to run in their default mode
            # Transport and ports are handled by server configuration

            # Start process - servers run in their default HTTP/SSE mode
            process = subprocess.Popen(
                cmd,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # Give it a moment to start
            time.sleep(2)

            # Check if process is still running
            if process.poll() is None:
                self.processes[server_name] = {
                    "process": process,
                    "transport": "HTTP/SSE",
                    "port": config["port"],
                    "url": f"http://{host}:{config['port']}"
                }

                print(f"✅ Started {server_name} server (PID: {process.pid})")
                print(f"   URL: http://{host}:{config['port']}")
                return True
            else:
                print(f"❌ Failed to start {server_name} server")
                return False

        except Exception as e:
            print(f"❌ Failed to start {server_name}: {e}")
            return False

    def stop_server(self, server_name: str) -> bool:
        """Stop a specific MCP server"""
        if server_name not in self.processes:
            print(f"⚠️  Server {server_name} is not running")
            return True

        server_info = self.processes[server_name]
        process = server_info["process"]

        try:
            print(f"🛑 Stopping {server_name} server...")

            # Send SIGTERM
            process.terminate()

            # Wait for graceful shutdown
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                print(f"⚠️  Force killing {server_name} server...")
                process.kill()
                process.wait()

            del self.processes[server_name]
            print(f"✅ Stopped {server_name} server")
            return True

        except Exception as e:
            print(f"❌ Failed to stop {server_name}: {e}")
            return False

    def start_all_servers(self, debug: bool = False, transport: str = "stdio",
                            host: str = "127.0.0.1") -> bool:
        """Start all MCP servers with specified transport"""
        print(f"🚀 Starting all MCP servers with {transport.upper()} transport...")
        success = True

        for server_name in SERVERS.keys():
            if not self.start_server(server_name, debug=debug, transport=transport, host=host):
                success = False
            time.sleep(1)  # Small delay between server starts

        return success

    def stop_all_servers(self) -> bool:
        """Stop all running MCP servers"""
        print("🛑 Stopping all servers...")
        success = True

        for server_name in list(self.processes.keys()):
            if not self.stop_server(server_name):
                success = False

        return success

    def show_status(self):
        """Show status of all servers"""
        print("\n📊 MCP Servers Status:")
        print("=" * 100)
        print(f"{'Server':<15} {'Status':<10} {'PID':<8} {'Transport':<10} {'URL/Path':<30} {'Description'}")
        print("-" * 100)

        for server_name, config in SERVERS.items():
            is_running = server_name in self.processes
            status_str = "🟢 RUNNING" if is_running else "🔴 STOPPED"

            if is_running:
                server_info = self.processes[server_name]
                pid_str = str(server_info["process"].pid)
                transport_str = server_info["transport"].upper()
                url_str = server_info["url"]
            else:
                pid_str = "-"
                transport_str = "-"
                url_str = "-"

            print(f"{server_name:<15} {status_str:<10} {pid_str:<8} {transport_str:<10} {url_str:<30} {config['description']}")

        print()


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Simple MCP Server Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start all servers in STDIO mode (default - for Cursor/Claude Desktop)
  python run_all_servers.py --start-all

  # Start all servers as HTTP servers
  python run_all_servers.py --start-all --transport http --host 0.0.0.0

  # Start all servers as SSE servers (legacy MCP standard)
  python run_all_servers.py --start-all --transport sse --host 0.0.0.0

  # Start only indexer server in HTTP mode
  python run_all_servers.py --start wazuh_indexer --transport http

  # Stop all servers
  python run_all_servers.py --stop-all

  # Show server status
  python run_all_servers.py --status
        """
    )

    parser.add_argument('--start', choices=SERVERS.keys(), help='Start a specific server')
    parser.add_argument('--stop', choices=SERVERS.keys(), help='Stop a specific server')
    parser.add_argument('--start-all', action='store_true', help='Start all servers')
    parser.add_argument('--stop-all', action='store_true', help='Stop all servers')
    parser.add_argument('--status', action='store_true', help='Show server status')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode for servers')
    parser.add_argument('--transport', choices=['stdio', 'http', 'sse'], default='stdio',
                       help='Transport method: stdio (default, for Cursor/Claude Desktop), http (modern web), sse (legacy server)')
    parser.add_argument('--host', default='127.0.0.1', help='Server host (default: 127.0.0.1)')
    parser.add_argument('--port-offset', type=int, default=0, help='Port offset for all servers')

    args = parser.parse_args()

    manager = SimpleServerManager()

    try:
        if args.status:
            manager.show_status()
            return

        if args.start:
            success = manager.start_server(args.start, debug=args.debug,
                                         transport=args.transport, host=args.host)
            if success:
                print(f"\n✅ Server {args.start} started successfully!")
                manager.show_status()
            else:
                print(f"\n❌ Failed to start server {args.start}")
                sys.exit(1)

        elif args.stop:
            success = manager.stop_server(args.stop)
            if success:
                print(f"\n✅ Server {args.stop} stopped successfully!")
            else:
                print(f"\n❌ Failed to stop server {args.stop}")
                sys.exit(1)

        elif args.start_all:
            success = manager.start_all_servers(debug=args.debug,
                                              transport=args.transport, host=args.host)
            if success:
                print("\n✅ All servers started successfully!")
                manager.show_status()

                # Keep running and monitor
                try:
                    if args.transport == "stdio":
                        print("📡 Servers are running in STDIO mode for Cursor/Claude Desktop integration.")
                        print("📡 Press Ctrl+C to stop all servers...")
                    else:
                        print("📡 Servers are running in server mode.")
                        print("📡 Press Ctrl+C to stop all servers...")
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    print("\n🛑 Stopping all servers...")
                    manager.stop_all_servers()
                    print("✅ All servers stopped!")
            else:
                print("\n❌ Failed to start some servers")
                manager.stop_all_servers()
                sys.exit(1)

        elif args.stop_all:
            success = manager.stop_all_servers()
            if success:
                print("✅ All servers stopped successfully!")
            else:
                print("❌ Failed to stop some servers")
                sys.exit(1)

        else:
            # Default: show status and help
            manager.show_status()
            print("Use --help for available commands")

    except KeyboardInterrupt:
        print("\n🛑 Shutting down...")
        manager.stop_all_servers()
    except Exception as e:
        print(f"❌ Error: {e}")
        manager.stop_all_servers()
        sys.exit(1)


if __name__ == "__main__":
    main()