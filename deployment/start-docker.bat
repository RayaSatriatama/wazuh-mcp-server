@echo off
REM Wazuh MCP Server - Quick Docker Deployment Script (Windows)
REM This script will start both Wazuh MCP servers using Docker Compose

echo.
echo 🚀 Starting Wazuh MCP Server Docker Deployment...
echo ==================================================
echo.

REM Get the directory where this script is located
set "SCRIPT_DIR=%~dp0"
set "PROJECT_ROOT=%SCRIPT_DIR%.."

echo 📁 Project Root: %PROJECT_ROOT%

REM Check if Docker is installed
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Docker is not installed or not in PATH
    echo Please install Docker and Docker Compose first
    pause
    exit /b 1
)

REM Check if Docker Compose is available
docker compose version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Docker Compose is not available
    echo Please install Docker Compose
    pause
    exit /b 1
)

REM Navigate to deployment directory
set "DOCKER_DIR=%PROJECT_ROOT%\deployment\docker"

if not exist "%DOCKER_DIR%\docker-compose.yml" (
    echo ❌ Docker Compose file not found at: %DOCKER_DIR%\docker-compose.yml
    pause
    exit /b 1
)

echo 📦 Docker Compose file found
echo 🔧 Starting containers...

REM Change to docker directory
cd /d "%DOCKER_DIR%"

REM Stop any existing containers
echo 🛑 Stopping existing containers...
docker compose down --remove-orphans

REM Start containers
echo ▶️  Starting Wazuh MCP servers...
docker compose up -d

REM Wait for containers to be ready
echo ⏳ Waiting for containers to start...
timeout /t 5 /nobreak >nul

REM Check container status
echo.
echo 📊 Container Status:
docker compose ps

REM Show logs
echo.
echo 📝 Recent logs:
echo ===============
docker compose logs --tail=10

echo.
echo ✅ Deployment completed!
echo.
echo 🌐 MCP Server Endpoints:
echo   - Wazuh Indexer HTTP: http://localhost:8001/mcp
echo   - Wazuh Manager HTTP: http://localhost:8002/mcp
echo   - Wazuh Indexer SSE:  http://localhost:8001/sse
echo   - Wazuh Manager SSE:  http://localhost:8002/sse
echo.
echo 🔍 To view logs: docker compose -f "%DOCKER_DIR%\docker-compose.yml" logs -f
echo 🛑 To stop: docker compose -f "%DOCKER_DIR%\docker-compose.yml" down
echo.
echo 📋 Copy the following to your Cursor/Claude Desktop MCP config:
echo.
echo {
echo   "mcpServers": {
echo     "wazuh_indexer": {
echo       "url": "http://localhost:8001/mcp"
echo     },
echo     "wazuh_manager": {
echo       "url": "http://localhost:8002/mcp"
echo     }
echo   }
echo }
echo.
pause
