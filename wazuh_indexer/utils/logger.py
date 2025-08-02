"""
Logger utility for consistent logging across the application
"""
import logging
import os
import sys
import codecs
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional, Dict, Union


# Create logs directory if it doesn't exist
LOG_DIR = os.getenv("LOG_DIR", "logs")
os.makedirs(LOG_DIR, exist_ok=True)

# Cache for loggers to avoid creating multiple instances
_loggers: Dict[str, logging.Logger] = {}


class Utf8StreamHandler(logging.StreamHandler):
    """Stream handler that ensures UTF-8 encoding"""
    
    def __init__(self, stream=None):
        if stream is None:
            stream = sys.stdout
        # Ensure UTF-8 encoding for stdout
        if stream == sys.stdout and hasattr(stream, 'buffer'):
            stream = codecs.getwriter('utf-8')(stream.buffer, 'replace')
        super().__init__(stream)
        self.encoding = 'utf-8'
        
    def emit(self, record):
        try:
            msg = self.format(record)
            stream = self.stream
            # Ensure the message is properly encoded
            if isinstance(msg, str):
                msg = msg.encode('utf-8', 'replace').decode('utf-8')
            stream.write(msg + self.terminator)
            self.flush()
        except Exception:
            self.handleError(record)


def setup_logger(
    name: str = "mcp_server",
    log_level: Optional[str] = None,
    log_to_file: bool = True,
    log_to_console: bool = False,
    log_file: Optional[str] = None,
    max_file_size_mb: int = 10,
    backup_count: int = 5
) -> logging.Logger:
    """
    Configure and return a logger with consistent formatting

    Args:
        name: Logger name
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_to_file: Whether to log to a file
        log_to_console: Whether to log to console
        log_file: Custom log file name (default: {name}.log)
        max_file_size_mb: Maximum log file size in MB before rotation
        backup_count: Number of backup files to keep

    Returns:
        Configured logger
    """
    # Return cached logger if available
    if name in _loggers:
        return _loggers[name]

    if log_level is None:
        log_level = os.getenv("LOG_LEVEL", "INFO").upper()

    # If a specialized log level is set for this specific logger
    specific_level = os.getenv(f"{name.upper()}_LOG_LEVEL")
    if specific_level:
        log_level = specific_level.upper()

    # Create logger
    logger = logging.getLogger(name)

    # Set level
    level = getattr(logging, log_level, logging.INFO)
    logger.setLevel(level)

    # Prevent adding handlers multiple times
    if logger.handlers:
        return logger

    # Create formatter
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Add console handler if requested
    if log_to_console:
        console_handler = Utf8StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    # Add file handler if requested
    if log_to_file:
        if log_file is None:
            log_file = f"{name.lower()}.log"

        file_path = os.path.join(LOG_DIR, log_file)
        file_handler = RotatingFileHandler(
            file_path,
            maxBytes=max_file_size_mb * 1024 * 1024,
            backupCount=backup_count,
            encoding='utf-8',
            errors='replace'
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    # Cache the logger
    _loggers[name] = logger

    return logger


def get_service_logger(service_name: str, log_level: str = "INFO") -> logging.Logger:
    """
    Get a logger for a specific service with appropriate configuration

    Args:
        service_name: Name of the service (e.g., "wazuh_api", "ai_enhancement")
        log_level: Default log level for this service

    Returns:
        Configured logger for the service
    """
    # Convert service_name to a logger-friendly format
    logger_name = service_name.replace(" ", "_").lower()

    return setup_logger(
        name=f"service.{logger_name}",
        log_level=log_level,
        log_file=f"service_{logger_name}.log"
    )


# Create default application logger
logger = setup_logger()

# Create specialized AI logger with debug level
ai_logger = setup_logger(
    name="ai_service",
    log_level="DEBUG",
    log_file="ai_connection.log",
    max_file_size_mb=20  # Larger file size for detailed AI logs
)

# Log startup information
logger.info(f"Logging initialized. Log directory: {os.path.abspath(LOG_DIR)}")
logger.info("UTF-8 encoding configured for all log handlers")
