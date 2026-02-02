"""
Utility functions for the Cybersecurity Threat Advisor system.

This module provides common utility functions used across the application:
- Configuration loading
- Logging setup
- Date/time utilities
- File operations
"""

import yaml
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional


class Config:
    """
    Configuration manager that loads and provides access to system settings.
    
    Explanation:
    - Reads config.yaml file at startup
    - Provides easy access to configuration values
    - Handles missing config gracefully
    """
    
    def __init__(self, config_path: str = "config/config.yaml"):
        """
        Initialize configuration manager.
        
        Args:
            config_path: Path to the YAML configuration file
        """
        self.config_path = config_path
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logging.warning(f"Config file not found: {self.config_path}. Using defaults.")
            return {}
        except yaml.YAMLError as e:
            logging.error(f"Error parsing config file: {e}")
            return {}
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation.
        
        Example:
            config.get('monitoring.system_check_interval', 5)
            This gets the value from config['monitoring']['system_check_interval']
        
        Args:
            key_path: Dot-separated path to config value
            default: Default value if key not found
        
        Returns:
            Configuration value or default
        """
        keys = key_path.split('.')
        value = self.config
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        
        return value
    
    def reload(self):
        """Reload configuration from file."""
        self.config = self._load_config()


class Logger:
    """
    Logging manager for the application.
    
    Explanation:
    - Sets up logging to both file and console
    - Configures log format and level
    - Provides colored output for console
    """
    
    @staticmethod
    def setup_logging(config: Config) -> logging.Logger:
        """
        Set up application logging.
        
        Args:
            config: Configuration object
        
        Returns:
            Configured logger instance
        """
        log_level = config.get('logging.level', 'INFO')
        log_file = config.get('logging.log_file', 'data/logs/app.log')
        
        # Create logs directory if it doesn't exist
        log_dir = os.path.dirname(log_file)
        os.makedirs(log_dir, exist_ok=True)
        
        # Configure root logger
        logger = logging.getLogger('CyberAdvisor')
        logger.setLevel(getattr(logging, log_level))
        
        # Clear existing handlers
        logger.handlers = []
        
        # File handler
        file_handler = logging.FileHandler(log_file)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_formatter = logging.Formatter(
            '%(levelname)s: %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
        
        return logger


def load_rules(rules_path: str = "config/rules.json") -> Dict[str, Any]:
    """
    Load detection rules from JSON file.
    
    Explanation:
    Rules define what threats to look for and how to respond.
    Each rule has conditions, severity, and advisory information.
    
    Args:
        rules_path: Path to rules JSON file
    
    Returns:
        Dictionary containing rules and advisory templates
    """
    try:
        with open(rules_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        logging.warning(f"Rules file not found: {rules_path}")
        return {"rules": [], "advisory_templates": {}}
    except json.JSONDecodeError as e:
        logging.error(f"Error parsing rules file: {e}")
        return {"rules": [], "advisory_templates": {}}


def ensure_directory(path: str):
    """
    Ensure a directory exists, create if it doesn't.
    
    Args:
        path: Directory path to create
    """
    os.makedirs(path, exist_ok=True)


def timestamp_now() -> str:
    """
    Get current timestamp in ISO format.
    
    Returns:
        Current timestamp as string
    """
    return datetime.now().isoformat()


def format_timestamp(timestamp: str, format_str: str = "%Y-%m-%d %H:%M:%S") -> str:
    """
    Format ISO timestamp to human-readable format.
    
    Args:
        timestamp: ISO format timestamp
        format_str: Desired output format
    
    Returns:
        Formatted timestamp string
    """
    try:
        dt = datetime.fromisoformat(timestamp)
        return dt.strftime(format_str)
    except:
        return timestamp


def calculate_time_diff(timestamp1: str, timestamp2: str) -> float:
    """
    Calculate time difference in seconds between two timestamps.
    
    Args:
        timestamp1: First timestamp (ISO format)
        timestamp2: Second timestamp (ISO format)
    
    Returns:
        Time difference in seconds
    """
    try:
        dt1 = datetime.fromisoformat(timestamp1)
        dt2 = datetime.fromisoformat(timestamp2)
        return abs((dt2 - dt1).total_seconds())
    except:
        return 0.0


def safe_get(dictionary: Dict, *keys, default=None):
    """
    Safely get nested dictionary value.
    
    Example:
        safe_get(data, 'user', 'profile', 'name', default='Unknown')
    
    Args:
        dictionary: Dictionary to search
        *keys: Keys to traverse
        default: Default value if key not found
    
    Returns:
        Value or default
    """
    for key in keys:
        if isinstance(dictionary, dict) and key in dictionary:
            dictionary = dictionary[key]
        else:
            return default
    return dictionary


def truncate_string(text: str, max_length: int = 100) -> str:
    """
    Truncate string to max length with ellipsis.
    
    Args:
        text: String to truncate
        max_length: Maximum length
    
    Returns:
        Truncated string
    """
    if len(text) <= max_length:
        return text
    return text[:max_length-3] + "..."


def get_project_root() -> Path:
    """
    Get project root directory.
    
    Returns:
        Path object pointing to project root
    """
    return Path(__file__).parent.parent.parent


# Initialize global configuration
_global_config = None

def get_config() -> Config:
    """
    Get global configuration instance (singleton pattern).
    
    Returns:
        Global Config object
    """
    global _global_config
    if _global_config is None:
        _global_config = Config()
    return _global_config
