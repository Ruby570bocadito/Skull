"""
SKULL-NetRecon - Logger
Professional logging system with color support
"""

import logging
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional
from rich.console import Console
from rich.logging import RichHandler


class SkullLogger:
    """Custom logger with file and console output"""
    
    def __init__(self, name: str = "SKULL-NetRecon", log_dir: str = "./logs", verbose: bool = False):
        self.name = name
        self.log_dir = Path(log_dir)
        self.verbose = verbose
        self.console = Console()
        
        # Create log directory
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Setup logger
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Console handler with Rich
        console_handler = RichHandler(
            console=self.console,
            show_time=True,
            show_path=verbose,
            markup=True,
            rich_tracebacks=True
        )
        console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
        console_formatter = logging.Formatter("%(message)s")
        console_handler.setFormatter(console_formatter)
        
        # File handler
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = self.log_dir / f"skull_netrecon_{timestamp}.log"
        
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        
        # Add handlers
        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)
        
        # Store log file path
        self.log_file = log_file
    
    def debug(self, message: str):
        """Log debug message"""
        self.logger.debug(message)
    
    def info(self, message: str):
        """Log info message"""
        self.logger.info(message)
    
    def success(self, message: str):
        """Log success message"""
        self.logger.info(f"[green]✓[/green] {message}")
    
    def warning(self, message: str):
        """Log warning message"""
        self.logger.warning(f"[yellow]⚠[/yellow] {message}")
    
    def error(self, message: str):
        """Log error message"""
        self.logger.error(f"[red]✗[/red] {message}")
    
    def critical(self, message: str):
        """Log critical message"""
        self.logger.critical(f"[red bold]⚠⚠⚠[/red bold] {message}")
    
    def banner(self, text: str):
        """Print a banner"""
        self.console.rule(f"[bold cyan]{text}[/bold cyan]")
    
    def print_table(self, table):
        """Print a Rich table"""
        self.console.print(table)
    
    def print(self, *args, **kwargs):
        """Print to console"""
        self.console.print(*args, **kwargs)
    
    def get_log_file(self) -> Path:
        """Get the current log file path"""
        return self.log_file


# Global logger instance
_global_logger: Optional[SkullLogger] = None


def get_logger(name: str = "SKULL-NetRecon", log_dir: str = "./logs", verbose: bool = False) -> SkullLogger:
    """Get or create global logger instance"""
    global _global_logger
    
    if _global_logger is None:
        _global_logger = SkullLogger(name, log_dir, verbose)
    
    return _global_logger


def setup_logger(name: str = "SKULL-NetRecon", log_dir: str = "./logs", verbose: bool = False) -> SkullLogger:
    """Setup and return logger instance"""
    global _global_logger
    _global_logger = SkullLogger(name, log_dir, verbose)
    return _global_logger
