"""SKULL-NetRecon - Logger Module"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler


class SkullLogger:
    """Custom logger with file and console output."""

    def __init__(
        self,
        name: str = "SKULL-NetRecon",
        log_dir: str = "./logs",
        verbose: bool = False,
    ) -> None:
        self.name = name
        self.log_dir = Path(log_dir)
        self.verbose = verbose
        self.console = Console()
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)
        self.logger.handlers.clear()

        console_handler = RichHandler(
            console=self.console,
            show_time=True,
            show_path=verbose,
            markup=True,
            rich_tracebacks=True,
        )
        console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
        console_handler.setFormatter(logging.Formatter("%(message)s"))

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = self.log_dir / f"skull_netrecon_{timestamp}.log"
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        )

        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)
        self.log_file = log_file

    def debug(self, message: str) -> None:
        self.logger.debug(message)

    def info(self, message: str) -> None:
        self.logger.info(message)

    def success(self, message: str) -> None:
        self.logger.info(f"[green]✓[/green] {message}")

    def warning(self, message: str) -> None:
        self.logger.warning(f"[yellow]⚠[/yellow] {message}")

    def error(self, message: str) -> None:
        self.logger.error(f"[red]✗[/red] {message}")

    def critical(self, message: str) -> None:
        self.logger.critical(f"[red bold]⚠⚠⚠[/red bold] {message}")

    def banner(self, text: str) -> None:
        self.console.rule(f"[bold cyan]{text}[/bold cyan]")

    def get_log_file(self) -> Path:
        return self.log_file


_global_logger: Optional[SkullLogger] = None


def get_logger(
    name: str = "SKULL-NetRecon",
    log_dir: str = "./logs",
    verbose: bool = False,
) -> SkullLogger:
    """Get or create global logger instance."""
    global _global_logger
    if _global_logger is None:
        _global_logger = SkullLogger(name, log_dir, verbose)
    return _global_logger


def setup_logger(
    name: str = "SKULL-NetRecon",
    log_dir: str = "./logs",
    verbose: bool = False,
) -> SkullLogger:
    """Setup and return a fresh logger instance."""
    global _global_logger
    _global_logger = SkullLogger(name, log_dir, verbose)
    return _global_logger
