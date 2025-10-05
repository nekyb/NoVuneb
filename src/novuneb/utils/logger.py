"""
Logging configuration for NoVuneb.
"""

import logging
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler


def setup_logger(
    name: str = "novuneb",
    level: int = logging.INFO,
    log_file: Optional[Path] = None,
    verbose: bool = False
) -> logging.Logger:
    """
    Set up logger with rich formatting.
    
    Args:
        name: Logger name
        level: Logging level
        log_file: Optional file path for logging
        verbose: Enable verbose output
        
    Returns:
        Configured logger
    """
    if verbose:
        level = logging.DEBUG
    
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    if logger.handlers:
        logger.handlers.clear()
    
    console = Console(stderr=True)
    
    rich_handler = RichHandler(
        console=console,
        show_time=True,
        show_path=False,
        markup=True,
        rich_tracebacks=True,
    )
    rich_handler.setLevel(level)
    
    formatter = logging.Formatter(
        "%(message)s",
        datefmt="[%X]"
    )
    rich_handler.setFormatter(formatter)
    
    logger.addHandler(rich_handler)
    
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        
        file_formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        file_handler.setFormatter(file_formatter)
        
        logger.addHandler(file_handler)
    
    return logger


def get_logger(name: str = "novuneb") -> logging.Logger:
    """Get existing logger"""
    return logging.getLogger(name)
