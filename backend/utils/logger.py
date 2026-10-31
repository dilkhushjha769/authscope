"""Structured logging module for AuthScope.

Provides formatted console logs via Rich and file-based logs for audit trails.
"""

import logging
import sys
from rich.logging import RichHandler


def get_logger(name: str) -> logging.Logger:
    """Configures and returns a structured logger instance."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)

        handler = RichHandler(
            rich_tracebacks=True,
            show_time=True,
            show_level=True,
            show_path=False
        )
        formatter = logging.Formatter("%(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger

