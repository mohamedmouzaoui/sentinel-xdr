"""
Sentinel XDR Pro — Logging Configuration
==========================================
Compatibility shim: works with structlog if installed, falls back to stdlib.
"""
from __future__ import annotations
import logging
import sys

def get_logger(name: str):
    """Return a structlog logger if available, else stdlib logger."""
    try:
        import structlog
        return structlog.get_logger(name)
    except ImportError:
        logger = logging.getLogger(name)
        if not logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(logging.Formatter(
                '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
            ))
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger
