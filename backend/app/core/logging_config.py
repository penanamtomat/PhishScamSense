"""
Centralized logging configuration for PhishScamSense backend.

Format: LEVEL    [timestamp] logger_name — message
"""
import logging
import logging.config
import sys
from app.core.config import settings

_FMT = "%(levelname)-8s [%(asctime)s] %(name)s — %(message)s"
_DATE_FMT = "%Y-%m-%d %H:%M:%S"


def setup_logging(level: str | None = None) -> None:
    effective_level = level or ("DEBUG" if settings.DOCS_ENABLED else "INFO")
    config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "standard": {"format": _FMT, "datefmt": _DATE_FMT},
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "stream": sys.stdout,
                "formatter": "standard",
            },
        },
        "root": {"handlers": ["console"], "level": effective_level},
        "loggers": {
            "uvicorn": {"level": "INFO", "propagate": True},
            "uvicorn.error": {"level": "INFO", "propagate": True},
            "uvicorn.access": {"level": "WARNING", "propagate": True},
            "httpx": {"level": "WARNING", "propagate": True},
            "httpcore": {"level": "WARNING", "propagate": True},
            "transformers": {"level": "WARNING", "propagate": True},
            "xgboost": {"level": "WARNING", "propagate": True},
            "torch": {"level": "WARNING", "propagate": True},
        },
    }
    logging.config.dictConfig(config)
