from __future__ import annotations

import os
import logging


def setup_logging() -> None:
    level = os.getenv("LOG_LEVEL", "INFO").strip().upper()
    if level not in ("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"):
        level = "INFO"

    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)sZ %(levelname)s %(name)s :: %(message)s",
    )

    # requests/urllib3 noisy logs down
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
