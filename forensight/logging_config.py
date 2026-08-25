"""Application logging (spec section 54).

Never logs raw evidence contents - only forensic workflow events.
"""
from __future__ import annotations

import logging
from pathlib import Path

_LOG_FORMAT = "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"
_DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def configure_logging(log_dir: str | Path | None = None) -> logging.Logger:
    """Configure the root ForenSight logger.

    When ``log_dir`` is provided a per-case ``application.log`` file handler is
    attached; a stream handler is always present.
    """
    logger = logging.getLogger("forensight")
    logger.setLevel(logging.INFO)

    # Remove any previously attached file handlers so switching cases does not
    # keep writing to an old case's log file.
    for handler in list(logger.handlers):
        if isinstance(handler, logging.FileHandler):
            logger.removeHandler(handler)
            handler.close()

    if not any(isinstance(h, logging.StreamHandler) for h in logger.handlers):
        stream = logging.StreamHandler()
        stream.setFormatter(logging.Formatter(_LOG_FORMAT, _DATE_FORMAT))
        logger.addHandler(stream)

    if log_dir is not None:
        log_path = Path(log_dir) / "application.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setFormatter(logging.Formatter(_LOG_FORMAT, _DATE_FORMAT))
        logger.addHandler(file_handler)

    logger.propagate = False
    return logger


def get_logger(name: str = "forensight") -> logging.Logger:
    return logging.getLogger(name if name.startswith("forensight") else f"forensight.{name}")
