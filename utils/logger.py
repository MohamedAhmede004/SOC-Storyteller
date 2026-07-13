"""
utils/logger.py

Centralized logging configuration for SOC Storyteller.

Every module in the project obtains its logger via :func:`get_logger`
instead of calling ``logging.getLogger`` directly. This guarantees a
single, consistent log format/handler configuration across the whole
application and makes it trivial to redirect all logging (e.g. to a
file, to stdout, or to both) from one place.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional

_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)-28s | %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Guard flag so we only configure the root "soc_storyteller" logger once,
# even if get_logger() / configure_logging() is called many times.
_CONFIGURED = False


def configure_logging(
    level: int = logging.INFO,
    log_file: Optional[Path] = None,
    verbose: bool = False,
) -> None:
    """Configure the project-wide ``soc_storyteller`` logger tree.

    This should be called once, near the start of program execution
    (typically from ``main.py``). Subsequent calls are safe no-ops unless
    ``log_file`` changes, in which case a new file handler is attached.

    Args:
        level: The base logging level (e.g. ``logging.INFO``,
            ``logging.DEBUG``) applied when ``verbose`` is False.
        log_file: Optional path to also write logs to a file. Parent
            directories are created automatically if they do not exist.
        verbose: If True, forces DEBUG-level logging regardless of
            ``level``. Convenient for a ``--verbose`` CLI flag.

    Returns:
        None
    """
    global _CONFIGURED

    effective_level = logging.DEBUG if verbose else level
    root_logger = logging.getLogger("soc_storyteller")
    root_logger.setLevel(effective_level)

    if not _CONFIGURED:
        formatter = logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT)

        console_handler = logging.StreamHandler(stream=sys.stdout)
        console_handler.setFormatter(formatter)
        console_handler.setLevel(effective_level)
        root_logger.addHandler(console_handler)

        _CONFIGURED = True
    else:
        # Already configured: just update level on existing handlers.
        for handler in root_logger.handlers:
            handler.setLevel(effective_level)

    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        # Avoid attaching duplicate file handlers for the same path.
        existing_files = {
            Path(h.baseFilename).resolve()
            for h in root_logger.handlers
            if isinstance(h, logging.FileHandler)
        }
        if log_file.resolve() not in existing_files:
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT))
            file_handler.setLevel(effective_level)
            root_logger.addHandler(file_handler)


def get_logger(name: str) -> logging.Logger:
    """Return a module-scoped logger under the ``soc_storyteller`` namespace.

    Args:
        name: Usually ``__name__`` of the calling module, e.g.
            ``"soc_storyteller.parser.evtx_parser"``. A short prefix is
            added automatically if the caller passes a bare module name.

    Returns:
        A configured :class:`logging.Logger` instance. If
        :func:`configure_logging` has not yet been called, a sane default
        configuration (INFO level, console only) is applied automatically
        so that library usage without explicit setup still produces
        readable output.
    """
    if not _CONFIGURED:
        configure_logging()

    if name.startswith("soc_storyteller"):
        return logging.getLogger(name)
    return logging.getLogger(f"soc_storyteller.{name}")
