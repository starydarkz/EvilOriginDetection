"""
logger.py — Dual logging for Evil Origin Detection.

1. Structured file log (JSON lines) — all query activity for ops/audit.
2. Console log — human readable for development.

Query logs include: origin IP, user-agent, IOC queried, verdict, latency.
These are NEVER exposed in the UI — backend-only.
"""
import json
import logging
import logging.handlers
import os
import time
from datetime import datetime, timezone
from typing import Optional

from fastapi import Request
from config import get_settings

settings = get_settings()

# ── Setup ──────────────────────────────────────────────────────────────────────

os.makedirs(os.path.dirname(settings.log_path), exist_ok=True)

# File handler — JSON lines, one entry per query
_file_handler = logging.handlers.RotatingFileHandler(
    settings.log_path,
    maxBytes=10 * 1024 * 1024,   # 10 MB
    backupCount=5,
    encoding="utf-8",
)
_file_handler.setFormatter(logging.Formatter("%(message)s"))

# Console handler — readable
_console_handler = logging.StreamHandler()
_console_handler.setFormatter(logging.Formatter(
    "%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
))

# App logger
app_logger = logging.getLogger("eod")
app_logger.setLevel(getattr(logging, settings.log_level.upper(), logging.INFO))
app_logger.addHandler(_file_handler)
app_logger.addHandler(_console_handler)
app_logger.propagate = False

# Query-specific logger (file only — never console)
query_logger = logging.getLogger("eod.queries")
query_logger.setLevel(logging.INFO)
query_logger.addHandler(_file_handler)
query_logger.propagate = False


# ── Helpers ────────────────────────────────────────────────────────────────────

def get_client_ip(request: Request) -> str:
    """Extract real client IP, respecting X-Forwarded-For."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def log_query(
    request:       Request,
    ioc_value:     str,
    ioc_type:      Optional[str] = None,
    verdict:       Optional[str] = None,
    forced_rescan: bool = False,
    response_ms:   Optional[int] = None,
) -> None:
    """
    Write a structured query log entry.
    Contains everything useful for later analysis — never shown in UI.
    """
    entry = {
        "ts":           datetime.now(timezone.utc).isoformat(),
        "origin_ip":    get_client_ip(request),
        "user_agent":   request.headers.get("user-agent", ""),
        "method":       request.method,
        "path":         str(request.url.path),
        "ioc_value":    ioc_value,
        "ioc_type":     ioc_type,
        "verdict":      verdict,
        "forced_rescan":forced_rescan,
        "response_ms":  response_ms,
        "referer":      request.headers.get("referer", ""),
        "accept_lang":  request.headers.get("accept-language", ""),
    }
    query_logger.info(json.dumps(entry, ensure_ascii=False))
