"""
logger.py — Logging for Evil Origin Detection.

On Render: logs go to stdout/stderr only (console visible in Render Dashboard → Logs).
No file logging — Render's filesystem is ephemeral and Logs tab shows stdout.

Log levels:
  INFO  — startup, query activity, normal events
  ERROR — exceptions, connector failures
  DEBUG — detailed connector responses (set LOG_LEVEL=DEBUG in Render env)
"""
import json
import logging
import sys
from datetime import datetime, timezone
from typing import Optional

from fastapi import Request
from config import get_settings

settings = get_settings()

# ── Single console handler → stdout (visible in Render Logs tab) ──────────────

_console_handler = logging.StreamHandler(sys.stdout)
_console_handler.setFormatter(logging.Formatter(
    "%(asctime)s [%(levelname)-8s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
))

# ── App logger ────────────────────────────────────────────────────────────────

app_logger = logging.getLogger("eod")
app_logger.setLevel(getattr(logging, settings.log_level.upper(), logging.INFO))
app_logger.addHandler(_console_handler)
app_logger.propagate = False

# ── Query logger — structured JSON to stdout ──────────────────────────────────

query_logger = logging.getLogger("eod.queries")
query_logger.setLevel(logging.INFO)
query_logger.addHandler(_console_handler)
query_logger.propagate = False

# ── Exception logger — full tracebacks to stderr ─────────────────────────────

_err_handler = logging.StreamHandler(sys.stderr)
_err_handler.setLevel(logging.ERROR)
_err_handler.setFormatter(logging.Formatter(
    "%(asctime)s [ERROR] %(name)s\n%(message)s\n%(exc_info)s",
    datefmt="%Y-%m-%d %H:%M:%S",
))

exc_logger = logging.getLogger("eod.errors")
exc_logger.setLevel(logging.ERROR)
exc_logger.addHandler(_err_handler)
exc_logger.propagate = False


# ── Helpers ───────────────────────────────────────────────────────────────────

def get_client_ip(request: Request) -> str:
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
    entry = {
        "ts":           datetime.now(timezone.utc).isoformat(),
        "origin_ip":    get_client_ip(request),
        "ioc_value":    ioc_value,
        "ioc_type":     ioc_type,
        "verdict":      verdict,
        "forced_rescan":forced_rescan,
        "response_ms":  response_ms,
    }
    query_logger.info(f"QUERY {json.dumps(entry, ensure_ascii=False)}")
