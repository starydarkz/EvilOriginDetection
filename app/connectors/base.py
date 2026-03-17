"""
base.py — Abstract base connector for all threat intelligence sources.

Every connector inherits BaseConnector and implements:
  - SUPPORTED_TYPES: which IOC types this source can handle
  - _fetch(): the actual HTTP call returning raw dict
  - normalize(): maps raw response → NormalizedResult

The dispatcher calls query() which handles:
  - key selection (token rotation via config.pick_key)
  - type compatibility check
  - timeout / error handling
  - returning a SourceResult-ready dict
"""
import time
import abc
import httpx
from typing import Optional, ClassVar
from app.models import IOCType, SourceStatus
from app.parser import ParsedIOC


class NormalizedResult:
    """
    Unified schema returned by every connector.
    Fields not applicable to a source are left as None.
    """
    __slots__ = (
        "source",
        "status",
        "ioc_value",
        "ioc_type",

        # Core threat intel
        "malicious_count",
        "total_engines",
        "abuse_score",          # 0–100 percentage (AbuseIPDB style)
        "classification",       # malicious | benign | unknown (GreyNoise)
        "pulse_count",          # OTX / Pulsedive threat feeds count
        "tags",                 # list[str]
        "verdict_hint",         # source's own verdict string

        # Network / IP
        "country",
        "city",
        "asn",
        "org",
        "isp",
        "network",              # CIDR
        "ports",                # list[int]
        "hostnames",            # list[str]
        "last_seen",
        "usage_type",           # datacenter | residential | vpn | tor...
        "is_tor",
        "is_vpn",
        "is_noise",

        # Domain / URL
        "registrar",
        "creation_date",
        "expiry_date",
        "dns_records",          # dict
        "screenshot_url",       # URLScan result
        "http_status",
        "technologies",         # list[str]

        # Hash / File
        "file_name",
        "file_type",
        "file_size",
        "malware_family",
        "first_submission",

        # Email
        "email_reports",
        "username_hits",        # WhatsMyName results list

        # Raw
        "raw",                  # full original API response dict
        "error",                # error message if status != ok
        "fetched_ms",           # latency in ms
    )

    def __init__(self, source: str, ioc: ParsedIOC, status: SourceStatus):
        for slot in self.__slots__:
            setattr(self, slot, None)
        self.source    = source
        self.ioc_value = ioc.value
        self.ioc_type  = ioc.type
        self.status    = status
        self.tags      = []
        self.ports     = []
        self.hostnames = []
        self.dns_records   = {}
        self.technologies  = []
        self.username_hits = []
        self.verdict_hint  = "unknown"   # always a string, never None

    def to_dict(self) -> dict:
        result = {}
        for s in self.__slots__:
            val = getattr(self, s)
            if hasattr(val, "value"):
                result[s] = val.value
            else:
                result[s] = val
        return result


class BaseConnector(abc.ABC):
    """Abstract base class — all connectors inherit this."""

    # Override in subclass: which IOC types this source supports
    SUPPORTED_TYPES: ClassVar[set[IOCType]] = set()

    # Source identifier string — must match column in source_results
    SOURCE_NAME: ClassVar[str] = "base"

    # Request timeout in seconds
    TIMEOUT: ClassVar[float] = 12.0

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key

    def supports(self, ioc: ParsedIOC) -> bool:
        return ioc.type in self.SUPPORTED_TYPES

    async def query(self, ioc: ParsedIOC) -> NormalizedResult:
        """
        Main entry point called by the dispatcher.
        Handles: type check, key presence, timing, error wrapping.
        """
        result = NormalizedResult(self.SOURCE_NAME, ioc, SourceStatus.skipped)

        # Type check
        if not self.supports(ioc):
            result.status = SourceStatus.skipped
            return result

        # Key check (only if source requires key)
        if self.requires_key() and not self.api_key:
            result.status = SourceStatus.no_key
            return result

        t0 = time.monotonic()
        try:
            raw = await self._fetch(ioc)
            result.fetched_ms = int((time.monotonic() - t0) * 1000)
            result.raw = raw
            self.normalize(raw, ioc, result)
            result.status = SourceStatus.ok
        except httpx.TimeoutException:
            result.status     = SourceStatus.timeout
            result.error      = "Request timed out"
            result.fetched_ms = int((time.monotonic() - t0) * 1000)
        except httpx.HTTPStatusError as exc:
            result.status     = SourceStatus.error
            result.error      = f"HTTP {exc.response.status_code}"
            result.fetched_ms = int((time.monotonic() - t0) * 1000)
        except Exception as exc:
            result.status     = SourceStatus.error
            result.error      = str(exc)
            result.fetched_ms = int((time.monotonic() - t0) * 1000)

        return result

    def requires_key(self) -> bool:
        """Override to False for keyless sources (StopForumSpam, MalwareBazaar...)."""
        return True

    @abc.abstractmethod
    async def _fetch(self, ioc: ParsedIOC) -> dict:
        """Make the HTTP request(s). Return raw API response as dict."""
        ...

    @abc.abstractmethod
    def normalize(self, raw: dict, ioc: ParsedIOC, result: NormalizedResult) -> None:
        """Map raw API response fields onto result (NormalizedResult)."""
        ...

    @staticmethod
    def _client(headers: Optional[dict] = None) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=BaseConnector.TIMEOUT,
            headers=headers or {},
            follow_redirects=True,
        )
