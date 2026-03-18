"""
base.py — Abstract base connector for Evil Origin Detection.

DATA_CATEGORIES — each connector declares what type of data it can provide.
This allows the router and template to consume data semantically
(e.g. "give me host_info from any source") instead of by source name.

Categories:
  threat     — verdict, score, malicious detections, engine results
  reputation — global reputation score (VT community score, etc.)
  host_info  — geo, ASN, org, ports, flags (VPN/Tor/Cloud)
  ports      — open ports and services
  dns_whois  — DNS records, WHOIS, registrar, dates
  web_osint  — screenshot, technologies, HTTP info, username search
  abuse      — abuse reports, spam frequency, confidence
  file       — file metadata, malware family, hash info
  relations  — correlated IOCs for graph enrichment
"""
import abc
import time
import httpx
from typing import ClassVar, Optional
from app.models import IOCType, SourceStatus
from app.parser import ParsedIOC


class NormalizedResult:
    """
    Canonical data container — all connectors write to these fields.
    The template and router consume these fields, NEVER source-specific keys.

    Field groups map to DATA_CATEGORIES:
      threat:     malicious_count, total_engines, abuse_score, verdict_hint,
                  classification, tags
      reputation: pulse_count
      host_info:  country, city, asn, org, isp, network, hostnames,
                  lat, lon, is_tor, is_vpn, is_noise, usage_type, last_seen
      ports:      ports (list[int]), services (dict port→service_name)
      dns_whois:  dns_records, registrar, creation_date, expiry_date
      web_osint:  screenshot_url, http_status, technologies, username_hits,
                  http_title, redirects
      abuse:      email_reports
      file:       file_name, file_type, file_size, malware_family,
                  first_submission
      relations:  (stored in raw["_relations"] / raw["_linked_iocs"])
                  reports  (list[dict] for timeline — {date, summary, category})
    """
    __slots__ = (
        "source",
        "status",
        "ioc_value",
        "ioc_type",

        # ── threat ────────────────────────────────────────────────
        "malicious_count",
        "total_engines",
        "abuse_score",          # 0–100
        "classification",       # malicious | benign | unknown
        "pulse_count",          # feed/pulse count (Pulsedive)
        "tags",                 # list[str]
        "verdict_hint",         # canonical: malicious|suspicious|clean|unknown

        # ── host_info ─────────────────────────────────────────────
        "country",
        "city",
        "asn",
        "org",
        "isp",
        "network",              # CIDR block
        "hostnames",            # list[str]
        "last_seen",            # ISO date string
        "usage_type",           # datacenter|residential|vpn|tor|mobile...
        "is_tor",
        "is_vpn",
        "is_proxy",
        "is_hosting",
        "is_mobile",
        "is_scanner",
        "is_darkweb",
        "is_noise",

        # ── ports ─────────────────────────────────────────────────
        "ports",                # list[int]  — port numbers only
        "services",             # dict[int, str]  — port → service/product name

        # ── geolocation (subset of host_info) ─────────────────────
        "latitude",
        "longitude",

        # ── dns_whois ─────────────────────────────────────────────
        "registrar",
        "creation_date",
        "expiry_date",
        "dns_records",          # dict

        # ── web_osint ─────────────────────────────────────────────
        "screenshot_url",
        "http_status",
        "http_title",           # page title from URLScan/Pulsedive
        "technologies",         # list[str]
        "redirects",            # list[str] — redirect chain URLs
        "username_hits",        # list[dict] — WhatsMyName results

        # ── file ──────────────────────────────────────────────────
        "file_name",
        "file_type",
        "file_size",
        "malware_family",
        "first_submission",

        # ── abuse ─────────────────────────────────────────────────
        "email_reports",        # int — spam report count
        "reports",              # list[dict] — individual reports with dates

        # ── internal ──────────────────────────────────────────────
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
        # Lists / dicts default to empty, not None
        self.tags         = []
        self.ports        = []
        self.services     = {}
        self.hostnames    = []
        self.dns_records  = {}
        self.technologies = []
        self.redirects    = []
        self.username_hits = []
        self.reports      = []
        self.verdict_hint = "unknown"   # always a string, never None

    def to_dict(self) -> dict:
        result = {}
        for s in self.__slots__:
            val = getattr(self, s)
            if hasattr(val, "value"):   # Enum → .value string
                result[s] = val.value
            else:
                result[s] = val
        return result


class BaseConnector(abc.ABC):
    """Abstract base class — all connectors inherit this."""

    # ── Subclass must declare these ───────────────────────────────────────────

    # Which IOC types this source supports
    SUPPORTED_TYPES: ClassVar[set[IOCType]] = set()

    # Source identifier string — must match column in source_results
    SOURCE_NAME: ClassVar[str] = "base"

    # What categories of data this source can provide.
    # Used by the router/template to consume data semantically.
    # Values from: threat, reputation, host_info, ports, dns_whois,
    #              web_osint, abuse, file, relations
    DATA_CATEGORIES: ClassVar[set[str]] = set()

    # Request timeout in seconds
    TIMEOUT: ClassVar[float] = 12.0

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key

    def supports(self, ioc: ParsedIOC) -> bool:
        return ioc.type in self.SUPPORTED_TYPES

    def requires_key(self) -> bool:
        """Override to False for keyless sources."""
        return True

    def has_category(self, category: str) -> bool:
        """Check if this source provides a given data category."""
        return category in self.DATA_CATEGORIES

    async def query(self, ioc: ParsedIOC) -> NormalizedResult:
        """
        Main entry point. Handles: type check, key presence,
        timing, error wrapping.
        """
        result = NormalizedResult(self.SOURCE_NAME, ioc, SourceStatus.skipped)

        if not self.supports(ioc):
            result.status = SourceStatus.skipped
            return result

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
            code = exc.response.status_code
            # 404 = indicator not in this source's database — treat as unknown, not error
            if code == 404:
                result.status     = SourceStatus.ok
                result.verdict_hint = "unknown"
                result.error      = None
            else:
                result.status     = SourceStatus.error
                result.error      = f"HTTP {code}"
            result.fetched_ms = int((time.monotonic() - t0) * 1000)
        except Exception as exc:
            result.status     = SourceStatus.error
            result.error      = str(exc)
            result.fetched_ms = int((time.monotonic() - t0) * 1000)

        return result

    @abc.abstractmethod
    async def _fetch(self, ioc: ParsedIOC) -> dict:
        """Make HTTP request(s). Return raw API response as dict."""
        ...

    @abc.abstractmethod
    def normalize(self, raw: dict, ioc: ParsedIOC,
                  result: NormalizedResult) -> None:
        """Map raw API fields onto result (NormalizedResult)."""
        ...

    def _client(self, headers: Optional[dict] = None) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=self.TIMEOUT,
            follow_redirects=True,
            headers=headers or {},
        )
