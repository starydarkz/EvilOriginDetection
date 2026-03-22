"""
feodotracker.py — Feodo Tracker (abuse.ch) botnet C2 IP list.

Downloads static JSON: https://feodotracker.abuse.ch/downloads/ipblocklist.json
No API key required. Cached for 1 hour in memory.

Tracks C2 servers for: Emotet, QakBot, TrickBot, Dridex, BazarLoader, Pikabot.
These are botnets heavily associated with ransomware & darkweb operations.
"""
import asyncio
import time
from app.models  import IOCType
from app.parser  import ParsedIOC
from .base       import BaseConnector, NormalizedResult
from typing      import ClassVar

BLOCKLIST_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

# Module-level cache: (timestamp, {ip: entry})
_cache: dict = {"ts": 0, "data": {}}
_CACHE_TTL = 3600  # 1 hour
_lock: asyncio.Lock | None = None

def _get_lock() -> asyncio.Lock:
    global _lock
    if _lock is None:
        _lock = asyncio.Lock()
    return _lock


class FeodoTrackerConnector(BaseConnector):
    SOURCE_NAME:     ClassVar[str]   = "feodotracker"
    SUPPORTED_TYPES: ClassVar[set]   = {IOCType.ip}
    DATA_CATEGORIES: ClassVar[set]   = {"threat"}
    TIMEOUT:         ClassVar[float] = 20.0

    def requires_key(self) -> bool:
        return False

    async def _fetch(self, ioc: ParsedIOC) -> dict:
        import httpx

        # Strip port if present
        ip = ioc.value.split(":")[0] if ":" in ioc.value else ioc.value

        async with _get_lock():
            now = time.monotonic()
            if now - _cache["ts"] > _CACHE_TTL or not _cache["data"]:
                r = await httpx.AsyncClient(timeout=self.TIMEOUT).get(BLOCKLIST_URL)
                r.raise_for_status()
                entries = r.json()
                if isinstance(entries, list):
                    _cache["data"] = {
                        e["ip_address"]: e
                        for e in entries
                        if isinstance(e, dict) and e.get("ip_address")
                    }
                _cache["ts"] = now

        entry = _cache["data"].get(ip)
        return entry if entry else {"_not_found": True}

    def normalize(self, raw: dict, ioc: ParsedIOC,
                  result: NormalizedResult) -> None:
        if raw.get("_not_found"):
            result.verdict_hint = "unknown"
            return

        result.verdict_hint  = "malicious"
        result.abuse_score   = 100
        result.threat_type   = "Botnet C2"

        mw = raw.get("malware")
        result.malware_family = mw or "Unknown Botnet"
        result.country        = raw.get("country")
        result.last_seen      = (raw.get("last_online") or raw.get("first_seen",""))[:19]

        # Port used by C2
        port = raw.get("port")
        if port:
            result.ports    = [int(port)]
            result.services = {int(port): f"{mw or 'Botnet'} C2"}

        status = raw.get("status") or "unknown"

        result.tags = [
            mw or "botnet",
            "C2-server",
            f"status:{status}",
        ]
        if mw:
            result.tags.insert(0, mw.lower().replace(" ", "-"))

        result.reports = [{
            "date":    result.last_seen,
            "summary": (f"Feodo Tracker — {mw or 'Botnet'} C2 server"
                        f" · Status: {status.upper()}"
                        + (f" · Port {port}" if port else "")),
            "source":   "feodotracker",
            "category": "threat",
            "verdict":  "malicious",
        }]
