"""abuseipdb.py — AbuseIPDB connector. Supports: IP only."""
from app.models import IOCType
from app.parser import ParsedIOC
from .base import BaseConnector, NormalizedResult

BASE = "https://api.abuseipdb.com/api/v2"


class AbuseIPDBConnector(BaseConnector):
    SOURCE_NAME     = "abuseipdb"
    SUPPORTED_TYPES = {IOCType.ip}

    async def _fetch(self, ioc: ParsedIOC) -> dict:
        params = {"ipAddress": ioc.value, "maxAgeInDays": "90", "verbose": ""}
        async with self._client({"Key": self.api_key, "Accept": "application/json"}) as c:
            r = await c.get(f"{BASE}/check", params=params)
            r.raise_for_status()
            return r.json()

    def normalize(self, raw: dict, ioc: ParsedIOC, result: NormalizedResult) -> None:
        d = raw.get("data", {})
        result.abuse_score  = d.get("abuseConfidenceScore")
        result.country      = d.get("countryCode")
        result.isp          = d.get("isp")
        result.org          = d.get("domain")
        result.usage_type   = d.get("usageType")
        result.is_tor       = d.get("isTor", False)
        result.last_seen    = d.get("lastReportedAt")
        score = result.abuse_score or 0
        result.verdict_hint = ("malicious" if score >= 75 else
                               "suspicious" if score >= 25 else "clean")
