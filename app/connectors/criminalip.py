"""
criminalip.py — Criminal IP connector.
Supports: IP, Domain, URL
Docs: https://www.criminalip.io/developer/api
"""
from app.models import IOCType
from app.parser import ParsedIOC
from .base import BaseConnector, NormalizedResult

BASE = "https://api.criminalip.io/v1"


class CriminalIPConnector(BaseConnector):
    SOURCE_NAME     = "criminalip"
    SUPPORTED_TYPES = {IOCType.ip, IOCType.domain, IOCType.url}

    async def _fetch(self, ioc: ParsedIOC) -> dict:
        headers = {"x-api-key": self.api_key}
        async with self._client(headers) as c:
            if ioc.type == IOCType.ip:
                r = await c.get(f"{BASE}/ip/summary", params={"ip": ioc.value})
            elif ioc.type == IOCType.domain:
                r = await c.get(f"{BASE}/domain/summary", params={"query": ioc.value})
            else:
                r = await c.get(f"{BASE}/url/summary", params={"url": ioc.value})
            r.raise_for_status()
            return r.json()

    def normalize(self, raw: dict, ioc: ParsedIOC, result: NormalizedResult) -> None:
        score = raw.get("score", {})
        result.abuse_score  = score.get("inbound") or score.get("outbound")
        result.country      = raw.get("country")
        result.org          = raw.get("org_name") or raw.get("as_name")
        result.is_vpn       = raw.get("is_vpn", False)
        result.is_tor       = raw.get("is_tor", False)
        result.tags         = raw.get("tags", [])
        danger = (raw.get("dangerous_info") or {}).get("is_dangerous", False)
        result.verdict_hint = "malicious" if danger else "unknown"
