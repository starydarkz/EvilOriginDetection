"""
pulsedive.py — Pulsedive threat intelligence connector.
Supports: IP, Domain, Hash, URL
Docs: https://pulsedive.com/api/
"""
from app.models import IOCType
from app.parser import ParsedIOC
from .base import BaseConnector, NormalizedResult

BASE = "https://pulsedive.com/api"


class PulsediveConnector(BaseConnector):
    SOURCE_NAME     = "pulsedive"
    SUPPORTED_TYPES = {IOCType.ip, IOCType.domain, IOCType.hash, IOCType.url}

    async def _fetch(self, ioc: ParsedIOC) -> dict:
        params = {"indicator": ioc.value, "key": self.api_key, "pretty": "0"}
        async with self._client() as c:
            r = await c.get(f"{BASE}/info.php", params=params)
            r.raise_for_status()
            return r.json()

    def normalize(self, raw: dict, ioc: ParsedIOC, result: NormalizedResult) -> None:
        result.tags          = raw.get("attributes", {}).get("threats", [])
        risk                 = raw.get("risk", "unknown").lower()
        result.verdict_hint  = ("malicious"  if risk in ("high", "critical") else
                                "suspicious" if risk == "medium" else
                                "clean"      if risk in ("low", "none") else "unknown")
        props = raw.get("properties", {}).get("geo", {})
        result.country       = props.get("country")
        result.org           = props.get("org")
        result.pulse_count   = len(raw.get("feeds", []))
