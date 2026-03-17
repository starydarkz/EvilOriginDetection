"""
pulsedive.py — Pulsedive threat intelligence connector.
Supports: IP, Domain, Hash, URL
Docs: https://pulsedive.com/api/

Notes:
- Endpoint is /api/info.php with ?indicator=VALUE&key=KEY
- 404 = indicator not found in Pulsedive (not an error, just unknown)
- 400 = bad request / invalid indicator format
"""
from app.models import IOCType
from app.parser import ParsedIOC
from .base import BaseConnector, NormalizedResult

BASE = "https://pulsedive.com/api"


class PulsediveConnector(BaseConnector):
    SOURCE_NAME     = "pulsedive"
    SUPPORTED_TYPES = {IOCType.ip, IOCType.domain, IOCType.hash, IOCType.url}

    async def _fetch(self, ioc: ParsedIOC) -> dict:
        params = {
            "indicator": ioc.value,
            "pretty":    "0",
        }
        if self.api_key:
            params["key"] = self.api_key

        async with self._client() as c:
            r = await c.get(f"{BASE}/info.php", params=params)

            # 404 = indicator not in Pulsedive database — not an error
            if r.status_code == 404:
                return {"error": "not_found", "risk": "unknown"}

            # 400 = invalid format for this indicator type
            if r.status_code == 400:
                return {"error": "bad_request", "risk": "unknown"}

            # 429 = rate limited
            if r.status_code == 429:
                raise Exception("Pulsedive rate limit exceeded")

            r.raise_for_status()
            return r.json()

    def normalize(self, raw: dict, ioc: ParsedIOC,
                  result: NormalizedResult) -> None:
        # Not found or error cases
        if raw.get("error") in ("not_found", "bad_request"):
            result.verdict_hint = "unknown"
            return

        risk = (raw.get("risk") or "unknown").lower()
        result.verdict_hint = (
            "malicious"  if risk in ("high", "critical", "malicious") else
            "suspicious" if risk in ("medium", "moderate")             else
            "clean"      if risk in ("low", "none", "minimal")         else
            "unknown"
        )

        # Tags from threats field
        threats = raw.get("attributes", {}).get("threats", [])
        if isinstance(threats, list):
            result.tags = [t if isinstance(t, str) else str(t) for t in threats]

        # Geo / network info
        props = raw.get("properties", {})
        geo   = props.get("geo", {}) if isinstance(props, dict) else {}
        result.country = geo.get("country")
        result.org     = geo.get("org")

        # Feed / pulse count
        feeds = raw.get("feeds", [])
        result.pulse_count = len(feeds) if isinstance(feeds, list) else 0
