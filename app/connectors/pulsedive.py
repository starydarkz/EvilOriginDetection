"""
pulsedive.py — Pulsedive threat intelligence connector.
Supports: IP, Domain, Hash, URL
Docs: https://pulsedive.com/api/

Also fetches screenshot via the Pulsedive indicator page screenshot if available.
Correct web URL: https://pulsedive.com/indicator/VALUE (no ?ioc= param)
"""
from app.models import IOCType
from app.parser import ParsedIOC
from .base import BaseConnector, NormalizedResult

BASE = "https://pulsedive.com/api"


class PulsediveConnector(BaseConnector):
    SOURCE_NAME     = "pulsedive"
    SUPPORTED_TYPES = {IOCType.ip, IOCType.domain, IOCType.hash, IOCType.url}

    async def _fetch(self, ioc: ParsedIOC) -> dict:
        params = {"indicator": ioc.value, "pretty": "0"}
        if self.api_key:
            params["key"] = self.api_key

        async with self._client() as c:
            r = await c.get(f"{BASE}/info.php", params=params)

            if r.status_code == 404:
                return {"error": "not_found", "risk": "unknown"}
            if r.status_code == 400:
                return {"error": "bad_request", "risk": "unknown"}
            if r.status_code == 429:
                raise Exception("Pulsedive rate limit exceeded")

            r.raise_for_status()
            data = r.json()

            # Fetch linked data (ports, redirects, related indicators)
            iid = data.get("iid")
            if iid:
                try:
                    linked = await c.get(
                        f"{BASE}/linked.php",
                        params={"iid": iid, "pretty": "0",
                                **({"key": self.api_key} if self.api_key else {})}
                    )
                    if linked.status_code == 200:
                        data["_linked"] = linked.json()
                except Exception:
                    pass

            return data

    def normalize(self, raw: dict, ioc: ParsedIOC,
                  result: NormalizedResult) -> None:
        if raw.get("error") in ("not_found", "bad_request"):
            result.verdict_hint = "unknown"
            return

        risk = (raw.get("risk") or "unknown").lower()
        result.verdict_hint = (
            "malicious"  if risk in ("high", "critical", "malicious") else
            "suspicious" if risk in ("medium", "moderate")             else
            "clean"      if risk in ("low", "none", "minimal", "none") else
            "unknown"
        )

        # Tags — combine threats + risk factors
        threats = raw.get("attributes", {}).get("threats", []) or []
        result.tags = [
            t if isinstance(t, str) else t.get("name", str(t))
            for t in threats
        ][:10]

        # Geo
        props = raw.get("properties", {}) or {}
        geo   = props.get("geo", {}) or {}
        result.country = geo.get("country")
        result.org     = geo.get("org")

        # Ports from properties
        port_list = props.get("port", []) or []
        result.ports = [
            int(p) for p in port_list
            if str(p).isdigit()
        ][:10]

        # Redirects from linked data
        linked = raw.get("_linked", {}) or {}
        redirects = []
        for item in (linked.get("indicators", []) or []):
            if item.get("type") == "url":
                redirects.append(item.get("indicator", ""))
        if redirects:
            result.tags.append(f"redirects:{len(redirects)}")

        # Pulse / feed count
        feeds = raw.get("feeds", []) or []
        result.pulse_count = len(feeds)
