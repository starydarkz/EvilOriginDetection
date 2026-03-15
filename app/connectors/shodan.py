"""
shodan.py — Shodan host lookup connector.
Supports: IP only.
Docs: https://developer.shodan.io/api
"""
from app.models import IOCType
from app.parser import ParsedIOC
from .base import BaseConnector, NormalizedResult

BASE = "https://api.shodan.io"


class ShodanConnector(BaseConnector):
    SOURCE_NAME     = "shodan"
    SUPPORTED_TYPES = {IOCType.ip}

    async def _fetch(self, ioc: ParsedIOC) -> dict:
        async with self._client() as c:
            r = await c.get(
                f"{BASE}/shodan/host/{ioc.value}",
                params={"key": self.api_key}
            )
            r.raise_for_status()
            return r.json()

    def normalize(self, raw: dict, ioc: ParsedIOC, result: NormalizedResult) -> None:
        result.ports      = raw.get("ports", [])
        result.hostnames  = raw.get("hostnames", [])
        result.org        = raw.get("org")
        result.isp        = raw.get("isp")
        result.country    = raw.get("country_name") or raw.get("country_code")
        result.city       = raw.get("city")
        result.asn        = raw.get("asn")
        result.last_seen  = raw.get("last_update")
        result.tags       = raw.get("tags", [])

        # Collect vulnerability CVEs from banners
        vulns = list((raw.get("vulns") or {}).keys())
        if vulns:
            result.tags.extend(vulns[:5])
            result.verdict_hint = "suspicious"

        # Collect technologies from banners
        techs = set()
        for item in raw.get("data", []):
            if item.get("product"):
                techs.add(item["product"])
        result.technologies = list(techs)[:10]
