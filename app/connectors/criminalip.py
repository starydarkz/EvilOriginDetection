"""
criminalip.py — Criminal IP connector.
Supports: IP, Domain, URL
Docs: https://www.criminalip.io/developer/api

Verified API endpoints:
- IP:     GET /v1/ip/summary?ip=VALUE
- Domain: GET /v1/domain/summary?query=VALUE
- URL:    GET /v1/url/summary?url=VALUE

Web UI links (correct):
- IP:     https://search.criminalip.io/asset/search?query=ip%3AVALUE
- Domain: https://search.criminalip.io/asset/search?query=domain%3AVALUE
- URL:    https://search.criminalip.io/asset/search?query=url%3AVALUE
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
                r = await c.get(
                    f"{BASE}/ip/summary",
                    params={"ip": ioc.value}
                )
            elif ioc.type == IOCType.domain:
                r = await c.get(
                    f"{BASE}/domain/summary",
                    params={"query": ioc.value}
                )
            else:  # URL
                r = await c.get(
                    f"{BASE}/url/summary",
                    params={"url": ioc.value}
                )

            # 404 = not in Criminal IP database
            if r.status_code == 404:
                return {"status": "not_found"}
            # 402 = out of credits
            if r.status_code == 402:
                raise Exception("Criminal IP: out of credits")

            r.raise_for_status()
            return r.json()

    def normalize(self, raw: dict, ioc: ParsedIOC,
                  result: NormalizedResult) -> None:
        if raw.get("status") == "not_found":
            result.verdict_hint = "unknown"
            return

        # IP response structure
        if ioc.type == IOCType.ip:
            score = raw.get("score", {})
            inbound  = score.get("inbound",  0) or 0
            outbound = score.get("outbound", 0) or 0
            result.abuse_score = max(inbound, outbound)
            result.country     = raw.get("country")
            result.city        = raw.get("city")
            result.org         = raw.get("org_name") or raw.get("as_name")
            result.asn         = str(raw.get("as_no", "")) or None
            result.is_vpn      = bool(raw.get("is_vpn"))
            result.is_tor      = bool(raw.get("is_tor"))
            result.ports       = [
                p.get("port") for p in (raw.get("port", {}).get("data", []) or [])
                if p.get("port")
            ][:10]

            # Tags from issues
            issues = raw.get("issues", {}) or {}
            tag_map = {
                "is_vpn":          "VPN",
                "is_tor":          "Tor",
                "is_proxy":        "Proxy",
                "is_cloud":        "Cloud",
                "is_scanning_ip":  "Scanner",
                "is_darkweb":      "Darkweb",
                "is_snort":        "Snort",
                "is_anonymous_vpn":"Anonymous VPN",
            }
            result.tags = [
                label for key, label in tag_map.items()
                if issues.get(key)
            ]

            danger = (raw.get("dangerous_info") or {}).get("is_dangerous", False)
            sc     = result.abuse_score or 0
            result.verdict_hint = (
                "malicious"  if danger or sc >= 75 else
                "suspicious" if sc >= 40              else
                "clean"      if sc == 0               else
                "unknown"
            )

        # Domain response
        elif ioc.type == IOCType.domain:
            result.org         = raw.get("org_name")
            result.country     = raw.get("country")
            classified = raw.get("classification", "")
            result.verdict_hint = (
                "malicious"  if classified in ("malicious", "high") else
                "suspicious" if classified == "medium"               else
                "clean"      if classified in ("safe", "low")        else
                "unknown"
            )
            result.tags = raw.get("tags", []) or []

        else:  # URL
            result.verdict_hint = "unknown"
            result.tags = raw.get("tags", []) or []
