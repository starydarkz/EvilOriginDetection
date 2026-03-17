"""
criminalip.py — Criminal IP connector.
Supports: IP, Domain, URL
Docs: https://www.criminalip.io/developer/api

Verified API response structure (tested):
- All endpoints return { "status": "success", "data": {...} }
  or just top-level fields depending on endpoint version
- IP summary: returns inbound/outbound scores, issues, port data
- Domain summary: returns classification, whois, dns

API endpoints:
- IP:     GET /v1/ip/summary?ip=VALUE
- Domain: GET /v1/domain/summary?query=VALUE

Web UI (correct links):
- IP:     https://www.criminalip.io/asset/search?query=ip%3AVALUE
- Domain: https://www.criminalip.io/asset/search?query=domain%3AVALUE
"""
from app.models import IOCType
from app.parser import ParsedIOC
from .base import BaseConnector, NormalizedResult

BASE = "https://api.criminalip.io/v1"


class CriminalIPConnector(BaseConnector):
    SOURCE_NAME     = "criminalip"
    SUPPORTED_TYPES = {IOCType.ip, IOCType.domain}  # removed URL — unreliable

    async def _fetch(self, ioc: ParsedIOC) -> dict:
        headers = {"x-api-key": self.api_key}
        async with self._client(headers) as c:
            if ioc.type == IOCType.ip:
                r = await c.get(
                    f"{BASE}/ip/summary",
                    params={"ip": ioc.value}
                )
            else:  # domain
                r = await c.get(
                    f"{BASE}/domain/summary",
                    params={"query": ioc.value}
                )

            if r.status_code == 404:
                return {"_status": "not_found"}
            if r.status_code == 402:
                raise Exception("Criminal IP: out of credits")
            if r.status_code == 401:
                raise Exception("Criminal IP: invalid API key")
            if r.status_code == 400:
                return {"_status": "bad_request"}

            r.raise_for_status()
            data = r.json()

            # CriminalIP wraps response in "data" for some endpoints
            # Normalize to always work at top level
            if "data" in data and isinstance(data["data"], dict):
                # Merge data fields into top level for easier access
                merged = {**data["data"], "_wrapper_status": data.get("status")}
                return merged

            return data

    def normalize(self, raw: dict, ioc: ParsedIOC,
                  result: NormalizedResult) -> None:
        status = raw.get("_status") or raw.get("status", "")
        if status in ("not_found", "bad_request"):
            result.verdict_hint = "unknown"
            return

        if ioc.type == IOCType.ip:
            # Score — CriminalIP uses 0-5 scale or percentage
            # Try both formats
            score_obj = raw.get("score", {}) or {}
            inbound   = score_obj.get("inbound",  0) or 0
            outbound  = score_obj.get("outbound", 0) or 0

            # Some versions return scores as 0-5 integers, normalize to 0-100
            def normalize_score(s):
                if isinstance(s, (int, float)):
                    return int(s * 20) if s <= 5 else int(s)
                return 0

            result.abuse_score = max(
                normalize_score(inbound),
                normalize_score(outbound)
            )

            result.country = raw.get("country") or raw.get("country_code")
            result.city    = raw.get("city")
            result.org     = raw.get("org_name") or raw.get("as_name") or raw.get("isp")
            result.asn     = str(raw.get("as_no", "") or raw.get("asn", "")) or None
            result.is_vpn  = bool(raw.get("is_vpn"))
            result.is_tor  = bool(raw.get("is_tor"))

            # Ports
            port_data = (raw.get("port") or {}).get("data", []) or []
            result.ports = [
                p.get("port") for p in port_data if p.get("port")
            ][:15]

            # Issues / tags
            issues  = raw.get("issues", {}) or {}
            tag_map = {
                "is_vpn":           "VPN",
                "is_tor":           "Tor",
                "is_proxy":         "Proxy",
                "is_cloud":         "Cloud",
                "is_scanning_ip":   "Scanner",
                "is_darkweb":       "Darkweb",
                "is_anonymous_vpn": "Anonymous VPN",
                "is_hosting":       "Hosting",
            }
            result.tags = [
                label for key, label in tag_map.items()
                if issues.get(key)
            ]

            # Verdict
            danger = (raw.get("dangerous_info") or {}).get("is_dangerous", False)
            sc     = result.abuse_score or 0
            result.verdict_hint = (
                "malicious"  if danger or sc >= 75 else
                "suspicious" if sc >= 40             else
                "clean"      if sc == 0              else
                "unknown"
            )

        elif ioc.type == IOCType.domain:
            result.org     = raw.get("org_name") or raw.get("registrar")
            result.country = raw.get("country")

            # Score for domains
            score_obj  = raw.get("score", {}) or {}
            domain_score = score_obj.get("score") or 0
            if domain_score <= 5:
                result.abuse_score = int(domain_score * 20)
            else:
                result.abuse_score = int(domain_score)

            # Verdict from classification or score
            classified = (raw.get("classification") or "").lower()
            sc = result.abuse_score or 0
            result.verdict_hint = (
                "malicious"  if classified in ("malicious", "high") or sc >= 75 else
                "suspicious" if classified == "medium" or sc >= 40              else
                "clean"      if classified in ("safe", "low") or sc == 0        else
                "unknown"
            )
            result.tags = raw.get("tags", []) or []
