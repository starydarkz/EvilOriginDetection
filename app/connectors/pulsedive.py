"""
pulsedive.py — Pulsedive threat intelligence connector.
Supports: IP, Domain, Hash, URL
Docs: https://pulsedive.com/api/

Purpose: Host information (like Shodan) — ports, services, geo,
         DNS records, WHOIS, feeds/pulses that reference this indicator.

Web URL: https://pulsedive.com/indicator/VALUE
API:     GET /api/info.php?indicator=VALUE&pretty=0&key=APIKEY
"""
from app.models import IOCType
from app.parser import ParsedIOC
from .base import BaseConnector, NormalizedResult

BASE = "https://pulsedive.com/api"


class PulsediveConnector(BaseConnector):
    SOURCE_NAME     = "pulsedive"
    SUPPORTED_TYPES = {IOCType.ip, IOCType.domain, IOCType.hash, IOCType.url}

    async def _fetch(self, ioc: ParsedIOC) -> dict:
        params = {"indicator": ioc.value, "pretty": "0", "get": "indicator,properties"}
        if self.api_key:
            params["key"] = self.api_key

        async with self._client() as c:
            r = await c.get(f"{BASE}/info.php", params=params)

            if r.status_code == 404:
                return {"error": "not_found"}
            if r.status_code == 400:
                return {"error": "bad_request"}
            if r.status_code == 429:
                raise Exception("Pulsedive rate limit exceeded")

            r.raise_for_status()
            data = r.json()

            # Fetch linked indicators for correlation
            iid = data.get("iid")
            if iid:
                try:
                    linked = await c.get(
                        f"{BASE}/linked.php",
                        params={
                            "iid":    iid,
                            "pretty": "0",
                            "type":   "indicator",
                            **({"key": self.api_key} if self.api_key else {})
                        }
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

        # Risk — informational, not the main signal
        risk = (raw.get("risk") or "unknown").lower()
        result.verdict_hint = (
            "malicious"  if risk in ("high", "critical")  else
            "suspicious" if risk in ("medium", "moderate") else
            "clean"      if risk in ("low", "none", "minimal") else
            "unknown"
        )

        # ── Properties (the main host info) ───────────────────────
        props = raw.get("properties", {}) or {}

        # Geo
        geo = props.get("geo", {}) or {}
        result.country = geo.get("country")
        result.city    = geo.get("city")
        result.org     = geo.get("org")
        result.asn     = geo.get("asn") or geo.get("asnum")

        # Ports / services
        port_data = props.get("port", []) or []
        result.ports = []
        for p in port_data:
            if isinstance(p, dict):
                port_num = p.get("port") or p.get("value")
            else:
                port_num = p
            if port_num and str(port_num).isdigit():
                result.ports.append(int(port_num))
        result.ports = result.ports[:15]

        # Technologies / header info
        header_data = props.get("header", []) or []
        result.technologies = []
        for h in header_data:
            if isinstance(h, dict):
                val = h.get("value", "")
                if val and len(val) < 50:
                    result.technologies.append(val)
            elif isinstance(h, str):
                result.technologies.append(h)
        result.technologies = result.technologies[:8]

        # DNS records (for domains)
        dns_data = props.get("dns", {}) or {}
        if dns_data:
            result.dns_records = dns_data

        # WHOIS data
        whois = props.get("whois", {}) or {}
        if not result.org and whois.get("org"):
            result.org = whois.get("org")
        if whois.get("registrar"):
            result.registrar = whois.get("registrar")
        if whois.get("created"):
            result.creation_date = whois.get("created")
        if whois.get("expires"):
            result.expiry_date = whois.get("expires")

        # ── Feeds / pulses referencing this indicator ──────────────
        feeds = raw.get("feeds", []) or []
        result.pulse_count = len(feeds)

        # ── Tags from threats ──────────────────────────────────────
        threats = raw.get("attributes", {}).get("threats", []) or []
        result.tags = [
            (t if isinstance(t, str) else t.get("name", str(t)))
            for t in threats
        ][:10]

        # ── Linked indicators (for graph) ──────────────────────────
        # Stored in raw for graph router — IPs, domains linked to this IOC
        linked = raw.get("_linked", {}) or {}
        linked_indicators = []
        for item in (linked.get("indicators") or [])[:10]:
            itype = item.get("type", "")
            ival  = item.get("indicator", "")
            if ival and itype in ("ip", "domain", "url", "email"):
                linked_indicators.append({
                    "value": ival,
                    "type":  itype,
                })
        if linked_indicators:
            raw["_linked_iocs"] = linked_indicators
