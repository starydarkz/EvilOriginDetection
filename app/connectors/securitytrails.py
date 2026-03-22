"""
securitytrails.py — SecurityTrails connector.
Supports: IP, Domain
Categories: dns_whois · host_info
Docs: https://docs.securitytrails.com/reference

GET /v1/domain/{domain}
  current_dns: {a, aaaa, mx, ns, txt, soa} with values[]
  whois: {registrar, createdDate, expiresDate}
  subdomain_count (if available)

GET /v1/ips/nearby/{ip}
  blocks: [{network, ...}]
"""
from app.models import IOCType
from app.parser import ParsedIOC
from .base import BaseConnector, NormalizedResult
from typing import ClassVar

BASE = "https://api.securitytrails.com/v1"


class SecurityTrailsConnector(BaseConnector):
    SOURCE_NAME     = "securitytrails"
    SUPPORTED_TYPES = {IOCType.ip, IOCType.domain}
    DATA_CATEGORIES: ClassVar[set[str]] = {"dns_whois", "host_info"}

    async def _fetch(self, ioc: ParsedIOC) -> dict:
        headers = {"APIKEY": self.api_key}
        async with self._client(headers) as c:
            if ioc.type == IOCType.domain:
                r = await c.get(f"{BASE}/domain/{ioc.value}")
            else:
                r = await c.get(f"{BASE}/ips/nearby/{ioc.value}")

            if r.status_code == 404:
                return {"_not_found": True}
            r.raise_for_status()
            return r.json()

    def normalize(self, raw: dict, ioc: ParsedIOC,
                  result: NormalizedResult) -> None:
        if raw.get("_not_found"):
            result.verdict_hint = "unknown"
            return

        if ioc.type == IOCType.domain:
            self._normalize_domain(raw, result)
        else:
            self._normalize_ip(raw, result)

    def _normalize_domain(self, raw: dict, result: NormalizedResult) -> None:
        # ── DNS records ───────────────────────────────────────────
        records_raw = raw.get("current_dns", {}) or {}
        # Normalize all record types to {"values": [...]} for consistent template rendering
        records = {}
        for rtype, rdata in records_raw.items():
            if isinstance(rdata, dict):
                vals = rdata.get("values") or rdata.get("records") or []
                if not vals:
                    # Flatten remaining scalar fields (e.g. soa.rname, soa.email)
                    scalars = [v for k, v in rdata.items()
                               if isinstance(v, str) and k not in ("type", "ttl")]
                    if scalars:
                        vals = [{"value": s} for s in scalars]
                records[rtype.upper()] = {"values": vals[:10]}
            elif isinstance(rdata, list):
                records[rtype.upper()] = {"values": rdata[:10]}
            elif isinstance(rdata, str):
                records[rtype.upper()] = {"values": [{"value": rdata}]}
        result.dns_records = records

        # IPs currently resolving to this domain
        a_records = records.get("a", {}).get("values", []) or []
        result.hostnames = [r.get("ip") for r in a_records if r.get("ip")]

        # ── WHOIS ─────────────────────────────────────────────────
        whois = raw.get("whois", {}) or {}
        result.registrar     = whois.get("registrar")
        result.creation_date = whois.get("createdDate")
        result.expiry_date   = whois.get("expiresDate")
        result.org           = whois.get("registrant", {}).get("organization") if isinstance(whois.get("registrant"), dict) else None

        # ── Reports for timeline ───────────────────────────────────
        result.reports = []
        if result.creation_date:
            result.reports.append({
                "date":     str(result.creation_date)[:10],
                "summary":  f"Domain registered"
                            + (f" via {result.registrar}" if result.registrar else ""),
                "source":   "securitytrails",
                "category": "dns_whois",
            })
        if result.expiry_date:
            result.reports.append({
                "date":     str(result.expiry_date)[:10],
                "summary":  f"Domain expires"
                            + (f" · registrar: {result.registrar}" if result.registrar else ""),
                "source":   "securitytrails",
                "category": "dns_whois",
            })
        if result.hostnames:
            result.reports.append({
                "date":     None,
                "summary":  f"Resolves to: {', '.join(result.hostnames[:4])}",
                "source":   "securitytrails",
                "category": "dns_whois",
            })

    def _normalize_ip(self, raw: dict, result: NormalizedResult) -> None:
        blocks = raw.get("blocks", []) or []
        result.network = blocks[0].get("network") if blocks else None
