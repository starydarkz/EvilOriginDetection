"""
criminalip.py — Criminal IP connector.
Supports: IP, Domain
Categories: host_info · ports · threat · abuse
Docs: https://www.criminalip.io/developer/api

GET /v1/ip/summary — returns:
  score{inbound,outbound} (0-5 scale)
  tags{is_vpn,is_cloud,is_tor,is_proxy,is_hosting,is_mobile,is_darkweb,is_scanner,is_snort}
  issues{same fields}
  port{data:[{port, protocol, socket, app_name, app_type, ...}]}
  country, city, org_name, as_no, as_name, isp
  dangerous_info{is_dangerous}

GET /v1/domain/summary — returns:
  classification, score{score}, country, org_name, registrar, tags[]
"""
from app.models import IOCType
from app.parser import ParsedIOC
from .base import BaseConnector, NormalizedResult
from typing import ClassVar

BASE = "https://api.criminalip.io/v1"


class CriminalIPConnector(BaseConnector):
    SOURCE_NAME     = "criminalip"
    SUPPORTED_TYPES = {IOCType.ip, IOCType.domain}
    DATA_CATEGORIES: ClassVar[set[str]] = {"host_info", "ports", "threat", "abuse"}

    async def _fetch(self, ioc: ParsedIOC) -> dict:
        headers = {"x-api-key": self.api_key}
        async with self._client(headers) as c:
            if ioc.type == IOCType.ip:
                r = await c.get(f"{BASE}/ip/summary", params={"ip": ioc.value})
            else:
                r = await c.get(f"{BASE}/domain/summary", params={"query": ioc.value})

            if r.status_code == 404:
                return {"_not_found": True}
            if r.status_code == 402:
                raise Exception("Criminal IP: out of credits")
            if r.status_code == 401:
                raise Exception("Criminal IP: invalid API key")
            if r.status_code == 400:
                return {"_bad_request": True}

            r.raise_for_status()
            data = r.json()

            # Some versions wrap in {"status":"success","data":{...}}
            if isinstance(data.get("data"), dict):
                inner = data["data"]
                return {**inner, "_api_status": data.get("status", "")}

            return data

    def normalize(self, raw: dict, ioc: ParsedIOC,
                  result: NormalizedResult) -> None:
        if raw.get("_not_found") or raw.get("_bad_request"):
            result.verdict_hint = "unknown"
            return

        if ioc.type == IOCType.ip:
            self._normalize_ip(raw, result)
        else:
            self._normalize_domain(raw, result)

    def _normalize_ip(self, raw: dict, result: NormalizedResult) -> None:
        # ── Score → 0-100 ─────────────────────────────────────────
        score_obj = raw.get("score", {}) or {}
        inbound   = score_obj.get("inbound",  0) or 0
        outbound  = score_obj.get("outbound", 0) or 0

        def to_pct(v):
            try:
                v = float(v)
                return int(v * 20) if v <= 5 else int(min(v, 100))
            except (TypeError, ValueError):
                return 0

        result.abuse_score = max(to_pct(inbound), to_pct(outbound))

        # ── Host info ─────────────────────────────────────────────
        result.country = raw.get("country") or raw.get("country_code")
        result.city    = raw.get("city")
        result.org     = raw.get("org_name") or raw.get("as_name") or raw.get("isp")
        asn_raw        = raw.get("as_no") or raw.get("asn", "")
        result.asn     = str(asn_raw) if asn_raw else None

        # ── Boolean flags ─────────────────────────────────────────
        tags_obj   = raw.get("tags",   {}) or {}
        issues_obj = raw.get("issues", {}) or {}

        def flag(key):
            return bool(tags_obj.get(key) or issues_obj.get(key))

        result.is_vpn = flag("is_vpn")
        result.is_tor = flag("is_tor")

        # ── Tags from infrastructure flags ─────────────────────────
        tag_map = {
            "is_vpn":      "VPN",
            "is_cloud":    "Cloud",
            "is_tor":      "Tor",
            "is_proxy":    "Proxy",
            "is_hosting":  "Hosting",
            "is_mobile":   "Mobile",
            "is_darkweb":  "Darkweb",
            "is_scanner":  "Scanner",
            "is_snort":    "Snort",
        }
        result.tags = [label for key, label in tag_map.items() if flag(key)]

        # ── Ports + services from port.data[] ─────────────────────
        port_data = (raw.get("port") or {}).get("data", []) or []
        result.ports    = []
        result.services = {}

        for p in port_data:
            if not isinstance(p, dict):
                continue
            port_num = p.get("port")
            if not port_num:
                continue
            try:
                port_int = int(port_num)
            except (ValueError, TypeError):
                continue

            result.ports.append(port_int)

            # Build service label from app_name or protocol
            app_name  = p.get("app_name", "")
            app_type  = p.get("app_type", "")
            protocol  = p.get("protocol", "") or p.get("socket", "")
            svc_parts = [s for s in [app_name, app_type] if s and s.lower() not in ("unknown", "")]
            if svc_parts:
                result.services[port_int] = " / ".join(svc_parts[:2])
            elif protocol:
                result.services[port_int] = protocol.upper()

        result.ports = sorted(set(result.ports))[:15]

        # ── Verdict ────────────────────────────────────────────────
        danger = (raw.get("dangerous_info") or {}).get("is_dangerous", False)
        sc     = result.abuse_score or 0
        result.verdict_hint = (
            "malicious"  if danger or sc >= 60 else
            "suspicious" if sc >= 40             else
            "clean"      if sc == 0              else
            "unknown"
        )

        # ── Reports for timeline ───────────────────────────────────
        result.reports = []
        if result.tags or sc > 0:
            detail = f"Risk score {sc}/100"
            if result.tags:
                detail += f" · {', '.join(result.tags[:4])}"
            result.reports.append({
                "date":     None,
                "summary":  f"Criminal IP — {detail}",
                "source":   "criminalip",
                "category": "threat" if danger else "host_info",
            })

    def _normalize_domain(self, raw: dict, result: NormalizedResult) -> None:
        result.org     = raw.get("org_name") or raw.get("registrar")
        result.country = raw.get("country")

        score_obj    = raw.get("score", {}) or {}
        domain_score = score_obj.get("score") or 0
        try:
            s = float(domain_score)
            result.abuse_score = int(s * 20) if s <= 5 else int(min(s, 100))
        except (TypeError, ValueError):
            result.abuse_score = 0

        classified = (raw.get("classification") or "").lower()
        sc = result.abuse_score or 0
        result.verdict_hint = (
            "malicious"  if classified in ("malicious", "critical") or sc >= 75 else
            "suspicious" if classified in ("moderate", "high") or sc >= 40       else
            "clean"      if classified in ("safe", "low") or sc == 0             else
            "unknown"
        )
        result.tags = list(raw.get("tags", []) or [])
