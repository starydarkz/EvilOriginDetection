"""
criminalip.py — Criminal IP connector.
Supports: IP, Domain
Categories: host_info · ports · threat · abuse · relations

Uses TWO endpoints:
  GET /v1/asset/ip/report  — full report (preferred)
  GET /v1/ip/summary       — fallback

KEY STRUCTURAL DIFFERENCES between the two endpoints:
  Field       Report endpoint          Summary endpoint
  ──────────  ──────────────────────── ──────────────────────
  flags       "issue"   (singular)     "issues" (plural)
  tags        "tag"     (singular)     "tags"   (plural, dict)
  tag format  {data:[{tag_name:...}]}  {is_vpn:True,...}
  ports       "current_opened_port"    "port"
  score       inbound_score (float)    inbound (int 0-5)
"""
from app.models import IOCType
from app.parser import ParsedIOC
from .base import BaseConnector, NormalizedResult
from typing import ClassVar

BASE = "https://api.criminalip.io/v1"


class CriminalIPConnector(BaseConnector):
    SOURCE_NAME     = "criminalip"
    SUPPORTED_TYPES = {IOCType.ip, IOCType.domain}
    DATA_CATEGORIES: ClassVar[set[str]] = {
        "host_info", "ports", "threat", "abuse", "relations"
    }
    TIMEOUT = 20.0

    async def _fetch(self, ioc: ParsedIOC) -> dict:
        headers = {"x-api-key": self.api_key}
        async with self._client(headers) as c:
            if ioc.type == IOCType.domain:
                r = await c.get(f"{BASE}/domain/summary",
                                params={"query": ioc.value})
                self._handle_status(r)
                return self._unwrap(r.json(), "summary")

            # Try full report first
            r = await c.get(f"{BASE}/asset/ip/report",
                            params={"ip": ioc.value, "full": "true"})
            if r.status_code == 200:
                return self._unwrap(r.json(), "report")

            # Fallback to summary
            r2 = await c.get(f"{BASE}/ip/summary",
                             params={"ip": ioc.value})
            self._handle_status(r2)
            return self._unwrap(r2.json(), "summary")

    def _handle_status(self, r) -> None:
        if r.status_code == 404: raise Exception("_not_found")
        if r.status_code == 402: raise Exception("Criminal IP: out of credits")
        if r.status_code == 401: raise Exception("Criminal IP: invalid API key")
        if r.status_code == 400: raise Exception("_bad_request")
        r.raise_for_status()

    def _unwrap(self, data: dict, endpoint: str) -> dict:
        """Unwrap nested data key if present, inject endpoint marker."""
        if isinstance(data.get("data"), dict):
            inner = data["data"]
            inner["_endpoint"] = endpoint
            return inner
        data["_endpoint"] = endpoint
        return data

    def normalize(self, raw: dict, ioc: ParsedIOC,
                  result: NormalizedResult) -> None:
        if "_not_found" in str(raw.get("_endpoint", "")) or \
           raw.get("status") == "fail":
            result.verdict_hint = "unknown"
            return

        if ioc.type == IOCType.ip:
            self._normalize_ip(raw, result)
        else:
            self._normalize_domain(raw, result)

    def _normalize_ip(self, raw: dict, result: NormalizedResult) -> None:
        endpoint = raw.get("_endpoint", "summary")

        # ── Score ─────────────────────────────────────────────────
        score = raw.get("score", {}) or {}
        if endpoint == "report" and score.get("inbound_score") is not None:
            # Report: inbound_score is already 0-100 float
            result.abuse_score = int(min(float(score["inbound_score"]), 100))
        else:
            # Summary: inbound/outbound are int 0-5
            result.abuse_score = max(
                self._to_pct(score.get("inbound",  0)),
                self._to_pct(score.get("outbound", 0)),
            )

        # ── Host info ─────────────────────────────────────────────
        whois_data = ((raw.get("whois") or {}).get("data") or [{}])
        whois = whois_data[0] if isinstance(whois_data, list) and whois_data else {}
        result.country = raw.get("country") or raw.get("country_code") or whois.get("country_code")
        result.city    = raw.get("city")
        result.org     = (raw.get("org_name") or whois.get("org_name") or raw.get("as_name"))
        asn = raw.get("as_no") or whois.get("as_no") or raw.get("asn")
        result.asn = str(asn) if asn else None

        # Hostname → add to hostnames list
        hostname = raw.get("hostname") or raw.get("representative_domain")
        if hostname:
            result.hostnames = [hostname]

        # ── Infrastructure flags ───────────────────────────────────
        # Report uses "issue" (singular), Summary uses "issues" (plural)
        issue_obj = raw.get("issue") or raw.get("issues") or {}

        def flag(key, alt_key=None):
            v = issue_obj.get(key)
            if v is None and alt_key:
                v = issue_obj.get(alt_key)
            return bool(v) if v is not None else None

        result.is_vpn     = flag("is_vpn")
        result.is_tor     = flag("is_tor")
        result.is_proxy   = flag("is_proxy")
        result.is_hosting = flag("is_hosting")
        result.is_mobile  = flag("is_mobile")
        result.is_darkweb = flag("is_darkweb")
        result.is_cloud   = flag("is_cloud")
        # scanner key is inconsistent between endpoints
        scanner_val = issue_obj.get("is_scanning_ip") \
                      if "is_scanning_ip" in issue_obj \
                      else issue_obj.get("is_scanner")
        result.is_scanner = bool(scanner_val) if scanner_val is not None else None

        # ── Tags ──────────────────────────────────────────────────
        # Report: raw["tag"] = {"data": [{"tag_name": "SSL VPN"}, ...]}
        # Summary: raw["tags"] = {"is_vpn": True, ...}
        tag_block = raw.get("tag")
        tags_dict  = raw.get("tags")
        infra_tags = []

        if isinstance(tag_block, dict) and "data" in tag_block:
            # Report endpoint — named tags
            for t in (tag_block.get("data") or []):
                if isinstance(t, dict) and t.get("tag_name"):
                    infra_tags.append(t["tag_name"])
        elif isinstance(tags_dict, dict):
            # Summary endpoint — boolean flags as tags
            flag_label = {
                "is_vpn": "VPN", "is_cloud": "Cloud", "is_tor": "Tor",
                "is_proxy": "Proxy", "is_hosting": "Hosting",
                "is_mobile": "Mobile", "is_darkweb": "Darkweb",
                "is_scanning_ip": "Scanner",
            }
            for k, label in flag_label.items():
                if tags_dict.get(k):
                    infra_tags.append(label)

        # Also add infra flags as tags from issue block for summary endpoint
        if not infra_tags and issue_obj:
            flag_label = {
                "is_vpn": "VPN", "is_cloud": "Cloud", "is_tor": "Tor",
                "is_proxy": "Proxy", "is_hosting": "Hosting",
                "is_mobile": "Mobile", "is_darkweb": "Darkweb",
                "is_scanning_ip": "Scanner",
            }
            for k, label in flag_label.items():
                if issue_obj.get(k):
                    infra_tags.append(label)

        result.tags = infra_tags

        # ── Ports + services + banners ────────────────────────────
        port_block = (raw.get("current_opened_port")
                      or raw.get("port") or {})
        result.ports    = []
        result.services = {}
        banners         = {}

        for p in (port_block.get("data") or []):
            if not isinstance(p, dict): continue
            port_num = p.get("port") or p.get("open_port_no")
            try: port_int = int(port_num)
            except (TypeError, ValueError): continue

            result.ports.append(port_int)

            app = (p.get("app_name", "") or "").strip()
            ver = (p.get("app_version", "") or p.get("version", "")).strip()
            typ = (p.get("app_type", "") or "").strip()
            prt = (p.get("protocol", "") or p.get("socket", "")).strip()

            svc = " ".join(s for s in [app, ver]
                           if s and s.lower() not in ("unknown", "n/a", "")).strip()
            if svc:
                result.services[port_int] = svc
            elif typ and typ.lower() not in ("unknown", ""):
                result.services[port_int] = typ
            elif prt:
                result.services[port_int] = prt.upper()

            banner = (p.get("banner") or p.get("banner_data") or "").strip()
            if banner:
                banners[port_int] = banner[:300]

        result.ports = sorted(set(result.ports))[:20]

        # Store banners in raw for graph router to pick up
        if banners:
            raw["_banners"] = banners

        # ── CVEs ──────────────────────────────────────────────────
        vuln_block = raw.get("vulnerability", {}) or {}
        vuln_port_map = {}  # {port: [{"cve_id":..., "cvss":..., "summary":...}]}
        for v in (vuln_block.get("data") or []):
            if not isinstance(v, dict) or not v.get("cve_id"):
                continue
            port = v.get("port") or v.get("infer_port")
            cve  = {
                "cve_id":  v.get("cve_id"),
                "cvss":    v.get("cvss_score") or v.get("cvss"),
                "severity":v.get("severity") or ("critical" if (v.get("cvss_score") or 0) >= 9
                           else "high" if (v.get("cvss_score") or 0) >= 7
                           else "medium" if (v.get("cvss_score") or 0) >= 4 else "low"),
                "summary": (v.get("summary") or v.get("description") or "")[:120],
            }
            key = int(port) if port and str(port).isdigit() else 0
            vuln_port_map.setdefault(key, []).append(cve)
        all_cves: list = []
        if vuln_port_map:
            # Store in raw for results.py to extract
            raw["_vuln_ports"] = {str(k): v for k, v in vuln_port_map.items()}
            # Also add top CVE IDs to tags
            all_cves = [c["cve_id"] for port_cves in vuln_port_map.values() for c in port_cves]
            result.tags.extend(all_cves[:5])

        # ── Connected domains → graph ──────────────────────────────
        domain_block = raw.get("domain", {}) or {}
        conn_domains = [
            d.get("domain_name") or d.get("domain", "")
            for d in (domain_block.get("data") or [])
            if isinstance(d, dict)
        ]
        conn_domains = [d for d in conn_domains if d]
        if conn_domains:
            raw["_connected_domains"] = conn_domains[:10]

        # ── SSL Certificate ────────────────────────────────────────
        ssl = raw.get("ssl_certificate") or {}
        if isinstance(ssl, dict) and ssl.get("count"):
            ssl_tag = f"SSL:{ssl['count']}"
            if ssl.get("is_self_signed"):
                ssl_tag += " (self-signed)"
            result.tags.append(ssl_tag)

        # ── Verdict ────────────────────────────────────────────────
        danger = (raw.get("dangerous_info") or {}).get("is_dangerous", False)
        sc     = result.abuse_score or 0
        result.verdict_hint = (
            "malicious"  if danger or sc >= 60 or bool(all_cves) else
            "suspicious" if sc >= 40 else
            "clean"      if sc == 0  else "unknown"
        )

        # ── Reports for timeline ───────────────────────────────────
        result.reports = []
        if sc > 0 or result.tags:
            detail = f"Risk score {sc}/100"
            named_tags = [t for t in result.tags
                          if not t.startswith("CVE-") and not t.startswith("SSL:")]
            if named_tags:
                detail += f" · {', '.join(named_tags[:4])}"
            result.reports.append({
                "date": None,
                "summary": f"Criminal IP — {detail}",
                "source": "criminalip",
                "category": "threat" if danger else "host_info",
            })
        if all_cves:
            result.reports.append({
                "date": None,
                "summary": f"Vulnerabilities: {', '.join(all_cves[:4])}",
                "source": "criminalip",
                "category": "threat",
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
            "malicious"  if classified in ("malicious","critical") or sc >= 75 else
            "suspicious" if classified in ("moderate","high")      or sc >= 40 else
            "clean"      if classified in ("safe","low")           or sc == 0  else
            "unknown"
        )
        result.tags = list(raw.get("tags", []) or [])

    @staticmethod
    def _to_pct(v) -> int:
        try:
            v = float(v)
            return int(v * 20) if v <= 5 else int(min(v, 100))
        except (TypeError, ValueError):
            return 0
