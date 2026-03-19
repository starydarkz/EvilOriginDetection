"""
shodan.py — Shodan host lookup connector.
Supports: IP only.
Categories: host_info · ports
Docs: https://developer.shodan.io/api

Extracts from data[]:
  - port, transport (tcp/udp)
  - product + version → services dict
  - banner (first 200 chars)
  - vulns{} → CVE list
  - os detection
"""
from app.models import IOCType
from app.parser import ParsedIOC
from .base import BaseConnector, NormalizedResult
from typing import ClassVar

BASE = "https://api.shodan.io"


class ShodanConnector(BaseConnector):
    SOURCE_NAME     = "shodan"
    SUPPORTED_TYPES = {IOCType.ip}
    DATA_CATEGORIES: ClassVar[set[str]] = {"host_info", "ports"}

    async def _fetch(self, ioc: ParsedIOC) -> dict:
        async with self._client() as c:
            r = await c.get(
                f"{BASE}/shodan/host/{ioc.value}",
                params={"key": self.api_key}
            )
            if r.status_code == 404:
                return {"_not_found": True}
            if r.status_code == 403:
                # 403 on Shodan = IP blocked or plan restriction
                raise Exception("Shodan: access forbidden (check plan or IP restrictions)")
            r.raise_for_status()
            return r.json()

    def normalize(self, raw: dict, ioc: ParsedIOC,
                  result: NormalizedResult) -> None:
        if raw.get("_not_found"):
            result.verdict_hint = "unknown"
            return

        # ── Host info ─────────────────────────────────────────────
        result.hostnames = raw.get("hostnames", []) or []
        result.org       = raw.get("org")
        result.isp       = raw.get("isp")
        result.country   = raw.get("country_name") or raw.get("country_code")
        result.city      = raw.get("city")
        result.asn       = raw.get("asn")
        result.last_seen = raw.get("last_update")
        result.tags      = list(raw.get("tags", []) or [])

        # OS detection
        os_detected = raw.get("os")
        if os_detected:
            result.tags.append(f"os:{os_detected}")

        # ── Ports + services from data[] banners ──────────────────
        result.ports    = sorted(set(raw.get("ports", [])))
        result.services = {}
        result.technologies = []
        techs_seen = set()

        for item in raw.get("data", []):
            port      = item.get("port")
            transport = item.get("transport", "tcp").lower()
            product   = item.get("product", "")
            version   = item.get("version", "")

            if port:
                # Build service label: "nginx 1.18.0" or just "nginx"
                svc_parts = [p for p in [product, version] if p]
                svc_label = " ".join(svc_parts) if svc_parts else transport.upper()
                result.services[int(port)] = svc_label

                # Collect technologies (product names, deduped)
                if product and product.lower() not in techs_seen:
                    techs_seen.add(product.lower())
                    result.technologies.append(
                        f"{product} {version}".strip() if version else product
                    )

        result.technologies = result.technologies[:12]

        # ── Vulnerabilities → tags + verdict ─────────────────────
        vulns = list((raw.get("vulns") or {}).keys())
        if vulns:
            # Add CVEs as tags (top 5)
            result.tags.extend(vulns[:5])
            result.verdict_hint = "suspicious"
        else:
            result.verdict_hint = "unknown"

        # ── Reports for timeline ───────────────────────────────────
        # Shodan doesn't have dated events — last_update is the only date
        # We generate one timeline entry per meaningful service found
        result.reports = []
        if result.last_seen and result.ports:
            port_str = ", ".join(str(p) for p in result.ports[:8])
            suffix   = f" +{len(result.ports)-8} more" if len(result.ports) > 8 else ""
            result.reports.append({
                "date":     result.last_seen[:19],
                "summary":  f"Shodan indexed — {len(result.ports)} open port(s): {port_str}{suffix}",
                "source":   "shodan",
                "category": "host_info",
            })
        if vulns:
            result.reports.append({
                "date":     result.last_seen[:19] if result.last_seen else None,
                "summary":  f"Vulnerabilities detected: {', '.join(vulns[:5])}",
                "source":   "shodan",
                "category": "threat",
            })
