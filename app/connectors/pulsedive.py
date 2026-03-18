"""
pulsedive.py — Pulsedive connector.
Supports: IP, Domain, Hash, URL
Docs: https://pulsedive.com/api/

Pulsedive API /info.php response structure:
{
  "iid": 123,
  "indicator": "8.8.8.8",
  "type": "ip",
  "risk": "none|low|medium|high|critical|unknown",
  "risk_recommended": "...",
  "retired": false,
  "stamp_added": "2018-...",
  "stamp_seen": "2023-...",
  "stamp_probed": "2023-...",
  "stamp_retired": null,
  "recent_activity": {...},
  "properties": {
    "geo": {"country": "US", "org": "AS15169 GOOGLE", "city": "...",
            "asn": "AS15169", "latitude": 37.4, "longitude": -122.0},
    "port": [{"port": 443, "protocol": "TCP/SSL"}, ...],
    "header": [{"attribute": "server", "value": "gws"}, ...],
    "dns":  {"A": ["..."], "MX": [...], ...},
    "whois": {"registrar": "...", "created": "...", "expires": "...", "org": "..."},
    "cert": [...],
    "http": {"status": 200, "title": "Google", "redirects": [...]},
  },
  "threats": [...],
  "feeds": [...],
  "comments": [...],
  "attributes": {"threats": [...], "feeds": [...]}
}

Source summary shown to user: just "X feeds" or "Scanned" — no raw field dumps.
"""
from app.models import IOCType
from app.parser import ParsedIOC
from .base import BaseConnector, NormalizedResult

BASE = "https://pulsedive.com/api"


class PulsediveConnector(BaseConnector):
    SOURCE_NAME     = "pulsedive"
    SUPPORTED_TYPES = {IOCType.ip, IOCType.domain, IOCType.hash, IOCType.url}
    DATA_CATEGORIES: ClassVar[set[str]] = {"host_info", "ports", "dns_whois", "threat", "web_osint", "relations"}

    async def _fetch(self, ioc: ParsedIOC) -> dict:
        params = {
            "indicator": ioc.value,
            "pretty":    "0",
            "get":       "indicator,properties,threats,feeds",
        }
        if self.api_key:
            params["key"] = self.api_key

        async with self._client() as c:
            r = await c.get(f"{BASE}/info.php", params=params)

            if r.status_code == 404:
                return {"_not_found": True}
            if r.status_code in (400, 422):
                return {"_bad_request": True}
            if r.status_code == 429:
                raise Exception("Pulsedive rate limit exceeded")

            r.raise_for_status()
            data = r.json()

            # Fetch linked indicators for graph correlation (best-effort)
            iid = data.get("iid")
            if iid:
                try:
                    linked_r = await c.get(
                        f"{BASE}/linked.php",
                        params={
                            "iid":    iid,
                            "type":   "indicator",
                            "pretty": "0",
                            **({"key": self.api_key} if self.api_key else {}),
                        },
                        timeout=8.0,
                    )
                    if linked_r.status_code == 200:
                        data["_linked"] = linked_r.json()
                except Exception:
                    pass

            return data

    def normalize(self, raw: dict, ioc: ParsedIOC,
                  result: NormalizedResult) -> None:
        if raw.get("_not_found") or raw.get("_bad_request"):
            result.verdict_hint = "unknown"
            return

        # ── Risk / verdict ─────────────────────────────────────────
        risk = (raw.get("risk") or raw.get("risk_recommended") or "unknown").lower()
        result.verdict_hint = (
            "malicious"  if risk in ("high", "critical")     else
            "suspicious" if risk in ("medium", "moderate")   else
            "clean"      if risk in ("none", "low", "minimal") else
            "unknown"
        )

        # ── Last seen timestamps ───────────────────────────────────
        result.last_seen = (
            raw.get("stamp_seen") or raw.get("stamp_probed")
        )

        # ── Properties block ───────────────────────────────────────
        props = raw.get("properties", {}) or {}

        # Geo
        geo = props.get("geo", {}) or {}
        result.country   = geo.get("country")
        result.city      = geo.get("city")
        result.latitude  = geo.get("latitude")
        result.longitude = geo.get("longitude")
        # org: prefer clean format without ASN prefix
        org_raw = geo.get("org", "")
        if org_raw:
            # "AS15169 GOOGLE" → strip ASN prefix
            parts = org_raw.split(" ", 1)
            result.org = parts[1] if (len(parts) > 1 and parts[0].startswith("AS")) else org_raw
        result.asn = geo.get("asn")  # e.g. "AS15169"

        # Ports — [{port: 443, protocol: "TCP/SSL"}, ...]
        port_entries = props.get("port", []) or []
        result.ports = []
        for p in port_entries:
            if isinstance(p, dict):
                port_val = p.get("port")
            elif isinstance(p, (int, str)):
                port_val = p
            else:
                continue
            try:
                result.ports.append(int(str(port_val)))
            except (ValueError, TypeError):
                pass
        result.ports = sorted(set(result.ports))[:15]

        # Technologies from HTTP headers (server, x-powered-by, etc.)
        header_entries = props.get("header", []) or []
        techs = []
        for h in header_entries:
            if isinstance(h, dict):
                attr = (h.get("attribute") or "").lower()
                val  = h.get("value", "")
                if attr in ("server", "x-powered-by", "x-generator") and val:
                    techs.append(val[:40])
            elif isinstance(h, str) and h:
                techs.append(h[:40])
        result.technologies = techs[:8]

        # DNS records (for domains/URLs)
        dns = props.get("dns", {}) or {}
        if dns:
            result.dns_records = dns

        # WHOIS
        whois = props.get("whois", {}) or {}
        if whois:
            if not result.org and whois.get("org"):
                result.org = whois["org"]
            if whois.get("registrar"):
                result.registrar     = whois["registrar"]
            if whois.get("created"):
                result.creation_date = whois["created"]
            if whois.get("expires"):
                result.expiry_date   = whois["expires"]

        # HTTP info (for screenshot-like data)
        http = props.get("http", {}) or {}
        if http.get("status"):
            result.http_status = http["status"]

        # HTTP redirects
        redirects = http.get("redirects", []) or []
        if redirects:
            raw["_pd_redirects"] = [
                r.get("url", "") if isinstance(r, dict) else str(r)
                for r in redirects[:5]
            ]

        # ── Feeds (pulse count) ────────────────────────────────────
        feeds = raw.get("feeds", []) or []
        result.pulse_count = len(feeds)

        # ── Threats → tags ─────────────────────────────────────────
        threats = (
            raw.get("threats") or
            raw.get("attributes", {}).get("threats", []) or []
        )
        result.tags = []
        for t in threats:
            if isinstance(t, str):
                result.tags.append(t)
            elif isinstance(t, dict):
                name = t.get("name") or t.get("threat", "")
                if name:
                    result.tags.append(name)
        result.tags = result.tags[:10]

        # ── Linked indicators for graph ────────────────────────────
        linked = raw.get("_linked", {}) or {}
        linked_iocs = []
        for item in (linked.get("indicators") or [])[:10]:
            itype = item.get("type", "")
            ival  = item.get("indicator", "")
            if ival and itype in ("ip", "domain", "url", "email"):
                linked_iocs.append({"value": ival, "type": itype})
        if linked_iocs:
            raw["_linked_iocs"] = linked_iocs

        # ── Reports for timeline ───────────────────────────────────
        result.reports = []
        stamp_added = raw.get("stamp_added")
        stamp_seen  = raw.get("stamp_seen") or raw.get("stamp_probed")

        if stamp_added:
            result.reports.append({
                "date":     stamp_added[:19],
                "summary":  "First seen by Pulsedive",
                "source":   "pulsedive",
                "category": "host_info",
            })
        if result.pulse_count > 0:
            feed_names = [
                f.get("name", "") for f in feeds[:3] if f.get("name")
            ]
            detail = f"Present in {result.pulse_count} threat feed(s)"
            if feed_names:
                detail += f": {', '.join(feed_names)}"
            result.reports.append({
                "date":     stamp_seen[:19] if stamp_seen else None,
                "summary":  f"Pulsedive — {detail}",
                "source":   "pulsedive",
                "category": "threat",
            })
        if result.ports:
            result.reports.append({
                "date":     stamp_seen[:19] if stamp_seen else None,
                "summary":  f"Pulsedive host scan — {len(result.ports)} open port(s): "
                            + ", ".join(str(p) for p in result.ports[:6]),
                "source":   "pulsedive",
                "category": "host_info",
            })
