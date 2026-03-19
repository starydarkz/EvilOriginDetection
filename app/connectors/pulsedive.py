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
from typing import ClassVar

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
        # Pulsedive can return lists instead of dicts for some fields
        # depending on the indicator type — always check isinstance
        raw_props = raw.get("properties")
        props = raw_props if isinstance(raw_props, dict) else {}

        # Geo
        raw_geo = props.get("geo")
        geo = raw_geo if isinstance(raw_geo, dict) else {}
        result.country   = geo.get("country")
        result.city      = geo.get("city")
        result.latitude  = geo.get("latitude")
        result.longitude = geo.get("longitude")
        org_raw = geo.get("org", "") or ""
        if org_raw:
            parts = org_raw.split(" ", 1)
            result.org = (parts[1] if len(parts) > 1 and parts[0].startswith("AS")
                          else org_raw)
        result.asn = geo.get("asn")

        # Ports — can be [{port:443, protocol:"TCP/SSL"}] or []
        port_entries = props.get("port") or []
        port_entries = port_entries if isinstance(port_entries, list) else []
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

        # Technologies from HTTP headers
        header_entries = props.get("header") or []
        header_entries = header_entries if isinstance(header_entries, list) else []
        techs = []
        for h in header_entries:
            if isinstance(h, dict):
                attr = (h.get("attribute") or "").lower()
                val  = h.get("value", "") or ""
                if attr in ("server", "x-powered-by", "x-generator") and val:
                    techs.append(val[:40])
            elif isinstance(h, str) and h:
                techs.append(h[:40])
        result.technologies = techs[:8]

        # DNS records
        raw_dns = props.get("dns")
        dns = raw_dns if isinstance(raw_dns, dict) else {}
        if dns:
            result.dns_records = dns

        # WHOIS
        raw_whois = props.get("whois")
        whois = raw_whois if isinstance(raw_whois, dict) else {}
        if whois:
            if not result.org and whois.get("org"):
                result.org = whois["org"]
            if whois.get("registrar"):
                result.registrar     = whois["registrar"]
            if whois.get("created"):
                result.creation_date = whois["created"]
            if whois.get("expires"):
                result.expiry_date   = whois["expires"]

        # HTTP info
        raw_http = props.get("http")
        http = raw_http if isinstance(raw_http, dict) else {}
        if http.get("status"):
            result.http_status = http["status"]
        if http.get("title"):
            result.http_title = http["title"]

        # HTTP redirects
        redirects = http.get("redirects") or []
        redirects = redirects if isinstance(redirects, list) else []
        if redirects:
            result.redirects = [
                (r.get("url", "") if isinstance(r, dict) else str(r))
                for r in redirects[:5]
            ]

        # ── Feeds (pulse count) ────────────────────────────────────
        raw_feeds = raw.get("feeds")
        feeds = raw_feeds if isinstance(raw_feeds, list) else []
        result.pulse_count = len(feeds)

        # ── Threats → tags ─────────────────────────────────────────
        raw_attrs = raw.get("attributes")
        attrs = raw_attrs if isinstance(raw_attrs, dict) else {}
        threats = (
            raw.get("threats") or
            attrs.get("threats", []) or []
        )
        threats = threats if isinstance(threats, list) else []
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
        raw_linked = raw.get("_linked")
        linked = raw_linked if isinstance(raw_linked, dict) else {}
        linked_iocs = []
        linked_items = linked.get("indicators") if isinstance(linked, dict) else (linked if isinstance(linked, list) else [])
        for item in (linked_items or [])[:10]:
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

        if stamp_added and isinstance(stamp_added, str):
            result.reports.append({
                "date":     stamp_added[:19],
                "summary":  "First seen by Pulsedive",
                "source":   "pulsedive",
                "category": "host_info",
            })
        if result.pulse_count > 0:
            feed_names = []
            for f in feeds[:3]:
                if isinstance(f, dict) and f.get("name"):
                    feed_names.append(f["name"])
                elif isinstance(f, str) and f:
                    feed_names.append(f)
            detail = f"Present in {result.pulse_count} threat feed(s)"
            if feed_names:
                detail += f": {', '.join(feed_names)}"
            result.reports.append({
                "date":     stamp_seen[:19] if stamp_seen and isinstance(stamp_seen, str) else None,
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
