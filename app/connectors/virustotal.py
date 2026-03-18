"""
virustotal.py — VirusTotal v3 connector.
Supports: IP, Domain, Hash, URL
Docs: https://developers.virustotal.com/reference

Extracts:
- Tags from attributes.tags
- Relations: resolutions (IP↔Domain), communicating files, downloaded files
  These are fetched via separate /relationships endpoints and used in graph
"""
import base64
from app.models import IOCType
from app.parser import ParsedIOC
from .base import BaseConnector, NormalizedResult

BASE = "https://www.virustotal.com/api/v3"


class VirusTotalConnector(BaseConnector):
    SOURCE_NAME     = "virustotal"
    SUPPORTED_TYPES = {IOCType.ip, IOCType.domain, IOCType.hash, IOCType.url}
    DATA_CATEGORIES: ClassVar[set[str]] = {"threat", "reputation", "host_info", "file", "relations"}

    async def _fetch(self, ioc: ParsedIOC) -> dict:
        endpoint = self._endpoint(ioc)
        headers  = {"x-apikey": self.api_key}

        async with self._client(headers) as client:
            # Main lookup
            r = await client.get(f"{BASE}{endpoint}")
            r.raise_for_status()
            data = r.json()

            # Fetch relations for graph enrichment
            relations = await self._fetch_relations(client, ioc, endpoint)
            if relations:
                data["_relations"] = relations

            return data

    async def _fetch_relations(self, client, ioc: ParsedIOC,
                               endpoint: str) -> dict:
        """
        Fetch relationship data for graph correlation.
        Returns dict of {relation_type: [items]}
        Only fetches the most useful relations per IOC type.
        """
        relations = {}
        rel_map = {
            IOCType.ip:     ["resolutions", "communicating_files"],
            IOCType.domain: ["resolutions", "communicating_files",
                             "historical_ssl_certificates"],
            IOCType.hash:   ["contacted_ips", "contacted_domains",
                             "dropped_files"],
            IOCType.url:    ["contacted_ips", "contacted_domains"],
        }
        targets = rel_map.get(ioc.type, [])

        for rel in targets:
            try:
                r = await client.get(
                    f"{BASE}{endpoint}/relationships/{rel}",
                    params={"limit": "5"}
                )
                if r.status_code == 200:
                    items = r.json().get("data", [])
                    if items:
                        relations[rel] = items
            except Exception:
                pass   # relations are best-effort

        return relations

    def _endpoint(self, ioc: ParsedIOC) -> str:
        match ioc.type:
            case IOCType.ip:
                return f"/ip_addresses/{ioc.value}"
            case IOCType.domain:
                return f"/domains/{ioc.value}"
            case IOCType.hash:
                return f"/files/{ioc.value}"
            case IOCType.url:
                encoded = base64.urlsafe_b64encode(
                    ioc.value.encode()
                ).decode().rstrip("=")
                return f"/urls/{encoded}"

    def normalize(self, raw: dict, ioc: ParsedIOC,
                  result: NormalizedResult) -> None:
        attr  = raw.get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})

        result.malicious_count = stats.get("malicious", 0)
        result.total_engines   = sum(stats.values()) if stats else 0

        # Tags — combine VT tags + popular threat categories
        vt_tags = attr.get("tags", []) or []
        categories = list((attr.get("popular_threat_classification") or {})
                         .get("suggested_threat_label", "")
                         .split("/") if attr.get("popular_threat_classification") else [])
        result.tags = list(dict.fromkeys(
            [t for t in vt_tags + categories if t]
        ))[:15]

        result.country  = attr.get("country")
        result.asn      = attr.get("asn")
        result.org      = attr.get("as_owner")
        result.network  = attr.get("network")
        result.last_seen = attr.get("last_modification_date")

        # Verdict
        suspicious = stats.get("suspicious", 0)
        total      = result.total_engines or 1
        ratio      = (result.malicious_count + suspicious * 0.5) / total
        if ratio >= 0.3:
            result.verdict_hint = "malicious"
        elif ratio >= 0.05:
            result.verdict_hint = "suspicious"
        elif result.malicious_count == 0:
            result.verdict_hint = "clean"
        else:
            result.verdict_hint = "unknown"

        # Hash-specific
        if ioc.type == IOCType.hash:
            result.file_name    = (attr.get("names") or [None])[0]
            result.file_type    = attr.get("type_description")
            result.file_size    = attr.get("size")
            result.malware_family = (
                attr.get("popular_threat_name") or
                attr.get("suggested_threat_label")
            )
            result.first_submission = attr.get("first_submission_date")

        # ── Domain categories ─────────────────────────────────────
        # categories{} maps source → category label (e.g. "social-network")
        if ioc.type == IOCType.domain:
            cats = attr.get("categories", {}) or {}
            # Deduplicate category values across sources
            cat_vals = list(dict.fromkeys(v for v in cats.values() if v))
            if cat_vals:
                result.tags = list(dict.fromkeys(result.tags + cat_vals))[:15]

        # ── Reports for timeline ───────────────────────────────────
        result.reports = []
        first_sub = result.first_submission
        last_mod  = result.last_seen

        if first_sub:
            ts = _epoch_to_iso(first_sub)
            result.reports.append({
                "date":     ts,
                "summary":  "First submitted to VirusTotal",
                "source":   "virustotal",
                "category": "threat",
            })

        if last_mod and result.total_engines:
            ts  = _epoch_to_iso(last_mod)
            mal = result.malicious_count or 0
            tot = result.total_engines
            result.reports.append({
                "date":     ts,
                "summary":  (
                    f"VirusTotal — {mal}/{tot} engines detected"
                    if mal else
                    f"VirusTotal — Clean ({tot} engines)"
                ),
                "source":   "virustotal",
                "category": "threat",
            })

        # Relations are stored in result.raw (via _fetch) and read
        # directly by the graph router from raw_json in the DB
