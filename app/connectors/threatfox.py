"""
threatfox.py — ThreatFox (abuse.ch) connector.

POST https://threatfox-api.abuse.ch/api/v1/
No API key required.

Response structure:
  query_status: "ok" | "no_result"
  data: [{
    id, ioc, ioc_type, threat_type, malware, malware_printable,
    malware_alias, confidence_level, first_seen, last_seen,
    reporter, reference, tags: [str], ioc_id
  }]
"""
from app.models  import IOCType
from app.parser  import ParsedIOC
from .base       import BaseConnector, NormalizedResult
from typing      import ClassVar

API = "https://threatfox-api.abuse.ch/api/v1/"

# Map ThreatFox ioc_type → our IOCType
_TYPE_MAP = {
    "ip:port":     IOCType.ip,
    "domain":      IOCType.domain,
    "url":         IOCType.url,
    "md5_hash":    IOCType.hash,
    "sha256_hash": IOCType.hash,
}

# Threat type → human readable
_THREAT_LABELS = {
    "botnet_cc":        "Botnet C2",
    "payload_delivery": "Payload Delivery",
    "payload":          "Malware Payload",
    "c2":               "Command & Control",
    "phishing":         "Phishing",
    "spam":             "Spam",
}


class ThreatFoxConnector(BaseConnector):
    SOURCE_NAME:     ClassVar[str]      = "threatfox"
    SUPPORTED_TYPES: ClassVar[set]      = {IOCType.ip, IOCType.domain,
                                           IOCType.hash, IOCType.url}
    DATA_CATEGORIES: ClassVar[set]      = {"threat"}
    TIMEOUT:         ClassVar[float]    = 12.0

    def requires_key(self) -> bool:
        return False

    async def _fetch(self, ioc: ParsedIOC) -> dict:
        import httpx

        # Normalise: IP:port → just IP
        value = ioc.value
        if ioc.type == IOCType.ip and ":" in value:
            value = value.split(":")[0]

        body = {"query": "search_ioc", "search_term": value}

        headers = {
            "Content-Type": "application/json",
            "User-Agent":   "Mozilla/5.0 (compatible; EOD/1.0; threat intelligence)",
        }
        async with httpx.AsyncClient(timeout=self.TIMEOUT) as c:
            r = await c.post(API, json=body, headers=headers)
            if r.status_code in (401, 403):
                return {"_blocked": True, "_status": r.status_code,
                        "_body": r.text[:200]}
            r.raise_for_status()
            return r.json()

    def normalize(self, raw: dict, ioc: ParsedIOC,
                  result: NormalizedResult) -> None:
        if raw.get("_blocked"):
            result.verdict_hint = "unknown"
            result.error = f"Blocked by abuse.ch (HTTP {raw.get('_status',401)})"
            return
        if raw.get("query_status") == "no_result" or not raw.get("data"):
            result.verdict_hint = "unknown"
            return

        entries = raw["data"]
        if not isinstance(entries, list) or not entries:
            result.verdict_hint = "unknown"
            return

        # Use highest-confidence entry
        entries = sorted(entries,
                         key=lambda x: int(x.get("confidence_level", 0)),
                         reverse=True)
        top = entries[0]

        # Verdict
        confidence = int(top.get("confidence_level", 0))
        result.verdict_hint = (
            "malicious"  if confidence >= 50 else
            "suspicious" if confidence >= 25 else
            "unknown"
        )
        result.abuse_score = confidence

        # Threat type
        tt = top.get("threat_type", "")
        result.threat_type = _THREAT_LABELS.get(tt, tt.replace("_", " ").title())

        # Malware family
        result.malware_family = (
            top.get("malware_printable") or
            top.get("malware_alias")     or
            top.get("malware")
        )

        # Tags — combine ThreatFox tags + malware + threat type
        tags = list(top.get("tags") or [])
        if result.malware_family and result.malware_family not in tags:
            tags.insert(0, result.malware_family)
        if result.threat_type and result.threat_type not in tags:
            tags.append(result.threat_type)
        result.tags = [str(t) for t in tags if t][:12]

        # Dates
        result.last_seen  = top.get("last_seen")  or top.get("first_seen")
        result.last_seen  = result.last_seen[:19] if result.last_seen else None

        # Related IOCs — collect unique values from all entries
        seen = set()
        related = []
        for e in entries[:10]:
            val = e.get("ioc", "")
            if val and val != ioc.value and val not in seen:
                seen.add(val)
                rel_type = _TYPE_MAP.get(e.get("ioc_type", ""), IOCType.ip)
                related.append({
                    "value":        val,
                    "type":         rel_type.value,
                    "relationship": _THREAT_LABELS.get(
                        e.get("threat_type", ""), "related"),
                    "malware":      e.get("malware_printable") or e.get("malware"),
                })
        result.related_iocs = related[:8]

        # Reports for timeline
        result.reports = []
        for e in entries[:5]:
            fs = e.get("first_seen", "")[:19]
            mw = e.get("malware_printable") or e.get("malware") or "Unknown"
            tt_label = _THREAT_LABELS.get(e.get("threat_type", ""), "Threat")
            ref  = e.get("reference") or ""
            conf = e.get("confidence_level", 0)
            summary = f"ThreatFox — {mw} · {tt_label} · confidence {conf}%"
            if ref:
                summary += f" · ref: {ref[:60]}"
            result.reports.append({
                "date":     fs or None,
                "summary":  summary,
                "source":   "threatfox",
                "category": "threat",
                "verdict":  "malicious" if int(conf) >= 50 else "suspicious",
            })
