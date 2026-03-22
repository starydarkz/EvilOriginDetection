"""
otx.py — AlienVault OTX connector.

GET https://otx.alienvault.com/api/v1/indicators/{type}/{ioc}/general
No API key required for public data.
Optional key (free registration) gives higher rate limits.

Returns threat pulses, malware families, adversaries, ATT&CK techniques.
"""
from app.models  import IOCType
from app.parser  import ParsedIOC
from .base       import BaseConnector, NormalizedResult
from typing      import ClassVar

BASE = "https://otx.alienvault.com/api/v1/indicators"

_TYPE_PATH = {
    IOCType.ip:     "IPv4",
    IOCType.domain: "domain",
    IOCType.hash:   "file",
    IOCType.url:    "url",
}


class OTXConnector(BaseConnector):
    SOURCE_NAME:     ClassVar[str]   = "otx"
    SUPPORTED_TYPES: ClassVar[set]   = {IOCType.ip, IOCType.domain,
                                        IOCType.hash, IOCType.url}
    DATA_CATEGORIES: ClassVar[set]   = {"threat"}
    TIMEOUT:         ClassVar[float] = 15.0

    def requires_key(self) -> bool:
        return False   # key optional — set OTX_KEY in .env for higher limits

    async def _fetch(self, ioc: ParsedIOC) -> dict:
        import httpx

        type_path = _TYPE_PATH.get(ioc.type, "IPv4")
        url       = f"{BASE}/{type_path}/{ioc.value}/general"
        headers = {"User-Agent": "Mozilla/5.0 (compatible; EOD/1.0; threat intelligence)"}
        if self.api_key:
            headers["X-OTX-API-KEY"] = self.api_key

        async with httpx.AsyncClient(timeout=self.TIMEOUT,
                                     follow_redirects=True) as c:
            r = await c.get(url, headers=headers)
            if r.status_code == 404:
                return {"_not_found": True}
            if r.status_code in (401, 403):
                return {"_blocked": True, "_status": r.status_code}
            r.raise_for_status()
            return r.json()

    def normalize(self, raw: dict, ioc: ParsedIOC,
                  result: NormalizedResult) -> None:
        if raw.get("_blocked"):
            result.verdict_hint = "unknown"
            result.error = f"Blocked (HTTP {raw.get('_status', 401)})"
            return
        if raw.get("_not_found"):
            result.verdict_hint = "unknown"
            return

        pulse_count = int(raw.get("pulse_info", {}).get("count", 0))
        result.pulse_count = pulse_count

        # Verdict from pulse count + reputation
        reputation = raw.get("reputation", 0) or 0
        if isinstance(reputation, (int, float)):
            result.abuse_score = min(int(abs(reputation) * 10), 100)

        if pulse_count >= 5 or reputation <= -2:
            result.verdict_hint = "malicious"
        elif pulse_count >= 1 or reputation < 0:
            result.verdict_hint = "suspicious"
        else:
            result.verdict_hint = "unknown"

        # Geo
        result.country = raw.get("country_code") or raw.get("country_name")
        result.asn     = str(raw.get("asn", "")).replace("AS", "") or None

        # Malware families from pulse tags
        pulse_info    = raw.get("pulse_info", {}) or {}
        related_pulses = pulse_info.get("pulses", []) or []

        families: set = set()
        adversaries: set = set()
        attack_ids: list = []
        all_tags: set = set()

        for pulse in related_pulses[:15]:
            name = pulse.get("name", "")
            # Tags
            for t in (pulse.get("tags") or []):
                all_tags.add(str(t).lower())
            # Malware families
            for mf in (pulse.get("malware_families") or []):
                if isinstance(mf, dict):
                    families.add(mf.get("display_name") or mf.get("id",""))
                elif isinstance(mf, str):
                    families.add(mf)
            # Adversary
            adv = pulse.get("adversary")
            if adv:
                adversaries.add(str(adv))
            # ATT&CK
            for att in (pulse.get("attack_ids") or []):
                if isinstance(att, dict):
                    att_id = att.get("id") or att.get("display_name","")
                    if att_id and att_id not in attack_ids:
                        attack_ids.append(att_id)
                elif isinstance(att, str) and att not in attack_ids:
                    attack_ids.append(att)

        if families:
            result.malware_family = ", ".join(sorted(families)[:3])
        if adversaries:
            result.threat_actor = ", ".join(sorted(adversaries)[:3])
        result.attack_techniques = attack_ids[:10]
        result.tags = list(all_tags)[:12]

        # Add pulse count as tag
        if pulse_count > 0:
            result.tags.insert(0, f"{pulse_count}-pulses")

        # Related IOCs from pulse indicators (up to 6)
        related = []
        seen_vals: set = set()
        for pulse in related_pulses[:5]:
            for ind in (pulse.get("indicators") or [])[:4]:
                val  = ind.get("indicator","")
                itype = ind.get("type","").lower()
                if val and val != ioc.value and val not in seen_vals:
                    seen_vals.add(val)
                    # Map OTX type to our type
                    our_type = ("ip" if "ipv4" in itype or "ipv6" in itype
                                else "domain" if "domain" in itype or "hostname" in itype
                                else "hash"   if "hash" in itype or "md5" in itype or "sha" in itype
                                else "url"    if "url" in itype
                                else "ip")
                    related.append({
                        "value":        val,
                        "type":         our_type,
                        "relationship": f"co-occurs in pulse: {pulse.get('name','')[:40]}",
                        "malware":      result.malware_family,
                    })
                    if len(related) >= 8:
                        break
            if len(related) >= 8:
                break
        result.related_iocs = related

        # Timeline — one entry per unique pulse (most recent 5)
        result.reports = []
        for pulse in sorted(related_pulses, key=lambda x: x.get("modified",""),
                            reverse=True)[:5]:
            created = (pulse.get("created") or "")[:19]
            pname   = pulse.get("name", "Threat pulse")[:60]
            adv     = pulse.get("adversary") or ""
            adv_str = f" · actor: {adv}" if adv else ""
            result.reports.append({
                "date":     created or None,
                "summary":  f"OTX — {pname}{adv_str}",
                "source":   "otx",
                "category": "threat",
                "verdict":  result.verdict_hint,
            })
