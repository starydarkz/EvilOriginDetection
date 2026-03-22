"""
urlhaus.py — URLhaus (abuse.ch) connector.

POST https://urlhaus-api.abuse.ch/v1/host/    (IP or domain)
POST https://urlhaus-api.abuse.ch/v1/url/     (URL)
POST https://urlhaus-api.abuse.ch/v1/payload/ (hash)
No API key required.
"""
from app.models  import IOCType
from app.parser  import ParsedIOC
from .base       import BaseConnector, NormalizedResult
from typing      import ClassVar

API = "https://urlhaus-api.abuse.ch/v1"


class URLhausConnector(BaseConnector):
    SOURCE_NAME:     ClassVar[str]   = "urlhaus"
    SUPPORTED_TYPES: ClassVar[set]   = {IOCType.ip, IOCType.domain,
                                        IOCType.url, IOCType.hash}
    DATA_CATEGORIES: ClassVar[set]   = {"threat"}
    TIMEOUT:         ClassVar[float] = 12.0

    def requires_key(self) -> bool:
        return False

    async def _fetch(self, ioc: ParsedIOC) -> dict:
        import httpx

        async with httpx.AsyncClient(timeout=self.TIMEOUT) as c:
            if ioc.type == IOCType.hash:
                # Try sha256 first, then md5
                r = await c.post(f"{API}/payload/",
                                 data={"sha256_hash": ioc.value})
                if r.status_code == 200:
                    data = r.json()
                    if data.get("query_status") == "no_results":
                        r2 = await c.post(f"{API}/payload/",
                                          data={"md5_hash": ioc.value})
                        if r2.status_code == 200:
                            return r2.json()
                    return data
            elif ioc.type == IOCType.url:
                r = await c.post(f"{API}/url/", data={"url": ioc.value})
            else:
                # IP or domain
                r = await c.post(f"{API}/host/", data={"host": ioc.value})

            r.raise_for_status()
            return r.json()

    def normalize(self, raw: dict, ioc: ParsedIOC,
                  result: NormalizedResult) -> None:
        status = raw.get("query_status", "")
        if status in ("no_results", "invalid_host", "invalid_url",
                      "invalid_sha256_hash", "invalid_md5_hash"):
            result.verdict_hint = "unknown"
            return

        # ── Hash payload response ─────────────────────────────
        if ioc.type == IOCType.hash:
            if raw.get("md5_hash") or raw.get("sha256_hash"):
                result.verdict_hint = "malicious"
                result.file_name    = raw.get("file_name") or raw.get("filename")
                result.file_type    = raw.get("file_type")
                result.file_size    = raw.get("file_size")

                mw = raw.get("signature") or raw.get("tag")
                if mw:
                    result.malware_family = str(mw)

                result.tags = list(raw.get("tags") or [])[:10]

                urls = raw.get("urls") or []
                result.related_iocs = [
                    {"value": u.get("url",""), "type":"url",
                     "relationship": "payload delivered via",
                     "malware": result.malware_family}
                    for u in urls[:6] if u.get("url")
                ]

                fs = raw.get("first_seen","")[:19] if raw.get("first_seen") else None
                result.reports = [{
                    "date":     fs,
                    "summary":  f"URLhaus — {result.malware_family or 'malware'} payload"
                                f" · file: {result.file_name or ioc.value[:20]}",
                    "source":   "urlhaus",
                    "category": "threat",
                    "verdict":  "malicious",
                }]
            else:
                result.verdict_hint = "unknown"
            return

        # ── Host / URL response ───────────────────────────────
        urls = raw.get("urls") or []
        if not urls:
            result.verdict_hint = "unknown"
            return

        result.verdict_hint = "malicious"

        # Collect tags and malware families from all URLs
        all_tags:     set = set()
        all_families: set = set()
        active_count  = 0

        for u in urls:
            for t in (u.get("tags") or []):
                all_tags.add(str(t))
            mw = u.get("malware") or u.get("signature")
            if mw:
                all_families.add(str(mw))
            if (u.get("url_status") or "").lower() == "online":
                active_count += 1

        result.tags          = list(all_tags)[:12]
        result.malware_family = ", ".join(sorted(all_families)[:3]) or None
        result.threat_type   = "Payload Delivery"

        if active_count:
            result.tags.insert(0, f"{active_count}-active-urls")

        # Blacklist status
        bl = raw.get("blacklists") or {}
        if isinstance(bl, dict):
            if bl.get("gsb") == "listed":
                result.tags.append("google-safebrowsing")
            if bl.get("surbl") == "listed":
                result.tags.append("surbl")

        # Timeline reports — 1 per unique URL (max 5)
        result.reports = []
        for u in sorted(urls, key=lambda x: x.get("date_added",""), reverse=True)[:5]:
            fs     = (u.get("date_added") or "")[:19]
            status = u.get("url_status") or "unknown"
            mw     = u.get("malware") or u.get("signature") or "malware"
            url_v  = u.get("url") or ""
            summary = (f"URLhaus — {mw} · {status.upper()}"
                       f" · {url_v[:60] if url_v else ioc.value}")
            result.reports.append({
                "date":     fs or None,
                "summary":  summary,
                "source":   "urlhaus",
                "category": "threat",
                "verdict":  "malicious",
            })
