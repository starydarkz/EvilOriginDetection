"""
urlscan.py — URLScan.io connector.
Supports: URL, Domain
Categories: web_osint · threat · relations
Docs: https://urlscan.io/docs/api/

Extracts from /result/{uuid}/:
  - screenshot_url, http_status, http_title
  - technologies (Wappalyzer)
  - redirects chain
  - lists.ips[], lists.domains[], lists.hashes[], lists.urls[]
    → stored in raw["_lists"] for graph enrichment
  - verdicts.overall.malicious
"""
import asyncio
from app.models import IOCType
from app.parser import ParsedIOC
from .base import BaseConnector, NormalizedResult
from typing import ClassVar

SEARCH = "https://urlscan.io/api/v1/search"
SUBMIT = "https://urlscan.io/api/v1/scan/"
RESULT = "https://urlscan.io/api/v1/result"


class URLScanConnector(BaseConnector):
    SOURCE_NAME     = "urlscan"
    SUPPORTED_TYPES = {IOCType.url, IOCType.domain}
    DATA_CATEGORIES: ClassVar[set[str]] = {"web_osint", "threat", "relations"}
    TIMEOUT         = 35.0

    async def _fetch(self, ioc: ParsedIOC) -> dict:
        query = (f'page.url:"{ioc.value}"' if ioc.type == IOCType.url
                 else f"domain:{ioc.value}")

        headers = {"API-Key": self.api_key} if self.api_key else {}

        import httpx
        async with httpx.AsyncClient(
            timeout=self.TIMEOUT, follow_redirects=True, headers=headers
        ) as c:
            # Step 1: search existing scans
            r = await c.get(SEARCH, params={"q": query, "size": "1", "sort": "date:desc"})
            if r.status_code in (400, 403):
                return {"results": [], "_status": r.status_code}
            if r.status_code == 429:
                raise Exception("URLScan rate limit exceeded")
            if r.status_code != 200:
                return {"results": []}

            data    = r.json()
            results = data.get("results", [])

            # Step 2: submit new scan if nothing found and we have a key
            if not results and self.api_key:
                url_to_scan = (ioc.value if ioc.type == IOCType.url
                               else f"https://{ioc.value}")
                try:
                    sub = await c.post(
                        SUBMIT,
                        json={"url": url_to_scan, "visibility": "public"},
                        headers={"API-Key": self.api_key,
                                 "Content-Type": "application/json"},
                    )
                    if sub.status_code == 200:
                        uuid = sub.json().get("uuid")
                        if uuid:
                            await asyncio.sleep(15)
                            res_r = await c.get(f"{RESULT}/{uuid}/")
                            if res_r.status_code == 200:
                                detail = res_r.json()
                                data["results"] = [{
                                    "task":     {
                                        "uuid":          uuid,
                                        "url":           url_to_scan,
                                        "time":          detail.get("task", {}).get("time"),
                                        "screenshotURL": detail.get("task", {}).get("screenshotURL"),
                                    },
                                    "page":     detail.get("page", {}),
                                    "verdicts": detail.get("verdicts", {}),
                                }]
                                data["_detail"] = detail
                except Exception:
                    pass

            # Step 3: fetch detail for existing result
            existing = data.get("results", [])
            if existing and not data.get("_detail"):
                uuid = existing[0].get("task", {}).get("uuid")
                if uuid:
                    try:
                        r2 = await c.get(f"{RESULT}/{uuid}/", timeout=10.0)
                        if r2.status_code == 200:
                            data["_detail"] = r2.json()
                    except Exception:
                        pass

            return data

    def normalize(self, raw: dict, ioc: ParsedIOC,
                  result: NormalizedResult) -> None:
        results = raw.get("results", [])
        if not results:
            result.verdict_hint = "unknown"
            return

        hit    = results[0]
        task   = hit.get("task",     {})
        page   = hit.get("page",     {})
        detail = raw.get("_detail",  {})

        uuid = task.get("uuid")

        # ── Screenshot ────────────────────────────────────────────
        result.screenshot_url = (
            task.get("screenshotURL")
            or detail.get("task", {}).get("screenshotURL")
            or (f"https://urlscan.io/screenshots/{uuid}.png" if uuid else None)
        )

        # ── HTTP info ─────────────────────────────────────────────
        result.http_status = (
            page.get("status") or detail.get("page", {}).get("status")
        )
        result.http_title = (
            page.get("title") or detail.get("page", {}).get("title")
        )
        result.country   = page.get("country") or detail.get("page", {}).get("country")
        result.org       = page.get("asn")     or detail.get("page", {}).get("asn")
        result.last_seen = task.get("time")

        # ── Technologies (Wappalyzer) ─────────────────────────────
        wappa = (
            detail.get("meta", {})
                  .get("processors", {})
                  .get("wappa", {})
                  .get("data", [])
        )
        result.technologies = [
            t.get("app") for t in (wappa or []) if t.get("app")
        ][:12]

        # ── Redirect chain ────────────────────────────────────────
        result.redirects = []
        for req in (detail.get("data", {}).get("requests", []) or [])[:10]:
            resp   = req.get("response", {}).get("response", {})
            status = resp.get("status", 0)
            if status in (301, 302, 307, 308):
                loc = (resp.get("headers") or {}).get("location", "")
                if loc:
                    result.redirects.append(loc)

        # ── Tags from URLScan verdict ─────────────────────────────
        result.tags = (
            hit.get("verdicts", {}).get("urlscan", {}).get("tags", []) or []
        )
        if result.redirects:
            result.tags.append(f"redirects:{len(result.redirects)}")

        # ── Verdict ───────────────────────────────────────────────
        malicious = (
            hit.get("verdicts", {}).get("overall", {}).get("malicious", False)
        )
        result.verdict_hint = "malicious" if malicious else "unknown"

        # ── Relations — contacted IPs/domains/hashes ──────────────
        # Stored in raw for graph router
        lists = detail.get("lists", {}) or {}
        raw["_lists"] = {
            "ips":     (lists.get("ips")     or [])[:10],
            "domains": (lists.get("domains") or [])[:10],
            "hashes":  (lists.get("hashes")  or [])[:5],
            "urls":    (lists.get("urls")    or [])[:5],
        }

        # ── Reports for timeline ───────────────────────────────────
        result.reports = []
        if result.last_seen:
            detail_str = f"HTTP {result.http_status}" if result.http_status else "Scanned"
            if result.http_title:
                detail_str += f' — "{result.http_title[:60]}"'
            if result.technologies:
                detail_str += f" · {', '.join(result.technologies[:2])}"
            result.reports.append({
                "date":     result.last_seen[:19],
                "summary":  f"URLScan — {detail_str}",
                "source":   "urlscan",
                "category": "web_osint",
            })
            if result.redirects:
                result.reports.append({
                    "date":     result.last_seen[:19],
                    "summary":  f"Redirect chain detected ({len(result.redirects)} hop(s)): {result.redirects[0][:80]}",
                    "source":   "urlscan",
                    "category": "web_osint",
                })
