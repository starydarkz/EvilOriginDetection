"""
urlscan.py — URLScan.io connector.
Supports: URL, Domain

Strategy:
1. Search existing scans first (free, fast)
2. If none found AND we have a key → submit a new scan, poll for result
3. Screenshots are public once the scan completes
"""
import asyncio
from app.models import IOCType
from app.parser import ParsedIOC
from .base import BaseConnector, NormalizedResult

SEARCH = "https://urlscan.io/api/v1/search"
SUBMIT = "https://urlscan.io/api/v1/scan/"
RESULT = "https://urlscan.io/api/v1/result"


class URLScanConnector(BaseConnector):
    SOURCE_NAME     = "urlscan"
    SUPPORTED_TYPES = {IOCType.url, IOCType.domain}

    async def _fetch(self, ioc: ParsedIOC) -> dict:
        # Build search query
        if ioc.type == IOCType.url:
            query = f'page.url:"{ioc.value}"'
        else:
            query = f"domain:{ioc.value}"

        headers = {}
        if self.api_key:
            headers["API-Key"] = self.api_key

        async with self._client(headers) as c:

            # ── Step 1: Search existing scans ──────────────────────
            r = await c.get(
                SEARCH,
                params={"q": query, "size": "1", "sort": "date:desc"}
            )

            if r.status_code in (400, 403):
                return {"results": [], "total": 0, "_status": r.status_code}
            if r.status_code == 429:
                raise Exception("URLScan rate limit exceeded")
            if r.status_code != 200:
                return {"results": [], "total": 0}

            data    = r.json()
            results = data.get("results", [])

            # ── Step 2: Submit new scan if nothing found ───────────
            if not results and self.api_key:
                url_to_scan = (
                    ioc.value if ioc.type == IOCType.url
                    else f"https://{ioc.value}"
                )
                submit_r = await c.post(
                    SUBMIT,
                    json={"url": url_to_scan, "visibility": "public"},
                    headers={"API-Key": self.api_key,
                             "Content-Type": "application/json"},
                )
                if submit_r.status_code == 200:
                    scan_uuid = submit_r.json().get("uuid")
                    if scan_uuid:
                        # Poll for result — URLScan takes ~10s to complete
                        await asyncio.sleep(12)
                        result_r = await c.get(f"{RESULT}/{scan_uuid}/")
                        if result_r.status_code == 200:
                            detail = result_r.json()
                            # Build a fake "results" structure from the scan
                            data["results"] = [{
                                "task": {
                                    "uuid":          scan_uuid,
                                    "url":           url_to_scan,
                                    "time":          detail.get("task", {}).get("time"),
                                    "screenshotURL": detail.get("task", {}).get("screenshotURL"),
                                },
                                "page": detail.get("page", {}),
                                "verdicts": detail.get("verdicts", {}),
                            }]
                            data["_detail"] = detail
                            return data

            # ── Step 3: Fetch detail for existing result ───────────
            if results:
                uuid = results[0].get("task", {}).get("uuid")
                if uuid:
                    r2 = await c.get(f"{RESULT}/{uuid}/")
                    if r2.status_code == 200:
                        data["_detail"] = r2.json()

            return data

    def normalize(self, raw: dict, ioc: ParsedIOC,
                  result: NormalizedResult) -> None:
        results = raw.get("results", [])
        if not results:
            result.verdict_hint = "unknown"
            return

        hit    = results[0]
        task   = hit.get("task", {})
        page   = hit.get("page", {})
        detail = raw.get("_detail", {})

        # Screenshot URL — prefer direct field, fallback to constructed URL
        result.screenshot_url = (
            task.get("screenshotURL")
            or detail.get("task", {}).get("screenshotURL")
            or (f"https://urlscan.io/screenshots/{task.get('uuid')}.png"
                if task.get("uuid") else None)
        )

        result.http_status  = page.get("status") or detail.get("page", {}).get("status")
        result.country      = page.get("country") or detail.get("page", {}).get("country")
        result.org          = page.get("asn") or detail.get("page", {}).get("asn")
        result.last_seen    = task.get("time")
        result.tags         = (
            hit.get("verdicts", {}).get("urlscan", {}).get("tags", []) or []
        )

        # Technologies from Wappalyzer
        wappa = (
            detail.get("meta", {})
                  .get("processors", {})
                  .get("wappa", {})
                  .get("data", [])
        )
        result.technologies = [
            t.get("app") for t in (wappa or []) if t.get("app")
        ][:10]

        malicious = (
            hit.get("verdicts", {})
               .get("overall", {})
               .get("malicious", False)
        )
        result.verdict_hint = "malicious" if malicious else "unknown"
