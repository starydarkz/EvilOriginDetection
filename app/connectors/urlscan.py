"""
urlscan.py — URLScan.io connector.
Supports: URL, Domain
Docs: https://urlscan.io/docs/api/

Strategy:
1. Search existing scans (fast, no quota)
2. If none found + key available → submit new scan, wait 15s, fetch result
3. Screenshot URL: constructed from uuid (always valid for public scans)

Timeout override: 35s to allow for new scan submission + wait
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
    TIMEOUT         = 35.0  # override base 12s — new scans take ~15s to complete

    async def _fetch(self, ioc: ParsedIOC) -> dict:
        if ioc.type == IOCType.url:
            query = f'page.url:"{ioc.value}"'
        else:
            query = f"domain:{ioc.value}"

        headers = {}
        if self.api_key:
            headers["API-Key"] = self.api_key

        import httpx
        async with httpx.AsyncClient(
            timeout=self.TIMEOUT,
            follow_redirects=True,
            headers=headers,
        ) as c:

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
                try:
                    submit_r = await c.post(
                        SUBMIT,
                        json={"url": url_to_scan, "visibility": "public"},
                        headers={
                            "API-Key":      self.api_key,
                            "Content-Type": "application/json",
                        },
                    )
                    if submit_r.status_code == 200:
                        scan_uuid = submit_r.json().get("uuid")
                        if scan_uuid:
                            # URLScan needs ~10-15s to complete scan
                            await asyncio.sleep(15)
                            result_r = await c.get(f"{RESULT}/{scan_uuid}/")
                            if result_r.status_code == 200:
                                detail = result_r.json()
                                data["results"] = [{
                                    "task": {
                                        "uuid": scan_uuid,
                                        "url":  url_to_scan,
                                        "time": detail.get("task", {}).get("time"),
                                        "screenshotURL": detail.get("task", {})
                                                              .get("screenshotURL"),
                                    },
                                    "page":     detail.get("page", {}),
                                    "verdicts": detail.get("verdicts", {}),
                                }]
                                data["_detail"] = detail
                except Exception:
                    pass   # new scan is best-effort

            # ── Step 3: Fetch detail for existing result ───────────
            existing_results = data.get("results", [])
            if existing_results and not data.get("_detail"):
                uuid = existing_results[0].get("task", {}).get("uuid")
                if uuid:
                    try:
                        r2 = await c.get(
                            f"{RESULT}/{uuid}/",
                            timeout=10.0
                        )
                        if r2.status_code == 200:
                            data["_detail"] = r2.json()
                    except Exception:
                        pass   # detail is best-effort

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

        uuid = task.get("uuid")

        # Screenshot URL — try multiple sources in order of reliability
        result.screenshot_url = (
            task.get("screenshotURL")
            or detail.get("task", {}).get("screenshotURL")
            or (f"https://urlscan.io/screenshots/{uuid}.png" if uuid else None)
        )

        result.http_status = (
            page.get("status")
            or detail.get("page", {}).get("status")
        )
        result.country = (
            page.get("country")
            or detail.get("page", {}).get("country")
        )
        result.org      = page.get("asn") or detail.get("page", {}).get("asn")
        result.last_seen = task.get("time")

        # Tags from verdicts
        result.tags = (
            hit.get("verdicts", {}).get("urlscan", {}).get("tags", []) or []
        )

        # Technologies from Wappalyzer in detail
        wappa = (
            detail.get("meta", {})
                  .get("processors", {})
                  .get("wappa", {})
                  .get("data", [])
        )
        result.technologies = [
            t.get("app") for t in (wappa or []) if t.get("app")
        ][:10]

        # Redirects — from page data
        redirects = detail.get("data", {}).get("requests", [])
        redirect_chain = []
        for req in (redirects or [])[:5]:
            resp = req.get("response", {}).get("response", {})
            status = resp.get("status", 0)
            if status in (301, 302, 307, 308):
                loc = resp.get("headers", {}).get("location", "")
                if loc:
                    redirect_chain.append(loc)
        if redirect_chain:
            result.tags.append(f"redirects:{len(redirect_chain)}")

        malicious = (
            hit.get("verdicts", {})
               .get("overall", {})
               .get("malicious", False)
        )
        result.verdict_hint = "malicious" if malicious else "unknown"
