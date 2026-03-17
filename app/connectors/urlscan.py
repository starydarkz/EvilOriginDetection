"""
urlscan.py — URLScan.io connector.
Supports: URL, Domain
Docs: https://urlscan.io/docs/api/

Notes:
- Search endpoint is PUBLIC — no key needed, but key increases rate limits
- Result/detail endpoint is also public for existing scans
- 403 on search = malformed query or rate limited without key
- We search existing results only (no new scans) to avoid quota burn
"""
from app.models import IOCType
from app.parser import ParsedIOC
from .base import BaseConnector, NormalizedResult

SEARCH = "https://urlscan.io/api/v1/search"
RESULT = "https://urlscan.io/api/v1/result"


class URLScanConnector(BaseConnector):
    SOURCE_NAME     = "urlscan"
    SUPPORTED_TYPES = {IOCType.url, IOCType.domain}

    async def _fetch(self, ioc: ParsedIOC) -> dict:
        # Build query — search existing scans only
        if ioc.type == IOCType.url:
            query = f'page.url:"{ioc.value}"'
        else:
            query = f"domain:{ioc.value}"

        # Key is optional — search endpoint works without it
        # Including it raises rate limits from 100 to higher
        headers = {}
        if self.api_key:
            headers["API-Key"] = self.api_key

        async with self._client(headers) as c:
            r = await c.get(
                SEARCH,
                params={"q": query, "size": "1", "sort": "date:desc"}
            )

            # 404 = no results found (not an error)
            if r.status_code == 404:
                return {"results": [], "total": 0}

            # 429 = rate limited
            if r.status_code == 429:
                raise Exception("URLScan rate limit exceeded")

            # 400/403 = bad query or auth issue — return empty gracefully
            if r.status_code in (400, 403):
                return {"results": [], "total": 0, "_status": r.status_code}

            r.raise_for_status()
            data = r.json()

            # Fetch screenshot/detail for the most recent result
            results = data.get("results", [])
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

        result.screenshot_url = (
            # Try detail response first (more reliable)
            detail.get("task", {}).get("screenshotURL")
            or (f"https://urlscan.io/screenshots/{task.get('uuid')}.png"
                if task.get("uuid") else None)
        )
        result.http_status  = page.get("status")
        result.country      = page.get("country")
        result.org          = page.get("asn")
        result.last_seen    = task.get("time")
        result.tags         = (
            hit.get("verdicts", {}).get("urlscan", {}).get("tags", []) or []
        )

        # Technologies from Wappalyzer data in detail
        wappa = (
            detail.get("meta", {})
                  .get("processors", {})
                  .get("wappa", {})
                  .get("data", [])
        )
        result.technologies = [
            t.get("app") for t in wappa if t.get("app")
        ][:10]

        malicious = (
            hit.get("verdicts", {})
               .get("overall", {})
               .get("malicious", False)
        )
        result.verdict_hint = "malicious" if malicious else "unknown"
