"""
urlscan.py — URLScan.io connector.
Supports: URL, Domain
Docs: https://urlscan.io/docs/api/
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
        query = f"page.url:{ioc.value}" if ioc.type == IOCType.url else f"domain:{ioc.value}"
        headers = {"API-Key": self.api_key}
        async with self._client(headers) as c:
            r = await c.get(SEARCH, params={"q": query, "size": "1", "sort": "date:desc"})
            r.raise_for_status()
            data = r.json()
            # If we have a result, fetch full detail for screenshot
            results = data.get("results", [])
            if results:
                uuid = results[0].get("task", {}).get("uuid")
                if uuid:
                    r2 = await c.get(f"{RESULT}/{uuid}/")
                    if r2.status_code == 200:
                        data["_detail"] = r2.json()
            return data

    def normalize(self, raw: dict, ioc: ParsedIOC, result: NormalizedResult) -> None:
        results = raw.get("results", [])
        if not results:
            return
        hit    = results[0]
        task   = hit.get("task", {})
        page   = hit.get("page", {})
        detail = raw.get("_detail", {})

        result.screenshot_url = (
            f"https://urlscan.io/screenshots/{task.get('uuid')}.png"
            if task.get("uuid") else None
        )
        result.http_status  = page.get("status")
        result.country      = page.get("country")
        result.org          = page.get("asn")
        result.last_seen    = task.get("time")
        result.tags         = hit.get("verdicts", {}).get("urlscan", {}).get("tags", [])

        # Technologies from detail
        dom_techs = detail.get("meta", {}).get("processors", {}).get("wappa", {}).get("data", [])
        result.technologies = [t.get("app") for t in dom_techs if t.get("app")][:10]

        malicious = hit.get("verdicts", {}).get("overall", {}).get("malicious", False)
        result.verdict_hint = "malicious" if malicious else "unknown"
