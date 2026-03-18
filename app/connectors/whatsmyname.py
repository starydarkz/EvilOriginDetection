"""
whatsmyname.py — WhatsMyName username OSINT connector.
Supports: Email only (extracts username from local part of email).
Uses the public GitHub JSON dataset — no key required.
Docs: https://github.com/WebBreacher/WhatsMyName

Fix: uses a single client session and proper concurrency limiting
to avoid hammering 30 sites simultaneously.
"""
import asyncio
import httpx
from app.models import IOCType
from typing import ClassVar
from app.parser import ParsedIOC
from .base import BaseConnector, NormalizedResult

DATASET_URL = (
    "https://raw.githubusercontent.com/WebBreacher/WhatsMyName"
    "/main/wmn-data.json"
)
MAX_CONCURRENT = 10   # Max parallel site checks
SITE_TIMEOUT   = 5.0  # Per-site timeout in seconds
MAX_SITES      = 40   # Max sites to check per query


class WhatsMyNameConnector(BaseConnector):
    SOURCE_NAME     = "whatsmyname"
    SUPPORTED_TYPES = {IOCType.email}
    DATA_CATEGORIES: ClassVar[set[str]] = {"web_osint"}
    TIMEOUT         = 30.0  # Override base timeout for this connector

    def requires_key(self) -> bool:
        return False

    async def _fetch(self, ioc: ParsedIOC) -> dict:
        username = ioc.value.split("@")[0]

        # Use a single client for the entire operation
        async with httpx.AsyncClient(
            timeout=SITE_TIMEOUT,
            follow_redirects=True,
            headers={"User-Agent": "EvilOriginDetection/0.1 OSINT-Tool"},
        ) as client:
            # Fetch dataset
            try:
                r = await client.get(DATASET_URL, timeout=10.0)
                r.raise_for_status()
                dataset = r.json()
            except Exception as e:
                return {"username": username, "hits": [], "error": str(e)}

            sites = dataset.get("sites", [])[:MAX_SITES]

            # Semaphore to limit concurrency
            sem   = asyncio.Semaphore(MAX_CONCURRENT)
            hits  = []

            async def check_site(site: dict) -> dict | None:
                uri = site.get("uri_check", "").replace("{account}", username)
                if not uri:
                    return None
                async with sem:
                    try:
                        resp = await client.get(uri)
                        # Check by status code
                        if site.get("e_code") and resp.status_code == site["e_code"]:
                            return {
                                "site":     site.get("name", ""),
                                "url":      uri,
                                "category": site.get("cat", ""),
                            }
                        # Check by string presence
                        if site.get("e_string") and site["e_string"] in resp.text:
                            return {
                                "site":     site.get("name", ""),
                                "url":      uri,
                                "category": site.get("cat", ""),
                            }
                    except (httpx.TimeoutException, httpx.RequestError):
                        pass
                return None

            tasks   = [check_site(s) for s in sites]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            hits    = [r for r in results if isinstance(r, dict)]

        return {"username": username, "hits": hits}

    def normalize(self, raw: dict, ioc: ParsedIOC,
                  result: NormalizedResult) -> None:
        hits = raw.get("hits", [])
        result.username_hits = hits
        result.verdict_hint  = "unknown"

        if hits:
            result.tags.append(f"found-on-{len(hits)}-platforms")
            # Group categories
            categories = {}
            for h in hits:
                cat = h.get("category", "other") or "other"
                categories[cat] = categories.get(cat, 0) + 1
            for cat, count in sorted(categories.items(), key=lambda x: -x[1])[:4]:
                result.tags.append(f"{cat}:{count}")

            # Reports for timeline
            result.reports = [{
                "date":     None,
                "summary":  (
                    f"WhatsMyName — username found on {len(hits)} platform(s): "
                    + ", ".join(h.get("site", "") for h in hits[:5])
                    + ("…" if len(hits) > 5 else "")
                ),
                "source":   "whatsmyname",
                "category": "web_osint",
            }]
