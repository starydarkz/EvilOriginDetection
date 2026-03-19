"""
urlscan.py — URLScan.io connector.
Supports: URL, Domain
Categories: web_osint · threat · relations
Docs: https://urlscan.io/docs/api/

Flow:
  1. Search existing scans by domain/url (free, no key needed)
  2. If results found → fetch full detail from /result/{uuid}/
  3. If no results + key available → submit new scan, wait 20s, fetch result

Extracts:
  - screenshot_url (from task.screenshotURL or constructed from uuid)
  - scan_result_url → stored in raw["_result_url"] for source link
  - http_status (converted to int — API returns string)
  - http_title, technologies (Wappalyzer)
  - redirects chain from requests[]
  - lists.ips[], lists.domains[], lists.hashes[] → graph enrichment
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
    TIMEOUT         = 40.0   # new scans need 20s wait

    async def _fetch(self, ioc: ParsedIOC) -> dict:
        # Build search query
        if ioc.type == IOCType.url:
            query = f'page.url:"{ioc.value}"'
        else:
            query = f"domain:{ioc.value}"

        headers = {"API-Key": self.api_key} if self.api_key else {}

        import httpx
        async with httpx.AsyncClient(
            timeout=self.TIMEOUT,
            follow_redirects=True,
        ) as c:
            # ── Step 1: Search existing scans ─────────────────────
            r = await c.get(
                SEARCH,
                params={"q": query, "size": "1", "sort": "date:desc"},
                headers=headers,
            )

            if r.status_code in (400, 403):
                return {"results": [], "_status": r.status_code}
            if r.status_code == 429:
                raise Exception("URLScan rate limit exceeded")
            if r.status_code != 200:
                return {"results": []}

            data    = r.json()
            results = data.get("results", [])

            # ── Step 2: Submit new scan if nothing found ───────────
            if not results and self.api_key:
                url_to_scan = (ioc.value if ioc.type == IOCType.url
                               else f"https://{ioc.value}")
                try:
                    sub = await c.post(
                        SUBMIT,
                        json={"url": url_to_scan, "visibility": "public"},
                        headers={
                            "API-Key":      self.api_key,
                            "Content-Type": "application/json",
                        },
                    )
                    if sub.status_code == 200:
                        sub_data  = sub.json()
                        scan_uuid = sub_data.get("uuid")
                        if scan_uuid:
                            # URLScan needs 15-25s to complete
                            await asyncio.sleep(20)
                            res_r = await c.get(
                                f"{RESULT}/{scan_uuid}/",
                                headers=headers,
                            )
                            if res_r.status_code == 200:
                                detail = res_r.json()
                                # Synthetic result entry
                                data["results"] = [{
                                    "task": {
                                        "uuid":          scan_uuid,
                                        "url":           url_to_scan,
                                        "time":          detail.get("task", {}).get("time"),
                                        "screenshotURL": detail.get("task", {}).get("screenshotURL"),
                                        "reportURL":     detail.get("task", {}).get("reportURL",
                                                         f"https://urlscan.io/result/{scan_uuid}/"),
                                    },
                                    "page":     detail.get("page", {}),
                                    "verdicts": detail.get("verdicts", {}),
                                }]
                                data["_detail"]   = detail
                                data["_new_scan"] = True
                except Exception:
                    pass   # new scan is best-effort

            # ── Step 3: Fetch full detail for existing result ──────
            existing = data.get("results", [])
            if existing and not data.get("_detail"):
                uuid = existing[0].get("task", {}).get("uuid")
                if uuid:
                    try:
                        r2 = await c.get(
                            f"{RESULT}/{uuid}/",
                            headers=headers,
                            timeout=15.0,
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
        task   = hit.get("task",    {}) or {}
        page   = hit.get("page",    {}) or {}
        detail = raw.get("_detail", {}) or {}
        d_task = detail.get("task", {}) or {}
        d_page = detail.get("page", {}) or {}

        uuid = task.get("uuid") or d_task.get("uuid")

        # ── Screenshot URL ─────────────────────────────────────────
        result.screenshot_url = (
            task.get("screenshotURL")
            or d_task.get("screenshotURL")
            or (f"https://urlscan.io/screenshots/{uuid}.png" if uuid else None)
        )

        # ── Direct result link (stored in raw for source_link()) ───
        result_url = (
            task.get("reportURL")
            or d_task.get("reportURL")
            or (f"https://urlscan.io/result/{uuid}/" if uuid else None)
        )
        if result_url:
            raw["_result_url"] = result_url

        # ── HTTP info — page.status is a STRING in URLScan API ─────
        status_raw = (page.get("status") or d_page.get("status"))
        try:
            result.http_status = int(str(status_raw)) if status_raw else None
        except (ValueError, TypeError):
            result.http_status = None

        result.http_title = page.get("title") or d_page.get("title")
        result.country    = page.get("country") or d_page.get("country")
        result.org        = page.get("asn") or d_page.get("asn")
        result.last_seen  = task.get("time") or d_task.get("time")

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
        seen_locs = set()
        for req in (detail.get("data", {}).get("requests", []) or [])[:20]:
            resp   = req.get("response", {}).get("response", {}) or {}
            status = resp.get("status", 0)
            if status in (301, 302, 307, 308):
                headers_dict = resp.get("headers") or {}
                # headers can be dict or list of {name, value}
                if isinstance(headers_dict, list):
                    loc = next((h.get("value","") for h in headers_dict
                                if h.get("name","").lower() == "location"), "")
                else:
                    loc = headers_dict.get("location", "") or headers_dict.get("Location", "")
                if loc and loc not in seen_locs:
                    seen_locs.add(loc)
                    result.redirects.append(loc)

        # ── Tags ─────────────────────────────────────────────────
        urlscan_tags = (
            hit.get("verdicts", {}).get("urlscan", {}).get("tags", []) or
            detail.get("verdicts", {}).get("urlscan", {}).get("tags", []) or []
        )
        result.tags = list(urlscan_tags)
        if result.redirects:
            result.tags.append(f"redirects:{len(result.redirects)}")
        if raw.get("_new_scan"):
            result.tags.append("fresh-scan")

        # ── Verdict ───────────────────────────────────────────────
        malicious = (
            hit.get("verdicts", {}).get("overall", {}).get("malicious", False)
            or detail.get("verdicts", {}).get("overall", {}).get("malicious", False)
        )
        result.verdict_hint = "malicious" if malicious else "unknown"

        # ── Lists → graph enrichment ──────────────────────────────
        lists = detail.get("lists", {}) or {}
        raw["_lists"] = {
            "ips":     (lists.get("ips")     or [])[:10],
            "domains": [d for d in (lists.get("domains") or [])[:10]
                        if d and d != ioc.value],   # exclude exact self match
            "hashes":  (lists.get("hashes")  or [])[:5],
            "urls":    (lists.get("urls")     or [])[:5],
        }

        # ── Reports for timeline ───────────────────────────────────
        result.reports = []
        if result.last_seen:
            parts = []
            if result.http_status:
                parts.append(f"HTTP {result.http_status}")
            if result.http_title:
                parts.append(f'"{result.http_title[:50]}"')
            if result.technologies:
                parts.append(", ".join(result.technologies[:3]))
            summary = f"URLScan — {' · '.join(parts)}" if parts else "URLScan — Scanned"
            result.reports.append({
                "date":     result.last_seen[:19],
                "summary":  summary,
                "source":   "urlscan",
                "category": "web_osint",
            })
        if result.redirects:
            result.reports.append({
                "date":     result.last_seen[:19] if result.last_seen else None,
                "summary":  f"Redirects ({len(result.redirects)}): "
                            + " → ".join(r[:60] for r in result.redirects[:3]),
                "source":   "urlscan",
                "category": "web_osint",
            })
