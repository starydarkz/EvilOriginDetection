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
                return {"results": [], "_status": r.status_code, "_debug": f"search {r.status_code}"}
            if r.status_code == 429:
                raise Exception("URLScan rate limit exceeded")
            if r.status_code != 200:
                return {"results": [], "_debug": f"search HTTP {r.status_code}"}

            data    = r.json()
            results = data.get("results", [])
            data["_debug_search"] = {
                "total": data.get("total", 0),
                "results_count": len(results),
                "first_uuid": results[0].get("task",{}).get("uuid") if results else None,
                "first_screenshot": results[0].get("task",{}).get("screenshotURL") if results else None,
            }

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
                            data["_debug_detail"] = {
                                "status": r2.status_code,
                                "has_screenshot": bool(data["_detail"].get("task",{}).get("screenshotURL")),
                                "screenshot_url": data["_detail"].get("task",{}).get("screenshotURL"),
                            }
                        else:
                            data["_debug_detail"] = {"status": r2.status_code, "error": r2.text[:100]}
                    except Exception as _de:
                        data["_debug_detail"] = {"error": str(_de)}
                        pass   # detail is best-effort

            return data

    def normalize(self, raw: dict, ioc: ParsedIOC,
                  result: NormalizedResult) -> None:
        # Debug logging
        _ds = raw.get("_debug_search", {})
        _dd = raw.get("_debug_detail", {})
        try:
            from app.logger import app_logger
            app_logger.debug(f"[urlscan] {ioc.value} | search: {_ds} | detail: {_dd}")
        except Exception:
            pass

        results = raw.get("results", [])
        if not results:
            result.verdict_hint = "unknown"
            return

        hit    = results[0]
        task   = hit.get("task",    {}) or {}
        page   = hit.get("page",    {}) or {}
        vstats = hit.get("stats",   {}) or {}
        detail = raw.get("_detail", {}) or {}
        d_task = detail.get("task", {}) or {}
        d_page = detail.get("page", {}) or {}
        d_meta = detail.get("meta", {}) or {}
        d_lists= detail.get("lists",{}) or {}
        d_stats= detail.get("stats",{}) or {}
        d_verd = detail.get("verdicts", {}) or {}

        uuid = task.get("uuid") or d_task.get("uuid")

        # ── Screenshot URL ─────────────────────────────────────────
        if uuid:
            result.screenshot_url = f"https://urlscan.io/screenshots/{uuid}.png"
        else:
            result.screenshot_url = task.get("screenshotURL") or d_task.get("screenshotURL")

        # ── Direct result link ─────────────────────────────────────
        result_url = (task.get("reportURL") or d_task.get("reportURL")
                      or (f"https://urlscan.io/result/{uuid}/" if uuid else None))
        if result_url:
            raw["_result_url"] = result_url

        # ── DOM snapshot link ──────────────────────────────────────
        dom_url = task.get("domURL") or d_task.get("domURL")
        if dom_url:
            raw["_dom_url"] = dom_url

        # ── HTTP info ─────────────────────────────────────────────
        status_raw = page.get("status") or d_page.get("status")
        try:
            result.http_status = int(str(status_raw)) if status_raw else None
        except (ValueError, TypeError):
            result.http_status = None

        result.http_title = page.get("title")   or d_page.get("title")
        result.country    = page.get("country") or d_page.get("country")
        result.last_seen  = task.get("time")    or d_task.get("time")

        # ── IP + ASN + org from page ───────────────────────────────
        server_ip  = page.get("ip")      or d_page.get("ip")
        asn_num    = page.get("asn")     or d_page.get("asn")
        asn_name   = page.get("asnname") or d_page.get("asnname")  # "FACEBOOK, US"
        server_hdr = page.get("server")  or d_page.get("server")   # "proxygen-bolt"
        mime_type  = page.get("mimeType") or d_page.get("mimeType")

        # Prefer readable org name (asnname) over raw ASN number
        if asn_name:
            result.org = asn_name.split(",")[0].strip()  # "FACEBOOK" from "FACEBOOK, US"
        elif asn_num:
            result.org = asn_num
        result.asn = asn_num

        # Store server IP for graph enrichment
        if server_ip:
            raw["_server_ip"] = server_ip

        # ── Technologies (Wappalyzer + server header) ─────────────
        wappa = d_meta.get("processors", {}).get("wappa", {}).get("data", [])
        techs = []
        for t in (wappa or []):
            app_name = t.get("app") or ""
            version  = t.get("version") or ""
            if app_name:
                # Include version if meaningful (not empty, not just "0")
                label = f"{app_name} {version}".strip() if version and version != "0" else app_name
                techs.append(label)
        # Add server header as tech if not already covered
        if server_hdr and not any(server_hdr.lower() in t.lower() for t in techs):
            techs.append(server_hdr)
        result.technologies = techs[:15]

        # ── SSL / TLS certificate ─────────────────────────────────
        tls = d_page.get("tlsIssued") or {}
        certs_list = d_lists.get("certificates") or []
        if tls or certs_list:
            raw["_tls"] = {
                "valid_from": tls.get("validFrom"),
                "valid_to":   tls.get("validTo"),
                "issuer":     tls.get("issuer"),
                "count":      len(certs_list),
            }

        # ── Security headers from first response ──────────────────
        sec_headers = {}
        for req in (detail.get("data", {}).get("requests", []) or [])[:5]:
            resp = req.get("response", {}).get("response", {}) or {}
            hdrs = resp.get("headers") or {}
            if isinstance(hdrs, dict):
                for h in ("content-security-policy", "x-frame-options",
                          "strict-transport-security", "x-content-type-options"):
                    if h in hdrs or h.title() in hdrs:
                        sec_headers[h] = hdrs.get(h) or hdrs.get(h.title())
            elif isinstance(hdrs, list):
                for item in hdrs:
                    name = (item.get("name") or "").lower()
                    for h in ("content-security-policy", "x-frame-options",
                              "strict-transport-security", "x-content-type-options"):
                        if name == h:
                            sec_headers[h] = item.get("value")
            if sec_headers:
                break
        if sec_headers:
            raw["_security_headers"] = sec_headers

        # ── Redirect chain ────────────────────────────────────────
        result.redirects = []
        seen_locs = set()
        for req in (detail.get("data", {}).get("requests", []) or [])[:30]:
            resp   = req.get("response", {}).get("response", {}) or {}
            status = resp.get("status", 0)
            if status in (301, 302, 307, 308):
                hdrs = resp.get("headers") or {}
                if isinstance(hdrs, list):
                    loc = next((h.get("value","") for h in hdrs
                                if h.get("name","").lower() == "location"), "")
                else:
                    loc = hdrs.get("location","") or hdrs.get("Location","")
                if loc and loc not in seen_locs:
                    seen_locs.add(loc)
                    result.redirects.append(loc)

        # ── Community votes ────────────────────────────────────────
        community = (hit.get("verdicts",{}).get("community",{})
                     or d_verd.get("community", {}))
        community_votes = community.get("votes", {}) if isinstance(community, dict) else {}
        benign_votes    = community_votes.get("benign", 0)
        malicious_votes = community_votes.get("malicious", 0)

        # ── Stats ─────────────────────────────────────────────────
        uniq_ips     = d_stats.get("uniqIPs")     or vstats.get("uniqIPs", 0)
        total_links  = d_stats.get("totalLinks")  or vstats.get("totalLinks", 0)
        total_cookies= d_stats.get("totalCookies",0)
        stat_malicious = d_stats.get("malicious", 0)

        # Store extended stats for template
        raw["_web_stats"] = {
            "uniq_ips":      uniq_ips,
            "total_links":   total_links,
            "total_cookies": total_cookies,
            "mime_type":     mime_type,
            "benign_votes":  benign_votes,
            "malicious_votes": malicious_votes,
            "server_ip":     server_ip,
        }

        # ── Tags ─────────────────────────────────────────────────
        urlscan_tags = (
            hit.get("verdicts",{}).get("urlscan",{}).get("tags", []) or
            d_verd.get("urlscan",{}).get("tags", []) or []
        )
        result.tags = list(urlscan_tags)
        if result.redirects:
            result.tags.append(f"redirects:{len(result.redirects)}")
        if raw.get("_new_scan"):
            result.tags.append("fresh-scan")
        if malicious_votes > 0:
            result.tags.append(f"community-malicious:{malicious_votes}")
        if sec_headers:
            result.tags.append("has-security-headers")

        # ── Verdict ───────────────────────────────────────────────
        malicious = (
            hit.get("verdicts",{}).get("overall",{}).get("malicious", False)
            or d_verd.get("overall",{}).get("malicious", False)
            or malicious_votes > 0
            or stat_malicious > 0
        )
        result.verdict_hint = "malicious" if malicious else "unknown"

        # ── Lists → graph enrichment ──────────────────────────────
        raw["_lists"] = {
            "ips":         (d_lists.get("ips")         or [])[:10],
            "domains":     [d for d in (d_lists.get("domains")     or [])[:10]
                            if d and d != ioc.value],
            "hashes":      (d_lists.get("hashes")      or [])[:5],
            "urls":        (d_lists.get("urls")         or [])[:5],
            "linkDomains": [d for d in (d_lists.get("linkDomains") or [])[:8]
                            if d and d != ioc.value],
        }

        # ── Reports for timeline ───────────────────────────────────
        result.reports = []
        if result.last_seen:
            parts = []
            if result.http_status:
                parts.append(f"HTTP {result.http_status}")
            if result.http_title:
                parts.append(f'"{result.http_title[:40]}"')
            if result.technologies:
                parts.append(", ".join(t.split()[0] for t in result.technologies[:3]))
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
                "summary":  (f"Redirect chain ({len(result.redirects)}): "
                             + " → ".join(r[:55] for r in result.redirects[:3])),
                "source":   "urlscan",
                "category": "web_osint",
            })
