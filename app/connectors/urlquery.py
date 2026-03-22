"""
urlquery.py — urlquery.net connector for Evil Origin Detection.

API: https://urlquery.net/doc/api/public/v1
Key required via URLQUERY_KEY env variable.

Endpoints used:
  GET /public/v1/reputation/check/?query={ioc}
      → {url, verdict}  verdict: malware|phishing|fraud|suspicious|''
  GET /public/v1/search/reports/?query={ioc}&limit=5
      → {total_hits, reports:[{report_id, date, url, ip, stats, summary}]}
  GET /public/v1/report/{report_id}  (best-effort, adds IDS alerts)
      → full report with sensors.ids, sensors.urlquery, files
"""
from __future__ import annotations

import asyncio
from typing import ClassVar, Optional

from app.connectors.base import BaseConnector, IOCType, NormalizedResult


BASE    = "https://urlquery.net"
API     = f"{BASE}/api/v1/public"

_SUPPORTED = {IOCType.domain, IOCType.url, IOCType.ip}


class URLQueryConnector(BaseConnector):
    SOURCE_NAME:       ClassVar[str]       = "urlquery"
    SUPPORTED_TYPES:   ClassVar[set]       = _SUPPORTED
    DATA_CATEGORIES:   ClassVar[set]       = {"reputation", "web", "threat"}
    TIMEOUT:                                 float = 20.0

    def requires_key(self) -> bool:
        return True

    # ──────────────────────────────────────────────────────────
    async def _fetch(self, ioc) -> dict:
        import httpx

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Accept":        "application/json",
            "User-Agent":    "Mozilla/5.0 (compatible; EOD/1.0; threat intelligence)",
        }
        value = ioc.value.strip()
        # For IPs: prepend https:// for URL-based APIs, use raw for reputation
        query_val = value

        result: dict = {"_ioc": value}

        async with httpx.AsyncClient(timeout=self.TIMEOUT,
                                     follow_redirects=True) as c:
            # ── Step 1: Reputation check (fast) ───────────────────
            try:
                rep = await c.get(
                    f"{BASE}/public/v1/reputation/check/",
                    params={"query": query_val},
                    headers=headers,
                )
                if rep.status_code == 200:
                    result["_reputation"] = rep.json()
                elif rep.status_code in (401, 403):
                    result["_blocked"] = True
                    result["_status"]  = rep.status_code
                    return result
            except Exception as e:
                result["_rep_error"] = str(e)

            # ── Step 2: Search historical reports ─────────────────
            try:
                s = await c.get(
                    f"{BASE}/public/v1/search/reports/",
                    params={"query": query_val, "limit": 3},
                    headers=headers,
                )
                if s.status_code == 200:
                    search_data = s.json()
                    result["_search"] = search_data

                    # ── Step 3: Fetch latest full report ──────────
                    reports = search_data.get("reports", [])
                    if reports:
                        latest_id = reports[0].get("report_id")
                        if latest_id:
                            try:
                                r2 = await c.get(
                                    f"{BASE}/public/v1/report/{latest_id}",
                                    headers=headers,
                                    timeout=15.0,
                                )
                                if r2.status_code == 200:
                                    result["_report"] = r2.json()
                            except Exception:
                                pass  # best-effort
            except Exception as e:
                result["_search_error"] = str(e)

        return result

    # ──────────────────────────────────────────────────────────
    def normalize(self, raw: dict, ioc, result: NormalizedResult) -> None:
        import re as _re

        if raw.get("_blocked"):
            result.verdict_hint = "unknown"
            result.error = f"Blocked by urlquery.net (HTTP {raw.get('_status', 401)})"
            return

        # ── Reputation verdict ─────────────────────────────────
        rep_data = raw.get("_reputation") or {}
        verdict_str = (rep_data.get("verdict") or "").lower()
        result.verdict_hint = (
            "malicious"  if verdict_str in ("malware", "phishing", "fraud")   else
            "suspicious" if verdict_str == "suspicious"                          else
            "clean"      if verdict_str == ""                                    else
            "unknown"
        )

        # ── Search results ─────────────────────────────────────
        search   = raw.get("_search") or {}
        reports  = search.get("reports") or []
        full_rep = raw.get("_report")  or {}

        if not reports:
            return

        # Grab metadata from the latest report overview
        latest   = reports[0]
        page_ip  = (latest.get("ip") or {}).get("addr")
        page_url = (latest.get("url") or {}).get("fqdn") or raw.get("_ioc")
        rep_date = latest.get("date", "")[:10]

        # ── Tags from alerts and verdict ───────────────────────
        tags = []
        if verdict_str:
            tags.append(verdict_str)

        alert_count = (latest.get("stats") or {}).get("alert_count") or {}
        total_alerts = sum(alert_count.values()) if isinstance(alert_count, dict) else 0
        if total_alerts > 0:
            tags.append(f"{total_alerts}-alerts")
        result.tags = tags

        # ── IDS alerts from full report ────────────────────────
        ids_alerts = []
        if full_rep:
            sensors = full_rep.get("sensors") or {}
            for ids_sensor in (sensors.get("ids") or []):
                for alert in (ids_sensor.get("alerts") or [])[:4]:
                    ids_alerts.append({
                        "sensor":   ids_sensor.get("sensor_name", ""),
                        "alert":    alert.get("alert", ""),
                        "severity": alert.get("severity", ""),
                        "date":     (alert.get("date") or "")[:10],
                    })
            # urlquery-specific alerts
            for uq_alert in (sensors.get("urlquery") or [])[:4]:
                ids_alerts.append({
                    "sensor":   "urlquery",
                    "alert":    uq_alert.get("alert", ""),
                    "severity": uq_alert.get("severity", "medium"),
                    "date":     rep_date,
                })

        if ids_alerts:
            raw["_ids_alerts"] = ids_alerts

        # ── File detections from full report ───────────────────
        files = (full_rep.get("files") or []) if full_rep else []
        file_hashes = []
        for f in files[:4]:
            fh = f.get("sha256") or f.get("md5")
            if fh:
                file_hashes.append({
                    "sha256": f.get("sha256", ""),
                    "md5":    f.get("md5", ""),
                    "size":   f.get("size"),
                    "magic":  f.get("magic", ""),
                })
        if file_hashes:
            raw["_file_hashes"] = file_hashes

        # ── Credential leak scan in JS/DOM ─────────────────────
        credential_leaks = []
        js_data = (full_rep.get("javascript") or {}) if full_rep else {}
        sources_to_scan = []
        for script in (js_data.get("script") or [])[:10]:
            sources_to_scan.append(script.get("data", ""))
        for ev in (js_data.get("eval") or [])[:10]:
            sources_to_scan.append(ev.get("data", ""))
        for wr in (js_data.get("write") or [])[:10]:
            sources_to_scan.append(wr.get("data", ""))

        # Also scan HTTP transactions for POST bodies
        http_txns = (full_rep.get("http") or []) if full_rep else []
        for txn in http_txns[:20]:
            req = txn.get("request") or {}
            sources_to_scan.append(req.get("raw", ""))

        all_source = "\n".join(str(s) for s in sources_to_scan if s)

        # Telegram bot token pattern
        tg_tokens = _re.findall(
            r'(?:bot|token)[=: \'"]+([0-9]{8,12}:[A-Za-z0-9_\-]{35,})',
            all_source, _re.IGNORECASE
        )
        for tok in tg_tokens[:5]:
            parts = tok.split(":")
            bot_id = parts[0] if len(parts) > 1 else ""
            credential_leaks.append({
                "type":     "telegram_bot_token",
                "token":    tok[:15] + "…" + tok[-6:],  # truncate middle
                "token_full": tok,
                "chat_id":  None,
                "url":      f"https://api.telegram.org/bot{tok}/getMe",
            })

        # Telegram chat_id pattern (often near token)
        chat_ids = _re.findall(
            r'chat[_\-]?id[=: \'"]+(-?[0-9]{6,15})',
            all_source, _re.IGNORECASE
        )
        # attach chat_id to last Telegram leak if found
        if chat_ids and credential_leaks:
            for leak in credential_leaks:
                if leak["type"] == "telegram_bot_token" and not leak["chat_id"]:
                    leak["chat_id"] = chat_ids[0]
                    break

        # Discord webhook pattern
        discord_webhooks = _re.findall(
            r"(https://(?:ptb\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+)",
            all_source
        )
        for wh in discord_webhooks[:5]:
            credential_leaks.append({
                "type":  "discord_webhook",
                "token": wh[-20:],
                "token_full": wh,
                "chat_id": None,
                "url":   wh,
            })

        if credential_leaks:
            result.credential_leaks = credential_leaks
            if result.verdict_hint == "clean":
                result.verdict_hint = "suspicious"
            if "credential-leak" not in result.tags:
                result.tags = list(result.tags or []) + ["credential-leak"]

        # ── Reports for timeline ───────────────────────────────
        result.reports = []
        if verdict_str and verdict_str != "":
            result.reports.append({
                "date":     rep_date,
                "summary":  f"urlquery.net — verdict: {verdict_str}" +
                            (f" · {total_alerts} IDS alert(s)" if total_alerts else ""),
                "source":   "urlquery",
                "category": "threat" if verdict_str in ("malware", "phishing", "fraud") else "info",
            })
        for alert in ids_alerts[:3]:
            if alert.get("alert"):
                result.reports.append({
                    "date":     alert.get("date"),
                    "summary":  f"IDS: {alert['alert']}" +
                                (f" [{alert['severity']}]" if alert.get("severity") else ""),
                    "source":   "urlquery",
                    "category": "threat",
                })
