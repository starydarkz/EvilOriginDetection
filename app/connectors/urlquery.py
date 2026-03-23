"""
urlquery.py — urlquery.net connector for Evil Origin Detection.

API: https://api.urlquery.net/public/v1
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


BASE    = "https://api.urlquery.net"
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
            "X-APIKEY": self.api_key,
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
            # Try both with header key and query param key
            rep_urls = [
                (f"{BASE}/public/v1/reputation/check/", {"query": query_val}, headers),
                (f"{BASE}/reputation/check/",           {"query": query_val}, headers),
                (f"{BASE}/public/v1/reputation/check/", {"query": query_val, "apikey": self.api_key}, {"Accept":"application/json"}),
            ]
            try:
                rep = None
                for _url, _params, _hdrs in rep_urls:
                    try:
                        _r = await c.get(_url, params=_params, headers=_hdrs)
                        try:
                            from app.logger import app_logger
                            app_logger.info(f"[urlquery] probe {_url} → {_r.status_code} body={_r.text[:80]!r}")
                        except Exception: pass
                        if _r.status_code == 200:
                            rep = _r
                            break
                        elif _r.status_code in (401, 403):
                            rep = _r
                            break  # auth issue, no point trying others
                    except Exception as _pe:
                        try:
                            from app.logger import app_logger
                            app_logger.warning(f"[urlquery] probe error {_url}: {_pe}")
                        except Exception: pass
                if rep is None:
                    return {"_blocked": True, "_status": 404}
                rep = rep  # use the last attempted
                try:
                    from app.logger import app_logger
                    rep_body = rep.text[:200] if rep.status_code != 200 else str(rep.json())[:100]
                    app_logger.info(f"[urlquery] reputation status={rep.status_code} body={rep_body!r}")
                except Exception:
                    pass
                if rep.status_code == 200:
                    result["_reputation"] = rep.json()
                elif rep.status_code in (401, 403, 404):
                    # 404 often means wrong endpoint or key required
                    # Try again with key as query parameter
                    try:
                        rep2 = await c.get(
                            f"{BASE}/public/v1/reputation/check/",
                            params={"query": query_val, "apikey": self.api_key},
                            headers={"Accept": "application/json"},
                        )
                        from app.logger import app_logger
                        app_logger.warning(
                            f"[urlquery] retry with apikey param: "
                            f"status={rep2.status_code} body={rep2.text[:100]!r}"
                        )
                        if rep2.status_code == 200:
                            result["_reputation"] = rep2.json()
                        else:
                            result["_blocked"] = True
                            result["_status"]  = rep.status_code
                            return result
                    except Exception as _e2:
                        result["_blocked"] = True
                        result["_status"]  = rep.status_code
                        return result
            except Exception as e:
                result["_rep_error"] = str(e)

            # ── Step 2: Search historical reports ─────────────────
            try:
                # Search 1: by domain/value - get more results
                s = await c.get(
                    f"{BASE}/public/v1/search/reports/",
                    params={"query": query_val, "limit": 10},
                    headers=headers,
                )
                if s.status_code == 200:
                    search_data = s.json()
                    result["_search"] = search_data

                    # Search 2: look specifically for Telegram/malware reports
                    # Try with detection filter
                    all_reports = list(search_data.get("reports") or [])
                    try:
                        s2 = await c.get(
                            f"{BASE}/public/v1/search/reports/",
                            params={"query": query_val, "limit": 10,
                                    "detection": "malware"},
                            headers=headers,
                        )
                        if s2.status_code == 200:
                            d2 = s2.json()
                            extra = d2.get("reports") or []
                            # Add any new report IDs not already in list
                            existing_ids = {r.get("report_id") for r in all_reports}
                            for rep in extra:
                                if rep.get("report_id") not in existing_ids:
                                    all_reports.append(rep)
                                    existing_ids.add(rep.get("report_id"))
                            from app.logger import app_logger
                            app_logger.info(
                                f"[urlquery] detection=malware search: "
                                f"status={s2.status_code} "
                                f"extra_reports={len(extra)} "
                                f"new_added={len(all_reports)-len(search_data.get('reports') or [])}"
                            )
                    except Exception as _s2e:
                        try:
                            from app.logger import app_logger
                            app_logger.info(f"[urlquery] detection search skipped: {_s2e}")
                        except Exception: pass

                    # Also log each report's detection field to find Telegram
                    try:
                        from app.logger import app_logger
                        for i, rep in enumerate(all_reports[:6]):
                            det = rep.get("detection") or {}
                            tags = rep.get("tags") or []
                            app_logger.info(
                                f"[urlquery] report[{i}] id={rep.get('report_id','?')[:8]} "
                                f"tags={tags[:4]} "
                                f"detection_keys={list(det.keys())[:5] if isinstance(det, dict) else det}"
                            )
                    except Exception: pass

                    # Use combined reports list
                    search_data = dict(search_data)
                    search_data["reports"] = all_reports
                    result["_search"] = search_data

                    try:
                        from app.logger import app_logger
                        app_logger.info(
                            f"[urlquery] search status={s.status_code} "
                            f"total_hits={search_data.get('total_hits',0)} "
                            f"reports={len(all_reports)}"
                        )
                    except Exception:
                        pass

                    # ── Step 3: Fetch ALL reports, pick the richest ─────
                # (Telegram bot / malware might be in older report, not newest)
                reports = search_data.get("reports", [])
                if reports:
                    import asyncio as _asyncio

                    async def _fetch_report(rep_item):
                        rid = (rep_item.get("report_id") or
                               rep_item.get("id") or
                               rep_item.get("report"))
                        if not rid:
                            return None
                        try:
                            r2 = await c.get(
                                f"{BASE}/public/v1/report/{rid}",
                                headers=headers,
                                timeout=15.0,
                            )
                            if r2.status_code == 200:
                                data = r2.json()
                                # sensors at top level OR inside 'final'
                                sensors = (data.get("sensors") or
                                           (data.get("final") or {}).get("sensors") or {})
                                uq_sens = sensors.get("urlquery") or []
                                ids_sens = sensors.get("ids") or []
                                # Score: telegram=100, other uq alerts=10, ids=5, just data=1
                                score = 0
                                for a in uq_sens:
                                    alert_txt = (a.get("alert") or "").lower()
                                    if "telegram" in alert_txt:
                                        score += 100
                                    elif a.get("meta") or a.get("tags"):
                                        score += 10
                                    else:
                                        score += 5
                                for ids_blk in ids_sens:
                                    # ids_blk might have .alerts[] or direct alert fields
                                    alerts_list = (ids_blk.get("alerts") or
                                                   [ids_blk] if ids_blk.get("alert") else [])
                                    score += len(alerts_list) * 2
                                try:
                                    from app.logger import app_logger
                                    final_keys = list((data.get("final") or {}).keys())[:6]
                                    app_logger.info(
                                        f"[urlquery] report {rid} score={score} "
                                        f"uq={len(uq_sens)} ids={len(ids_sens)} "
                                        f"final_keys={final_keys} "
                                        f"alerts={[a.get('alert','?')[:40] for a in uq_sens[:2]]}"
                                    )
                                except Exception: pass
                                return (score, data)
                        except Exception as _fe:
                            try:
                                from app.logger import app_logger
                                app_logger.warning(f"[urlquery] report {rid} fetch error: {_fe}")
                            except Exception: pass
                        return None

                    # Fetch all reports concurrently
                    tasks = [_fetch_report(r) for r in reports[:3]]
                    fetched = await _asyncio.gather(*tasks)
                    fetched = [(s, d) for r in fetched if r for s, d in [r]]

                    if fetched:
                        best_score, best_report = max(fetched, key=lambda x: x[0])
                        result["_report"] = best_report
                        try:
                            from app.logger import app_logger
                            sensors = best_report.get("sensors") or {}
                            arts    = best_report.get("artifacts") or {}
                            app_logger.info(
                                f"[urlquery] best report score={best_score} "
                                f"uq={len(sensors.get('urlquery') or [])} "
                                f"telegram_artifacts={len((arts.get('telegram') or []))}"
                            )
                        except Exception: pass
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

        try:
            from app.logger import app_logger
            app_logger.info(
                f"[urlquery] normalize: reports={len(reports)} "
                f"full_rep_keys={list(full_rep.keys())[:8] if full_rep else []} "
                f"raw_keys={[k for k in raw if k.startswith('_')]}"
            )
        except Exception: pass

        if not reports:
            return

        # Grab metadata from the latest report overview
        # Find the report with the richest detection data
        # Sort by: has telegram > has detection data > most recent
        def _rep_score(r):
            det = r.get("detection") or {}
            tags = r.get("tags") or []
            tag_str = " ".join(str(t).lower() for t in tags)
            det_str = str(det).lower()
            if "telegram" in tag_str or "telegram" in det_str:
                return 100
            if det:
                return 10
            return 0

        reports_sorted = sorted(reports, key=_rep_score, reverse=True)
        latest = reports_sorted[0]

        try:
            from app.logger import app_logger
            app_logger.info(
                f"[urlquery] best_search_report: id={latest.get('report_id','?')[:8]} "
                f"score={_rep_score(latest)} "
                f"tags={latest.get('tags',[])} "
                f"detection_keys={list((latest.get('detection') or {}).keys())[:6]}"
            )
        except Exception: pass

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
            # sensors can be at top level OR nested inside 'final'
            sensors = (full_rep.get("sensors") or
                       (full_rep.get("final") or {}).get("sensors") or {})
            try:
                from app.logger import app_logger
                final_keys = list((full_rep.get("final") or {}).keys())[:8]
                app_logger.info(
                    f"[urlquery] sensors_lookup: top={bool(full_rep.get('sensors'))} "
                    f"final_keys={final_keys} "
                    f"sensors_keys={list(sensors.keys())} "
                    f"uq_count={len(sensors.get('urlquery') or [])}"
                )
            except Exception: pass
            for ids_sensor in (sensors.get("ids") or []):
                for alert in (ids_sensor.get("alerts") or [])[:4]:
                    ids_alerts.append({
                        "sensor":   ids_sensor.get("sensor_name", ""),
                        "alert":    alert.get("alert", ""),
                        "severity": alert.get("severity", ""),
                        "date":     (alert.get("date") or "")[:10],
                    })
            # ── Artifacts: Telegram Bot (report.artifacts.telegram[]) ───
            # urlquery stores confirmed Telegram bot data in artifacts, not sensors
            artifacts = full_rep.get("artifacts") or {}
            telegram_artifacts = artifacts.get("telegram") or []
            if telegram_artifacts:
                try:
                    from app.logger import app_logger
                    app_logger.info(
                        f"[urlquery] artifacts.telegram count={len(telegram_artifacts)} "
                        f"keys={list(telegram_artifacts[0].keys())[:8]}"
                    )
                except Exception: pass
                for tg in telegram_artifacts:
                    url_obj  = tg.get("url") or {}
                    bot_obj  = tg.get("bot") or {}
                    chat_obj = tg.get("chat") or {}
                    token    = tg.get("token") or ""
                    url_str  = (url_obj.get("fqdn") or url_obj.get("addr") or "")
                    ip_obj   = tg.get("ip") or {}
                    ip_str   = ip_obj.get("addr", "") if isinstance(ip_obj, dict) else ""
                    sa = {
                        "sensor":   "urlquery",
                        "alert":    "Telegram Bot detected",
                        "severity": "high",
                        "date":     rep_date,
                        "url":      url_str[:200],
                        "ip":       ip_str,
                        "telegram": {
                            "token":      token,
                            "user_id":    bot_obj.get("id"),
                            "username":   bot_obj.get("username", ""),
                            "first_name": bot_obj.get("first_name", ""),
                            "last_name":  bot_obj.get("last_name", ""),
                            "chat_id":    chat_obj.get("id"),
                            "chat_type":  chat_obj.get("type", ""),
                            "chat_title": chat_obj.get("title", ""),
                            "user_count": chat_obj.get("members_count"),
                            "admins":     chat_obj.get("admins_count"),
                            "pending":    None,
                        },
                    }
                    ids_alerts.append({"sensor":"urlquery","alert":"Telegram Bot detected",
                                       "severity":"high","date":rep_date})
                    raw.setdefault("_uq_sensor_alerts", []).append(sa)
                    result.tags = list(result.tags or []) + ["telegram-bot"]
                    result.verdict_hint = "malicious"
                    try:
                        from app.logger import app_logger
                        app_logger.info(
                            f"[urlquery] Telegram artifact extracted: "
                            f"token={bool(token)} "
                            f"@{bot_obj.get('username','?')} "
                            f"chat={chat_obj.get('title','?')!r}"
                        )
                    except Exception: pass

            # ── detection.analyzer YARA hits (Telegram / malware) ────────
            detect = full_rep.get("detection") or {}
            for hit in (detect.get("analyzer") or [])[:5]:
                htxt = hit.get("alert") or ""
                if htxt and "telegram" in htxt.lower():
                    ids_alerts.append({
                        "sensor":   hit.get("sensor_name", "analyzer"),
                        "alert":    htxt,
                        "severity": hit.get("severity", "medium"),
                        "date":     rep_date,
                    })

            # urlquery-specific alerts — capture FULL detail
            uq_sensor_alerts = []
            for uq_alert in (sensors.get("urlquery") or [])[:10]:
                alert_txt = uq_alert.get("alert", "")
                if not alert_txt:
                    continue
                # Build rich alert object with all available metadata
                # URL and IP can be at top-level or inside meta
                meta    = uq_alert.get("meta") or {}
                url_val = uq_alert.get("url") or meta.get("url") or ""
                ip_val  = ((uq_alert.get("ip") or {}).get("addr") or
                            meta.get("ip") or "")

                alert_obj = {
                    "sensor":   "urlquery",
                    "alert":    alert_txt,
                    "severity": uq_alert.get("severity", "medium"),
                    "date":     rep_date,
                    "url":      url_val[:200] if url_val else "",
                    "ip":       ip_val,
                }

                # Telegram Bot: check both top-level AND meta fields
                # urlquery stores: meta.token, meta.bot_overview, meta.chat_info
                # OR: token, bot_overview, chat_info at top level
                is_telegram = "telegram" in alert_txt.lower()
                token   = (uq_alert.get("token") or
                           meta.get("token") or
                           meta.get("bot_token") or "")
                bot_ov  = (uq_alert.get("bot_overview") or
                           meta.get("bot_overview") or
                           meta.get("bot") or {})
                chat_i  = (uq_alert.get("chat_info") or
                           meta.get("chat_info") or
                           meta.get("chat") or {})

                # Also check tags for telegram evidence
                tags = uq_alert.get("tags") or []
                if any("telegram" in str(t).lower() for t in tags):
                    is_telegram = True

                if is_telegram or token or bot_ov:
                    alert_obj["telegram"] = {
                        "token":       token,
                        "user_id":     bot_ov.get("user_id") or bot_ov.get("id"),
                        "username":    bot_ov.get("username", ""),
                        "first_name":  bot_ov.get("first_name", ""),
                        "last_name":   bot_ov.get("last_name", ""),
                        "chat_id":     chat_i.get("chat_id") or chat_i.get("id"),
                        "chat_type":   chat_i.get("chat_type") or chat_i.get("type", ""),
                        "chat_title":  chat_i.get("title", ""),
                        "user_count":  chat_i.get("user_count") or chat_i.get("members_count"),
                        "admins":      chat_i.get("admins"),
                        "pending":     chat_i.get("pending_msgs"),
                    }
                    # Log full meta for debugging
                    try:
                        from app.logger import app_logger
                        app_logger.info(
                            f"[urlquery] telegram meta: token={bool(token)} "
                            f"bot_ov_keys={list(bot_ov.keys())} "
                            f"chat_keys={list(chat_i.keys())} "
                            f"meta_keys={list(meta.keys())[:10]}"
                        )
                    except Exception: pass
                ids_alerts.append({
                    "sensor":   "urlquery",
                    "alert":    alert_txt,
                    "severity": uq_alert.get("severity", "medium"),
                    "date":     rep_date,
                })
                uq_sensor_alerts.append(alert_obj)

            if uq_sensor_alerts:
                raw["_uq_sensor_alerts"] = uq_sensor_alerts
                try:
                    from app.logger import app_logger
                    for sa in uq_sensor_alerts:
                        tg = sa.get("telegram") or {}
                        app_logger.info(
                            f"[urlquery] sensor_alert: {sa.get('alert')!r} "
                            f"has_telegram={bool(tg)} "
                            f"token={bool(tg.get('token'))} "
                            f"username={tg.get('username','')!r}"
                        )
                except Exception: pass

        if ids_alerts:
            raw["_ids_alerts"] = ids_alerts
            try:
                from app.logger import app_logger
                app_logger.info(f"[urlquery] ids_alerts extracted: {len(ids_alerts)}")
            except Exception: pass

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

        # ── Detected URLs from HTTP transactions ───────────────
        if full_rep:
            uq_http = full_rep.get("http") or []
            detected_urls = []
            for txn in uq_http[:30]:
                req_obj = txn.get("request") or {}
                rsp_obj = txn.get("response") or {}
                url = req_obj.get("url") or req_obj.get("uri") or ""
                method = req_obj.get("method", "GET")
                status = rsp_obj.get("status") or rsp_obj.get("status_code") or 0
                if url:
                    detected_urls.append({
                        "url":    url[:200],
                        "method": method,
                        "status": status,
                    })
            if detected_urls:
                raw["_detected_urls"] = detected_urls

            # ── URLQuery sensor alerts (non-IDS) ──────────────
            sensors  = full_rep.get("sensors") or {}
            uq_alerts = []
            for alert in (sensors.get("urlquery") or []):
                txt = alert.get("alert") or alert.get("description") or ""
                if txt:
                    uq_alerts.append({
                        "alert":    txt,
                        "severity": alert.get("severity", "medium"),
                        "type":     "urlquery",
                    })
            # Also include IDS alerts summary
            for ids_sensor in (sensors.get("ids") or []):
                for alert in (ids_sensor.get("alerts") or [])[:5]:
                    txt = alert.get("alert") or alert.get("signature") or ""
                    if txt:
                        uq_alerts.append({
                            "alert":    txt,
                            "severity": alert.get("severity", "medium"),
                            "type":     "ids",
                        })
            if uq_alerts:
                raw["_uq_alerts"] = uq_alerts

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
