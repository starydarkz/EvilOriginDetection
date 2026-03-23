"""
results.py — Results / analysis page router.
GET /results/{ioc_id} → render full analysis view.
GET /results/{ioc_id}/graph → graph data as JSON for Cytoscape.js.
POST /results/{ioc_id}/rescan → force fresh analysis.
"""
import re
import json
import traceback
from app.logger import app_logger, exc_logger, log_query
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models import IOC, SourceResult, ScanHistory, Correlation
from app.parser import ParsedIOC, IOCType

router    = APIRouter()
templates = Jinja2Templates(directory="templates")


@router.get("/results/{ioc_id}", response_class=HTMLResponse)
async def results_page(
    ioc_id:  int,
    request: Request,
    db:      AsyncSession = Depends(get_db),
):
    try:
        return await _results_page_inner(ioc_id, request, db)
    except Exception as e:
        tb = traceback.format_exc()
        exc_logger.error(f"results_page failed for ioc_id={ioc_id}:\n{tb}")
        app_logger.error(f"500 on /results/{ioc_id} — {type(e).__name__}: {e}")
        raise


async def _results_page_inner(
    ioc_id:  int,
    request: Request,
    db:      AsyncSession,
):
    # Load IOC with all related data
    stmt = (
        select(IOC)
        .where(IOC.id == ioc_id)
        .options(
            selectinload(IOC.source_results),
            selectinload(IOC.scan_history),
        )
    )
    result = await db.execute(stmt)
    ioc    = result.scalar_one_or_none()

    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")

    # Parse JSON fields
    tags     = json.loads(ioc.tags     or "[]")
    metadata = json.loads(ioc.metadata_ or "{}")

    # Build source results map: source_name → normalized dict
    sources: dict = {}
    for sr in ioc.source_results:
        try:
            norm = json.loads(sr.normalized or "{}")
        except Exception:
            norm = {}
        # JSON serializes int dict keys as strings — restore int keys for services
        if isinstance(norm.get("services"), dict):
            norm["services"] = {
                int(k): v for k, v in norm["services"].items()
                if str(k).isdigit()
            }
        # Ensure new fields added in Phase 2/3 have defaults for old cached records
        norm.setdefault("services",   {})
        norm.setdefault("redirects",  [])
        norm.setdefault("reports",    [])
        norm.setdefault("http_title", None)
        norm.setdefault("is_proxy",   None)
        # Extract banners from CriminalIP raw for display
        if sr.source == "criminalip":
            try:
                raw_json = json.loads(sr.raw_json or "{}")
                banners   = raw_json.get("_banners",    {})
                vuln_pts  = raw_json.get("_vuln_ports", {})
                conn_doms = raw_json.get("_connected_domains", [])
                if banners:
                    norm["banners"]   = {int(k): v for k, v in banners.items()
                                         if str(k).isdigit()}
                if vuln_pts:
                    norm["vuln_ports"] = {int(k): v for k, v in vuln_pts.items()
                                          if str(k).isdigit()}
                if conn_doms:
                    norm["connected_domains"] = conn_doms
            except Exception:
                pass
        norm.setdefault("is_hosting", None)
        norm.setdefault("is_mobile",  None)
        norm.setdefault("is_scanner", None)
        norm.setdefault("is_darkweb", None)
        norm.setdefault("is_cloud",   None)
        # URLScan: extract all enriched fields from raw_json
        if sr.source == "urlscan":
            try:
                raw_us = json.loads(sr.raw_json or "{}")
                if raw_us.get("_result_url"):
                    norm["result_url"] = raw_us["_result_url"]
                if raw_us.get("_dom_url"):
                    norm["dom_url"] = raw_us["_dom_url"]
                web_stats = raw_us.get("_web_stats") or {}
                if web_stats:
                    norm["web_stats"] = web_stats
                if raw_us.get("_security_headers"):
                    norm["security_headers"] = raw_us["_security_headers"]
                if raw_us.get("_tls"):
                    norm["tls"] = raw_us["_tls"]
                if raw_us.get("_server_ip"):
                    norm["server_ip"] = raw_us["_server_ip"]
                _lists = raw_us.get("_lists") or {}
                if _lists.get("linkDomains"):
                    norm["link_domains"] = _lists["linkDomains"]
                if raw_us.get("_http_txns"):
                    norm["http_txns"] = raw_us["_http_txns"]
                if not norm.get("screenshot_url"):
                    uuid_us = None
                    # Try multiple sources for the UUID
                    dbg = raw_us.get("_debug_search") or {}
                    uuid_us = dbg.get("first_uuid")
                    if not uuid_us:
                        _res = raw_us.get("results", [])
                        if _res:
                            task = (_res[0].get("task") or {})
                            uuid_us = task.get("uuid")
                            # Also try screenshotURL from task
                            if not uuid_us:
                                ss_url = task.get("screenshotURL") or task.get("screenshot") or ""
                                import re as _re2a
                                _mu = _re2a.search(r'screenshots/([0-9a-fA-F-]{36})', ss_url)
                                if _mu: uuid_us = _mu.group(1)
                    # Try detail response
                    if not uuid_us:
                        _detail = raw_us.get("_detail") or {}
                        _dtask  = _detail.get("task") or {}
                        uuid_us = _dtask.get("uuid")
                        if not uuid_us:
                            ss_url2 = _dtask.get("screenshotURL") or ""
                            import re as _re2b
                            _mu2 = _re2b.search(r'screenshots/([0-9a-fA-F-]{36})', ss_url2)
                            if _mu2: uuid_us = _mu2.group(1)
                    # Try extracting from result_url
                    if not uuid_us and norm.get("result_url"):
                        import re as _re2
                        _m = _re2.search(r'/result/([0-9a-fA-F-]{36})/', norm["result_url"])
                        if _m: uuid_us = _m.group(1)
                    if uuid_us:
                        norm["screenshot_url"] = f"https://urlscan.io/screenshots/{uuid_us}.png"
            except Exception:
                pass
        # URLQuery: extract enriched fields from raw_json
        if sr.source == "urlquery":
            try:
                raw_uq = json.loads(sr.raw_json or "{}")
                _uq_raw_keys = [k for k in raw_uq if k.startswith("_")]
                try:
                    from app.logger import app_logger
                    app_logger.info(
                        f"[results] urlquery raw_json keys: {_uq_raw_keys} "
                        f"sensor_alerts={len(raw_uq.get('_uq_sensor_alerts') or [])}"
                    )
                except Exception: pass
                if raw_uq.get("_detected_urls"):
                    norm["detected_urls"] = raw_uq["_detected_urls"]
                if raw_uq.get("_uq_alerts"):
                    norm["uq_alerts"] = raw_uq["_uq_alerts"]
                if raw_uq.get("_uq_sensor_alerts"):
                    norm["uq_sensor_alerts"] = raw_uq["_uq_sensor_alerts"]
                if raw_uq.get("_ids_alerts"):
                    norm["ids_alerts"] = raw_uq["_ids_alerts"]
                if raw_uq.get("_file_hashes"):
                    norm["file_hashes"] = raw_uq["_file_hashes"]
            except Exception as _ue:
                try:
                    from app.logger import app_logger
                    app_logger.warning(f"[results] urlquery raw_json extraction error: {_ue}")
                except Exception: pass

        sources[sr.source] = {
            "status":     sr.status.value,
            "fetched_at": sr.fetched_at.isoformat() if sr.fetched_at else None,
            **norm,
        }

    # Scan history sorted by date desc
    history = sorted(ioc.scan_history, key=lambda h: h.scanned_at, reverse=True)

    # Build timeline events from source results + scan history
    timeline = _build_timeline(ioc, sources, history)

    # Check if result is cached (cache_until exists and > now)
    from datetime import datetime
    is_cached = bool(
        ioc.cache_until and ioc.cache_until > datetime.utcnow()
    )
    cache_age_h = None
    if ioc.last_scan:
        delta = datetime.utcnow() - ioc.last_scan
        cache_age_h = round(delta.total_seconds() / 3600, 1)

    # Geo data (if IP)
    geo = _extract_geo(sources) if ioc.type == IOCType.ip else None

    # Build source links for template (correct URLs per IOC type)
    ioc_type_str = ioc.type.value if ioc.type else "ip"
    source_links = {
        src: _source_link(src, ioc.value, ioc_type_str)
        for src in sources.keys()
    }
    # Override URLScan link with direct result URL if available
    us_result_url = sources.get("urlscan", {}).get("result_url")
    if us_result_url:
        source_links["urlscan"] = us_result_url

    # Merge and deduplicate ports + services + technologies from all sources
    # Priority: Shodan (most detailed) > Pulsedive > CriminalIP > others
    merged_ports    = []
    merged_techs    = []
    merged_services = {}   # port → {service, source}
    seen_ports      = set()
    seen_techs      = set()
    port_source     = {}   # port → source name

    for src_priority in ["shodan", "pulsedive", "criminalip", "urlscan",
                         "securitytrails"]:
        sdata = sources.get(src_priority, {})
        if sdata.get("status") != "ok":
            continue
        # Ports
        for p in (sdata.get("ports") or []):
            if p and p not in seen_ports:
                seen_ports.add(p)
                merged_ports.append(p)
                port_source[p] = src_priority
        # Services (port → service name) + banners
        _svc = sdata.get("services") or {}
        if isinstance(_svc, dict):
            for port, svc in _svc.items():
                try:
                    port_int = int(port)
                except (ValueError, TypeError):
                    continue
                if port_int not in merged_services and svc:
                    merged_services[port_int] = {
                        "service": svc,
                        "source":  src_priority,
                    }
        # Banners from CriminalIP
        _banners = sdata.get("banners") or {}
        if isinstance(_banners, dict):
            for port, banner in _banners.items():
                try:
                    port_int = int(port)
                except (ValueError, TypeError):
                    continue
                if port_int in merged_services:
                    merged_services[port_int]["banner"] = banner
                else:
                    merged_services[port_int] = {"banner": banner, "source": src_priority}
        # Technologies
        for t in (sdata.get("technologies") or []):
            tl = t.lower() if t else ""
            if t and tl not in seen_techs:
                seen_techs.add(tl)
                merged_techs.append(t)

    merged_ports.sort()
    merged_ports = merged_ports[:20]
    merged_techs = merged_techs[:12]

    # Merge all tags across sources, deduplicating
    all_tags_merged = []
    seen_tags_lower = set()
    for sdata in sources.values():
        if sdata.get("status") != "ok":
            continue
        for tag in (sdata.get("tags") or []):
            tl = tag.lower() if tag else ""
            if tag and tl not in seen_tags_lower:
                seen_tags_lower.add(tl)
                all_tags_merged.append(tag)

    # Also include ioc-level tags
    for tag in (tags or []):
        tl = tag.lower() if tag else ""
        if tag and tl not in seen_tags_lower:
            seen_tags_lower.add(tl)
            all_tags_merged.append(tag)
    all_tags_merged = all_tags_merged[:20]

    # ── Unified view — canonical fields merged across all sources ──────────
    # Template consumes these instead of source-specific dicts.
    # Priority order is encoded per field — best source wins.

    def first(*vals):
        """Return first non-None, non-empty value."""
        for v in vals:
            if v is not None and v != "" and v != [] and v != {}:
                return v
        return None

    def ok(src):
        return sources.get(src, {}).get("status") == "ok"

    sh  = sources.get("shodan",         {})
    vt  = sources.get("virustotal",      {})
    ab  = sources.get("abuseipdb",       {})
    cip = sources.get("criminalip",      {})
    pd  = sources.get("pulsedive",       {})
    st  = sources.get("securitytrails",  {})
    us  = sources.get("urlscan",         {})
    mb  = sources.get("malwarebazaar",   {})
    wmn = sources.get("whatsmyname",     {})
    sfs = sources.get("stopforumspam",   {})
    # ── New sources ───────────────────────────────────────────────────
    tf  = sources.get("threatfox",       {})
    uh  = sources.get("urlhaus",         {})
    fd  = sources.get("feodotracker",    {})
    ripe= sources.get("ripestat",        {})
    hl  = sources.get("hashlookup",      {})
    dns = sources.get("passivedns",      {})

    def _to_int(val) -> int | None:
        """Normalize http_status to int — URLScan returns string."""
        try:
            return int(str(val)) if val is not None else None
        except (ValueError, TypeError):
            return None

    def _tri_flag(vals: list) -> bool | None:
        """
        Tri-state flag merge across sources.
        True  → at least one source says True
        False → all sources that checked say False (none said True)
        None  → no source has data (all None/missing)
        """
        has_data = False
        for v in vals:
            if v is None:
                continue
            has_data = True
            if v:
                return True
        return False if has_data else None

    unified = {
        # ── Network / geo ─────────────────────────────────────────
        "country":    first(cip.get("country"), sh.get("country"),
                            ab.get("country"),  vt.get("country"),
                            pd.get("country")),
        "city":       first(cip.get("city"),    sh.get("city"),
                            pd.get("city")),
        "org":        first(sh.get("org"),      vt.get("org"),
                            cip.get("org"),     pd.get("org"),
                            ab.get("org")),
        "asn":        first(sh.get("asn"),      vt.get("asn"),
                            cip.get("asn"),     pd.get("asn")),
        "isp":        first(sh.get("isp"),      ab.get("isp")),
        "network":    first(vt.get("network"),  sh.get("network")),
        "hostnames":  first(sh.get("hostnames"), st.get("hostnames"), []),
        "usage_type": first(ab.get("usage_type")),
        # Tri-state network flags: True=confirmed / False=confirmed-not / None=unknown
        # A source returning False is different from a source not checking at all
        "is_tor":    _tri_flag([
                         cip.get("is_tor"),   # CriminalIP checks tor
                         ab.get("is_tor"),    # AbuseIPDB checks tor
                     ]),
        "is_vpn":    _tri_flag([
                         cip.get("is_vpn"),   # CriminalIP checks VPN
                     ]),
        "is_proxy":  _tri_flag([
                         cip.get("is_proxy") if ok("criminalip") else None,
                     ]),
        "is_hosting":_tri_flag([
                         cip.get("is_hosting") if ok("criminalip") else None,
                     ]),
        "is_mobile": _tri_flag([
                         cip.get("is_mobile") if ok("criminalip") else None,
                     ]),
        "is_scanner":_tri_flag([
                         cip.get("is_scanner") if ok("criminalip") else None,
                     ]),
        "is_darkweb":_tri_flag([
                         cip.get("is_darkweb") if ok("criminalip") else None,
                     ]),
        "is_cloud":  _tri_flag([
                         cip.get("is_cloud") if ok("criminalip") else None,
                     ]),
        "latitude":   first(pd.get("latitude")),
        "longitude":  first(pd.get("longitude")),

        # ── Ports / services (already merged above) ────────────────
        "ports":      merged_ports,
        "services":   merged_services,
        "port_source":port_source,

        # ── Domain / web ──────────────────────────────────────────
        "registrar":      first(pd.get("registrar"),     st.get("registrar")),
        "creation_date":  first(pd.get("creation_date"), st.get("creation_date")),
        "expiry_date":    first(pd.get("expiry_date"),   st.get("expiry_date")),
        "dns_records":    first(pd.get("dns_records"),   st.get("dns_records"), {}),
        "screenshot_url": first(us.get("screenshot_url"), pd.get("screenshot_url")),
        "link_domains":   us.get("link_domains") or [],
        "http_status":    _to_int(first(us.get("http_status"),   pd.get("http_status"))),
        "http_title":     first(us.get("http_title"),    pd.get("http_title")),
        "technologies":   merged_techs,
        "redirects":      first(us.get("redirects"),     pd.get("redirects"), []),

        # ── Threat / file ─────────────────────────────────────────
        "malicious_count": vt.get("malicious_count", 0),
        "total_engines":   vt.get("total_engines", 0),
        "abuse_score":     first(ab.get("abuse_score"),  cip.get("abuse_score")),
        "malware_family":  first(vt.get("malware_family"), mb.get("malware_family")),
        "file_name":       first(vt.get("file_name"),    mb.get("file_name")),
        "file_type":       first(vt.get("file_type"),    mb.get("file_type")),
        "file_size":       first(vt.get("file_size"),    mb.get("file_size")),
        "first_submission":first(vt.get("first_submission"), mb.get("first_submission")),

        # ── Abuse / email ─────────────────────────────────────────
        "email_reports":     sfs.get("email_reports", 0),
        "sfs_confidence":    sfs.get("confidence"),
        "sfs_country":       sfs.get("country"),
        "sfs_assoc_emails":  sfs.get("reports", []),   # individual report entries with emails
        "username_hits":     wmn.get("username_hits") or [],
        "sfs_verdict":       sfs.get("verdict_hint", "unknown"),
        "pulse_count":     pd.get("pulse_count", 0),

        # ── Source availability ───────────────────────────────────
        "has_screenshot":    bool(us.get("screenshot_url")),
        "shodan_ok":         ok("shodan"),
        "urlscan_ok":        ok("urlscan"),
        "st_ok":             ok("securitytrails"),
        "mb_ok":             ok("malwarebazaar"),
        "connected_domains": cip.get("connected_domains") or [],
        "cip_vuln_ports":    cip.get("vuln_ports") or {},
        # ── Credential leaks (from URLScan + urlquery) ─────────────
        "credential_leaks":  (us.get("credential_leaks") or []),

        # ── New sources — threat intel ────────────────────────────
        "threat_type":       first(tf.get("threat_type"),  uh.get("threat_type"),
                                   fd.get("threat_type")),
        "threat_actor":      first(tf.get("threat_actor"), uh.get("threat_actor")),
        "related_iocs":      (tf.get("related_iocs") or uh.get("related_iocs") or [])[:8],
        # Botnet C2 context (Feodo Tracker)
        "is_botnet_c2":      ok("feodotracker") and fd.get("verdict_hint") == "malicious",
        "botnet_family":     fd.get("malware_family"),
        # RIPEstat technical
        "abuse_contact":     ripe.get("abuse_contact"),
        "bgp_prefix":        first(ripe.get("bgp_prefix"), sh.get("network"), vt.get("network")),
        "rir":               ripe.get("rir"),
        "asn_rank":          ripe.get("asn_rank"),
        "asn_rank_position": ripe.get("asn_rank_position"),
        # CIRCL hashlookup
        "known_file":        hl.get("known_file"),
        "known_file_name":   hl.get("known_file_name"),
        # Passive DNS
        "passive_dns":       dns.get("passive_dns") or [],
        # Override hostnames with passive DNS co-hosts for IPs
        "pdns_hostnames":    dns.get("hostnames") or [],
    }

    return templates.TemplateResponse("results.html", {
        "request":       request,
        "ioc":           ioc,
        "tags":          all_tags_merged,
        "metadata":      metadata,
        "sources":       sources,
        "unified":       unified,
        "timeline":      timeline,
        "history":       history,
        "geo":           geo,
        "is_cached":     is_cached,
        "cache_age_h":   cache_age_h,
        "source_links":  source_links,
        "merged_ports":    merged_ports,
        "merged_techs":    merged_techs,
        "merged_services": merged_services,
        "port_source":     port_source,
    })


@router.get("/proxy/screenshot")
async def proxy_screenshot(url: str):
    """
    Proxy URLScan screenshots through our server to avoid CORS/hotlink issues.
    Only allows urlscan.io screenshot URLs.
    """
    import re as _re
    from fastapi.responses import StreamingResponse, Response
    import httpx as _httpx

    # Security: only allow screenshot URLs from trusted sources
    _urlscan_re   = r'^https://urlscan\.io/screenshots/[a-fA-F0-9\-]+\.png$'
    _pulsedive_re = r'^https://pulsedive\.com/api/screenshots/\S+$'

    is_urlscan   = bool(_re.match(_urlscan_re,   url))
    is_pulsedive = bool(_re.match(_pulsedive_re, url))

    if not is_urlscan and not is_pulsedive:
        raise HTTPException(status_code=400, detail="Invalid screenshot URL")

    try:
        # Build appropriate headers per source
        if is_pulsedive:
            from app.config import get_settings as _gs
            _pd_key = _gs().pulsedive_key_1 or _gs().pulsedive_key_2 or ""
            _req_headers = {
                "User-Agent": "Mozilla/5.0 (compatible; EvilOriginDetection/1.0)",
                "Accept": "image/png,image/*",
                "Referer": "https://pulsedive.com/",
                **({"X-API-Key": _pd_key} if _pd_key else {}),
            }
        else:
            _req_headers = {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "image/webp,image/png,image/*,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Referer": "https://urlscan.io/",
                "Origin": "https://urlscan.io",
            }

        async with _httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            r = await client.get(url, headers=_req_headers)
            if r.status_code == 200:
                return Response(
                    content=r.content,
                    media_type="image/png",
                    headers={
                        "Cache-Control": "public, max-age=86400",
                        "X-Content-Type-Options": "nosniff",
                    }
                )
            raise HTTPException(status_code=r.status_code, detail="Screenshot unavailable")
    except _httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Screenshot request timed out")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Screenshot proxy error: {exc}")


@router.get("/results/{ioc_id}/graph", response_class=JSONResponse)
async def graph_data(
    ioc_id: int,
    db:     AsyncSession = Depends(get_db),
):
    """
    Returns Cytoscape.js-compatible graph data for the IOC and its artifacts.
    """
    try:
        data = await _graph_data_inner(ioc_id, db)
        app_logger.debug(
            f"[graph] ioc={ioc_id} nodes={len(data.get('nodes',[]))} "
            f"edges={len(data.get('edges',[]))}"
        )
        return data
    except HTTPException:
        raise
    except Exception as exc:
        import traceback as _tb
        app_logger.error(f"graph_data error ioc={ioc_id}: {_tb.format_exc()}")
        return JSONResponse({"nodes": [], "edges": [], "error": str(exc)})


async def _graph_data_inner(ioc_id: int, db):
    stmt   = select(IOC).where(IOC.id == ioc_id).options(selectinload(IOC.source_results))
    result = await db.execute(stmt)
    ioc    = result.scalar_one_or_none()

    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")

    nodes = []
    edges = []

    # Central node
    # Build extra info for hash nodes
    extra_data = {}
    if ioc.type.value == "hash":
        meta = json.loads(ioc.metadata_ or "{}")
        # Pull from metadata_ first (fastest, set at analysis time)
        for _f in ("malware_family", "file_name", "file_type", "file_size", "first_submission"):
            if meta.get(_f):
                extra_data[_f] = meta[_f]
        # Also scan source_results in case metadata is from old cached record
        for _sr in ioc.source_results:
            if _sr.status.value == "ok":
                _n = json.loads(_sr.normalized or "{}")
                for _f in ("file_name", "malware_family", "file_type"):
                    if _n.get(_f):
                        extra_data.setdefault(_f, _n[_f])

    nodes.append({
        "data": {
            "id":      f"ioc_{ioc.id}",
            "label":   ioc.value,
            "type":    ioc.type.value,
            "verdict": ioc.verdict.value if ioc.verdict else "unknown",
            "score":   ioc.score,
            "central": True,
            **extra_data,
        }
    })

    seen_nodes = {ioc.value}

    # Only IOC types are valid graph nodes
    IOC_TYPES = {"ip", "domain", "url", "email", "hash", "network", "username"}

    def add_node(node_id, label, ntype, verdict="unknown", score=None,
                 source=None, reason=None, **extra):
        """Add node only if it's an IOC type and not already seen."""
        if ntype not in IOC_TYPES:
            return False
        if label in seen_nodes:
            return False
        seen_nodes.add(label)
        node_data = {
            "id":      node_id,
            "label":   label,
            "type":    ntype,
            "verdict": verdict,
            "score":   score,
            "source":  source,
            "reason":  reason,
        }
        node_data.update({k: v for k, v in extra.items() if v is not None})
        nodes.append({"data": node_data})
        return True

    def add_edge(source_id, target_id, label, edge_type="default",
                 source_intel=None):
        eid = f"e_{source_id}_{target_id}"
        # avoid duplicate edges
        if any(e["data"]["id"] == eid for e in edges):
            return
        edges.append({"data": {
            "id":           eid,
            "source":       source_id,
            "target":       target_id,
            "label":        label,
            "type":         edge_type,
            "source_intel": source_intel,
        }})

    central_id = f"ioc_{ioc.id}"

    for sr in ioc.source_results:
        if sr.status.value != "ok":
            continue
        try:
            norm = json.loads(sr.normalized or "{}")
            raw  = json.loads(sr.raw_json   or "{}")
        except Exception:
            continue

        src = sr.source

        # ── Hostnames / PTR → domain nodes ────────────────────────
        for hostname in (norm.get("hostnames") or [])[:5]:
            if hostname:
                nid = f"host_{hostname}"
                if add_node(nid, hostname, "domain",
                            source=src, reason="PTR/hostname record"):
                    add_edge(central_id, nid, "resolves-to", "resolution",
                             source_intel=src)

        # ── VirusTotal relations ───────────────────────────────────
        if src == "virustotal":
            relations = raw.get("_relations", {})

            # Resolutions: IP↔Domain — add each as a SEPARATE typed node
            # VT quirk: item.id sometimes = IPv6+hostname or IPv4+hostname concatenated
            def _split_res_id(item_id):
                """Split a possibly-concatenated VT resolution id into (ip, host)."""
                # IPv6 prefix (hex groups with colons)
                m6 = re.match(r'^([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7})([a-zA-Z].*)?$',
                              item_id)
                if m6 and ':' in m6.group(1):
                    return m6.group(1), (m6.group(2) or "").strip()
                # IPv4 prefix
                m4 = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})([a-zA-Z].*)?$',
                              item_id)
                if m4:
                    return m4.group(1), (m4.group(2) or "").strip()
                # Pure domain
                if '.' in item_id and not item_id.replace('.','').isdigit():
                    return "", item_id
                return item_id, ""

            for item in (relations.get("resolutions") or [])[:8]:
                attr      = item.get("attributes", {}) or {}
                ip_addr   = (attr.get("ip_address") or "").strip()
                host_name = (attr.get("host_name")  or "").strip()
                item_id   = (item.get("id") or "").strip()

                # Always try to split item.id in case attributes are missing
                # or item.id itself is a concatenated ip+host string
                if item_id and (not ip_addr or not host_name):
                    _id_ip, _id_host = _split_res_id(item_id)
                    if not ip_addr:
                        ip_addr   = _id_ip
                    if not host_name:
                        host_name = _id_host

                for val, rtype in [(ip_addr, "ip"), (host_name, "domain")]:
                    val = val.strip()
                    if not val or val == ioc.value:
                        continue
                    nid = f"vt_res_{val[:40]}"
                    if add_node(nid, val, rtype,
                                source="virustotal",
                                reason="DNS resolution (VirusTotal)"):
                        add_edge(central_id, nid, "resolves-to", "resolution",
                                 source_intel="virustotal")
            # Communicating / dropped hashes
            for rel_key, elabel in [
                ("communicating_files", "communicates-with"),
                ("dropped_files",       "drops"),
            ]:
                for item in (relations.get(rel_key) or [])[:4]:
                    fhash = item.get("id", "")
                    if fhash:
                        nid = f"vt_file_{fhash[:12]}"
                        _item_attrs = item.get("attributes", {}) or {}
                        _mname = _item_attrs.get("meaningful_name") or None
                        _mf = _item_attrs.get("popular_threat_classification", {})
                        _mf = (_mf.get("suggested_threat_label") or "") if isinstance(_mf, dict) else ""
                        # Use full hash as label/value; meaningful_name as display metadata
                        if add_node(nid, fhash, "hash",
                                    verdict="malicious",
                                    source="virustotal",
                                    reason=f"File {elabel} this host (VirusTotal)",
                                    file_name=_mname,
                                    malware_family=_mf or None):
                            add_edge(central_id, nid, elabel, "threat",
                                     source_intel="virustotal")

            # Contacted IPs / domains
            for rel_key, rtype, elabel in [
                ("contacted_ips",     "ip",     "contacted"),
                ("contacted_domains", "domain", "contacted"),
            ]:
                for item in (relations.get(rel_key) or [])[:5]:
                    val = item.get("id", "")
                    if val:
                        nid = f"vt_{rel_key}_{val}"
                        if add_node(nid, val, rtype,
                                    source="virustotal",
                                    reason=f"Contacted by this malware (VirusTotal)"):
                            add_edge(central_id, nid, elabel, "resolution",
                                     source_intel="virustotal")

        # ── Pulsedive linked indicators ────────────────────────────
        if src == "pulsedive":
            for linked_ioc in (raw.get("_linked_iocs") or [])[:5]:
                val  = linked_ioc.get("value", "")
                ltyp = linked_ioc.get("type", "")
                if val and ltyp in IOC_TYPES:
                    nid = f"pd_linked_{val}"
                    if add_node(nid, val, ltyp,
                                source="pulsedive",
                                reason="Linked indicator (Pulsedive)"):
                        add_edge(central_id, nid, "linked", "resolution",
                                 source_intel="pulsedive")

        # ── SecurityTrails — DNS A records ─────────────────────────
        if src == "securitytrails":
            dns = norm.get("dns_records") or {}
            for rec in (dns.get("a", {}).get("values", []) or [])[:4]:
                ip = rec.get("ip", "")
                if ip:
                    nid = f"st_ip_{ip}"
                    if add_node(nid, ip, "ip",
                                source="securitytrails",
                                reason="DNS A record (SecurityTrails)"):
                        add_edge(central_id, nid, "a-record", "resolution",
                                 source_intel="securitytrails")

        # ── Shodan — hostname resolutions ──────────────────────────
        if src == "shodan":
            for hostname in (norm.get("hostnames") or [])[:4]:
                if hostname:
                    nid = f"sh_host_{hostname}"
                    if add_node(nid, hostname, "domain",
                                source="shodan",
                                reason="Hostname (Shodan)"):
                        add_edge(central_id, nid, "hostname", "resolution",
                                 source_intel="shodan")

        # ── WhatsMyName — usernames found ──────────────────────────
        if src == "whatsmyname":
            for hit in (norm.get("username_hits") or [])[:5]:
                site = hit.get("site", "")
                url  = hit.get("url", "")
                if url:
                    nid = f"wmn_{site}"
                    if add_node(nid, url, "url",
                                source="whatsmyname",
                                reason=f"Username found on {site} (WhatsMyName)"):
                        add_edge(central_id, nid, "account-on", "resolution",
                                 source_intel="whatsmyname")

        # ── CriminalIP — connected domains + CVEs ─────────────────
        if src == "criminalip":
            for domain in (raw.get("_connected_domains") or [])[:6]:
                if domain:
                    nid = f"cip_dom_{domain}"
                    if add_node(nid, domain, "domain",
                                verdict="suspicious",
                                source="criminalip",
                                reason="Domain connected to this IP (Criminal IP)"):
                        add_edge(central_id, nid, "connected-domain",
                                 "resolution", source_intel="criminalip")
            # CVE tags → label them as threat nodes
            for tag in (norm.get("tags") or []):
                if tag.startswith("CVE-"):
                    nid = f"cip_cve_{tag}"
                    if add_node(nid, tag, "hash",  # closest type for CVE IDs
                                verdict="malicious",
                                source="criminalip",
                                reason=f"Vulnerability {tag} detected (Criminal IP)"):
                        add_edge(central_id, nid, "vulnerable-to",
                                 "threat", source_intel="criminalip")

        # ── StopForumSpam — emails associated with this IP ───────
        if src == "stopforumspam":
            for entry in (raw.get("_associated_emails") or [])[:8]:
                email = entry.get("email", "")
                if email and "@" in email:
                    nid = f"sfs_email_{email}"
                    if add_node(nid, email, "email",
                                verdict="suspicious",
                                source="stopforumspam",
                                reason=f"Email used in spam submissions from this IP (StopForumSpam)"):
                        add_edge(central_id, nid, "spam-submission", "threat",
                                 source_intel="stopforumspam")

        # ── URLScan — IPs/domains contacted during scan ────────────
        if src == "urlscan":
            lists = raw.get("_lists", {}) or {}
            for ip in (lists.get("ips") or [])[:5]:
                if ip:
                    nid = f"us_ip_{ip}"
                    if add_node(nid, ip, "ip",
                                source="urlscan",
                                reason="IP contacted during web scan (URLScan)"):
                        add_edge(central_id, nid, "contacted", "resolution",
                                 source_intel="urlscan")
            for domain in (lists.get("domains") or [])[:5]:
                if domain:
                    nid = f"us_dom_{domain}"
                    if add_node(nid, domain, "domain",
                                source="urlscan",
                                reason="Domain contacted during web scan (URLScan)"):
                        add_edge(central_id, nid, "contacted", "resolution",
                                 source_intel="urlscan")
            for fhash in (lists.get("hashes") or [])[:3]:
                if fhash:
                    nid = f"us_hash_{fhash[:12]}"
                    if add_node(nid, fhash[:20] + "…", "hash",
                                source="urlscan",
                                reason="File hash loaded during scan (URLScan)",
                                file_name=None):
                        add_edge(central_id, nid, "loads", "threat",
                                 source_intel="urlscan")

        # ── ThreatFox / URLhaus — related IOCs ────────────────────
        if src in ("threatfox", "urlhaus"):
                for rel in (raw.get("related_iocs") or [])[:6]:
                    if not isinstance(rel, dict):
                        continue
                    val   = (rel.get("value") or "").strip()
                    rtype = rel.get("type", "ip")
                    if not val or val == ioc.value:
                        continue
                    if rtype not in ("ip", "domain", "hash", "url"):
                        continue
                    nid = f"rel_{src}_{val[:32]}"
                    mw  = rel.get("malware") or rel.get("malware_family") or ""
                    reason = f"Related IOC ({src})" + (f" · {mw}" if mw else "")
                    if add_node(nid, val, rtype,
                                verdict="malicious",
                                source=src,
                                reason=reason):
                        add_edge(central_id, nid,
                                 rel.get("relationship", "related"),
                                 "threat", source_intel=src)
    return {"nodes": nodes, "edges": edges}


@router.post("/results/{ioc_id}/rescan")
async def rescan(
    ioc_id:  int,
    request: Request,
    db:      AsyncSession = Depends(get_db),
):
    """Force a fresh analysis, ignoring cache."""
    from app.routers.analyze import analyze_single
    stmt   = select(IOC).where(IOC.id == ioc_id)
    result = await db.execute(stmt)
    ioc    = result.scalar_one_or_none()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")

    parsed = ParsedIOC(value=ioc.value, type=ioc.type, raw_input=ioc.value)
    ioc, _ = await analyze_single(parsed, db, force_rescan=True)

    log_query(request, ioc.value, ioc.type.value,
              ioc.verdict.value if ioc.verdict else None,
              forced_rescan=True)

    return RedirectResponse(url=f"/results/{ioc.id}", status_code=303)


# ── Helpers ───────────────────────────────────────────────────────────────────

# Phrases that indicate a scan event rather than IOC activity
_SCAN_NOISE = (
    # ── Scan-metadata (tool ran a scan, not an indicator event) ─────
    "shodan indexed",
    "shodan — ",
    "pulsedive — ",
    "pulsedive host scan",
    "first seen by pulsedive",
    "criminal ip — ",
    "criminalip — ",
    "virustotal — clean",
    "urlscan — http",
    "urlscan — scanned",
    "urlscan — scan",
    "analysis complete",
    "first scanned",
    "resolves to:",
    "securitytrails — ",
    "dns records",
    "whatsMyName",
    "found on ",
    "page captured",
    "scan complete",
    " ports found",
    " open port",
    "risk score",
    "passive dns —",         # pdns is informational, not events
    "ripestat — ",           # routing info not an event
    # Keep: threatfox, urlhaus, feodo, otx, abuseipdb, mb, sfs
)


def _build_timeline(ioc, sources: dict, history) -> list[dict]:
    """
    Build activity timeline — ONLY real IOC activity, not scan metadata.
    Rules:
    - Must have a real date (actual activity timestamp)
    - Skip generic scan/index events
    - Keep: abuse reports, malware detections, spam submissions, CVEs,
            domain registration, redirects, threat feed appearances
    """
    events = []

    src_labels = {
        "virustotal": "VT", "abuseipdb": "ABUSE", "shodan": "SHODAN",
        "pulsedive": "PD", "criminalip": "CIP", "malwarebazaar": "MB",
        "urlscan": "USCAN", "securitytrails": "ST",
        "stopforumspam": "SFS", "whatsmyname": "WMN",
    }

    for src_name, data in sources.items():
        if data.get("status") != "ok":
            continue

        for rep in (data.get("reports") or []):
            summary = rep.get("summary", "")
            if not summary:
                continue

            # Skip scan-noise events
            low = summary.lower()
            if any(noise in low for noise in _SCAN_NOISE):
                continue

            # Require a real date for activity events
            # (undated entries are typically scan summaries, not real activity)
            date = rep.get("date")
            category = rep.get("category", "")
            if not date:
                # Only allow undated entries for hard threat detections
                if category not in ("threat", "abuse"):
                    continue
                # Skip undated scan summaries even if category is threat
                low2 = summary.lower()
                if any(s in low2 for s in ("risk score", "scanned", "indexed", "found on")):
                    continue

            events.append({
                "date":     date,
                "source":   src_name,
                "label":    src_labels.get(src_name, src_name[:3].upper()),
                "verdict":  data.get("verdict_hint", "unknown"),
                "summary":  summary,
                "link":     _source_link(src_name, ioc.value, ioc.type.value),
                "category": rep.get("category", ""),
            })

    # Sort chronologically (oldest first, undated last)
    def sort_key(e):
        d = e.get("date")
        return str(d)[:19] if d else "9999-99-99"

    events.sort(key=sort_key)

    # Deduplicate near-identical summaries
    seen = set()
    unique = []
    for e in events:
        key = (e["source"], e.get("summary", "")[:50])
        if key not in seen:
            seen.add(key)
            unique.append(e)

    return unique[:20]


def _epoch_to_iso(val) -> str | None:
    """Convert Unix timestamp int to ISO date string."""
    if val is None:
        return None
    try:
        from datetime import datetime
        if isinstance(val, (int, float)) and val > 1000000000:
            return datetime.utcfromtimestamp(val).strftime("%Y-%m-%dT%H:%M:%S")
        return str(val)[:19]
    except Exception:
        return str(val)[:19] if val else None


def _source_summary(source: str, data: dict) -> str:
    match source:
        case "virustotal":
            mal   = data.get("malicious_count", 0)
            total = data.get("total_engines", 0)
            if not total:
                return "Scanned"
            return f"{mal}/{total} engines flagged" if mal else f"Clean — {total} engines"
        case "abuseipdb":
            score = data.get("abuse_score", 0) or 0
            return f"{score}% abuse confidence"
        case "shodan":
            ports = data.get("ports") or []
            return f"{len(ports)} open port(s)" if ports else "Scanned"
        case "pulsedive":
            # Clean summary: just feed count or "Scanned"
            count = data.get("pulse_count") or 0
            return f"{count} feed(s)" if count else "Scanned"
        case "criminalip":
            score = data.get("abuse_score") or 0
            if score:
                return f"Risk score {score}/100"
            tags = data.get("tags") or []
            return ", ".join(tags[:2]) if tags else "Scanned"
        case "malwarebazaar":
            family = data.get("malware_family")
            return f"Family: {family}" if family else "Sample found"
        case "urlscan":
            return "Screenshot available" if data.get("screenshot_url") else "Scanned"
        case "securitytrails":
            dns = data.get("dns_records") or {}
            count = sum(len(v.get("values", [])) for v in dns.values() if isinstance(v, dict))
            return f"{count} DNS record(s)" if count else "Scanned"
        case "stopforumspam":
            freq = data.get("email_reports") or 0
            return f"{freq} spam report(s)" if freq else "Not listed"
        case _:
            hint = data.get("verdict_hint", "")
            return hint.capitalize() if hint else "Scanned"


def _source_link(source: str, value: str, ioc_type: str = "") -> str | None:
    from urllib.parse import quote
    match source:
        case "virustotal":
            type_map = {"ip": "ip-address", "domain": "domain",
                        "hash": "file", "url": "url"}
            vt_type = type_map.get(ioc_type, "search")
            return f"https://www.virustotal.com/gui/{vt_type}/{quote(value, safe='')}"
        case "abuseipdb":
            return f"https://www.abuseipdb.com/check/{value}"
        case "shodan":
            return f"https://www.shodan.io/host/{value}"
        case "pulsedive":
            return f"https://pulsedive.com/indicator/{quote(value, safe='')}"
        case "malwarebazaar":
            return f"https://bazaar.abuse.ch/sample/{value}"
        case "urlscan":
            # Use the direct scan result URL if stored, else fall back to search
            if ioc_type == "url":
                return f"https://urlscan.io/search/#page.url:{quote(value, safe='')}"
            elif ioc_type == "ip":
                return f"https://urlscan.io/search/#page.ip:{quote(value, safe='')}"
            # domain: use page.domain: query (not domain: which is too broad)
            return f"https://urlscan.io/search/#page.domain:{quote(value, safe='')}"
        case "securitytrails":
            if ioc_type == "ip":
                return f"https://securitytrails.com/list/ip/{value}"
            return f"https://securitytrails.com/domain/{value}"
        case "criminalip":
            # /asset/report/{ip} for IPs, /asset/search for domains
            if ioc_type == "ip":
                return f"https://www.criminalip.io/asset/report/{value}"
            q = quote(f"domain:{value}")
            return f"https://search.criminalip.io/asset/search?query={q}"
        case "stopforumspam":
            return f"https://www.stopforumspam.com/search?q={quote(value, safe='')}"
        case "whatsmyname":
            return f"https://whatsmyname.app/"
        case "threatfox":
            return f"https://threatfox.abuse.ch/browse/?q={quote(value, safe='')}"
        case "urlhaus":
            return f"https://urlhaus.abuse.ch/browse/?q={quote(value, safe='')}"
        case "feodotracker":
            return f"https://feodotracker.abuse.ch/browse/"
        case "ripestat":
            if ioc_type == "ip":
                return f"https://stat.ripe.net/widget/prefix-overview#w.resource={value}"
            return f"https://stat.ripe.net/"
        case "hashlookup":
            return f"https://hashlookup.circl.lu/lookup/sha256/{value}"
        case "passivedns":
            return f"https://api.mnemonic.no/pdns/v3/{quote(value, safe='')}"
        case "urlquery":
            return f"https://urlquery.net/search?q={quote(value, safe='')}"
        case _:
            return None


def _extract_geo(sources: dict) -> dict | None:
    geo = {}
    priority = ["criminalip", "shodan", "abuseipdb", "virustotal",
                "pulsedive", "securitytrails"]

    # Collect all source data in priority order
    ordered = []
    seen = set()
    for src in priority:
        if src in sources:
            ordered.append(sources[src])
            seen.add(src)
    for src, data in sources.items():
        if src not in seen:
            ordered.append(data)

    for data in ordered:
        if not geo.get("country") and data.get("country"):
            geo["country"] = data["country"]
        if not geo.get("city") and data.get("city"):
            geo["city"] = data["city"]
        if not geo.get("org") and data.get("org"):
            geo["org"] = data["org"]
        if not geo.get("asn") and data.get("asn"):
            geo["asn"] = data["asn"]
        if not geo.get("isp") and data.get("isp"):
            geo["isp"] = data["isp"]
        if not geo.get("network") and data.get("network"):
            geo["network"] = data["network"]
        # Lat/lon from CriminalIP or other sources that provide it
        if not geo.get("lat") and data.get("latitude"):
            geo["lat"] = data["latitude"]
        if not geo.get("lon") and data.get("longitude"):
            geo["lon"] = data["longitude"]

    return geo if geo else None


@router.get("/results/{ioc_id}/export")
async def export_json(
    ioc_id: int,
    db:     AsyncSession = Depends(get_db),
):
    """Export IOC analysis as JSON."""
    from fastapi.responses import JSONResponse as JR
    stmt   = select(IOC).where(IOC.id == ioc_id).options(selectinload(IOC.source_results))
    result = await db.execute(stmt)
    ioc    = result.scalar_one_or_none()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")

    sources_out = {}
    for sr in ioc.source_results:
        if sr.status.value == "ok":
            try:
                norm = json.loads(sr.normalized or "{}")
                sources_out[sr.source] = {
                    "verdict": norm.get("verdict_hint","unknown"),
                    "tags":    norm.get("tags", []),
                    "ports":   norm.get("ports", []),
                    "country": norm.get("country"),
                    "org":     norm.get("org"),
                }
            except Exception:
                pass

    export = {
        "ioc":     ioc.value,
        "type":    ioc.type.value if ioc.type else "unknown",
        "score":   ioc.score,
        "verdict": ioc.verdict.value if ioc.verdict else "unknown",
        "tags":    json.loads(ioc.tags or "[]"),
        "sources": sources_out,
        "scanned_at": ioc.last_scan.isoformat() if ioc.last_scan else None,
    }
    return JR(content=export,
              headers={"Content-Disposition": f'attachment; filename="eod_{ioc.value[:20]}.json"'})


@router.get("/graph", response_class=HTMLResponse)
async def graph_page(request: Request):
    """Standalone correlation graph explorer."""
    return templates.TemplateResponse("graph.html", {"request": request})
