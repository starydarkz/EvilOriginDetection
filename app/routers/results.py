"""
results.py — Results / analysis page router.
GET /results/{ioc_id} → render full analysis view.
GET /results/{ioc_id}/graph → graph data as JSON for Cytoscape.js.
POST /results/{ioc_id}/rescan → force fresh analysis.
"""
import json
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
        # Services (port → service name)
        for port, svc in (sdata.get("services") or {}).items():
            try:
                port_int = int(port)
            except (ValueError, TypeError):
                continue
            if port_int not in merged_services and svc:
                merged_services[port_int] = {
                    "service": svc,
                    "source":  src_priority,
                }
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
        "is_tor":     any([cip.get("is_tor"), ab.get("is_tor")]),
        "is_vpn":     bool(cip.get("is_vpn")),
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
        "http_status":    first(us.get("http_status"),   pd.get("http_status")),
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
        "email_reports":   sfs.get("email_reports", 0),
        "sfs_confidence":  sfs.get("confidence"),
        "sfs_country":     sfs.get("country"),
        "username_hits":   wmn.get("username_hits") or [],
        "sfs_verdict":     sfs.get("verdict_hint", "unknown"),
        "pulse_count":     pd.get("pulse_count", 0),

        # ── Source availability ───────────────────────────────────
        "has_screenshot": bool(us.get("screenshot_url")),
        "shodan_ok":      ok("shodan"),
        "urlscan_ok":     ok("urlscan"),
        "st_ok":          ok("securitytrails"),
        "mb_ok":          ok("malwarebazaar"),
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


@router.get("/results/{ioc_id}/graph", response_class=JSONResponse)
async def graph_data(
    ioc_id: int,
    db:     AsyncSession = Depends(get_db),
):
    """
    Returns Cytoscape.js-compatible graph data for the IOC and its artifacts.
    Nodes: the IOC + related artifacts (hostnames, domains, ASN, malware family)
    Edges: relationships between them.
    """
    stmt   = select(IOC).where(IOC.id == ioc_id).options(selectinload(IOC.source_results))
    result = await db.execute(stmt)
    ioc    = result.scalar_one_or_none()

    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")

    nodes = []
    edges = []

    # Central node
    nodes.append({
        "data": {
            "id":      f"ioc_{ioc.id}",
            "label":   ioc.value,
            "type":    ioc.type.value,
            "verdict": ioc.verdict.value if ioc.verdict else "unknown",
            "score":   ioc.score,
            "central": True,
        }
    })

    seen_nodes = {ioc.value}

    # Only IOC types are valid graph nodes
    IOC_TYPES = {"ip", "domain", "url", "email", "hash", "network", "username"}

    def add_node(node_id, label, ntype, verdict="unknown", score=None,
                 source=None, reason=None):
        """Add node only if it's an IOC type and not already seen."""
        if ntype not in IOC_TYPES:
            return False
        if label in seen_nodes:
            return False
        seen_nodes.add(label)
        nodes.append({"data": {
            "id":      node_id,
            "label":   label,
            "type":    ntype,
            "verdict": verdict,
            "score":   score,
            "source":  source,   # which intelligence source found this
            "reason":  reason,   # why this is correlated
        }})
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

            # Resolutions: IP↔Domain
            for item in (relations.get("resolutions") or [])[:6]:
                attr    = item.get("attributes", {})
                related = (attr.get("host_name") or attr.get("ip_address")
                           or item.get("id", ""))
                if related:
                    rtype = ("domain"
                             if "." in related and not related.replace(".", "").isdigit()
                             else "ip")
                    nid = f"vt_res_{related}"
                    if add_node(nid, related, rtype,
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
                    fname = (item.get("attributes", {})
                                 .get("meaningful_name") or fhash[:20] + "…")
                    if fhash:
                        nid = f"vt_file_{fhash[:12]}"
                        if add_node(nid, fname, "hash",
                                    verdict="malicious",
                                    source="virustotal",
                                    reason=f"File {elabel} this host (VirusTotal)"):
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
                                reason="File hash loaded during scan (URLScan)"):
                        add_edge(central_id, nid, "loads", "threat",
                                 source_intel="urlscan")

    return {"nodes": nodes, "edges": edges}


@router.post("/results/{ioc_id}/rescan")
async def rescan(
    ioc_id:  int,
    request: Request,
    db:      AsyncSession = Depends(get_db),
):
    """Force a fresh analysis, ignoring cache."""
    from app.routers.analyze import analyze_single
    from app.logger import log_query

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

def _build_timeline(ioc, sources: dict, history) -> list[dict]:
    """
    Build activity timeline from result.reports[] populated by each connector.
    Each connector is responsible for extracting its own dated events.
    We collect all, sort chronologically, and cap at 15.
    """
    events = []

    for src_name, data in sources.items():
        if data.get("status") != "ok":
            continue

        # Use pre-built reports from connector normalize()
        for rep in (data.get("reports") or []):
            if not rep.get("summary"):
                continue
            events.append({
                "date":    rep.get("date"),
                "source":  src_name,
                "label":   src_name.upper()[:3],
                "verdict": data.get("verdict_hint", "unknown"),
                "summary": rep["summary"],
                "link":    _source_link(src_name, ioc.value, ioc.type.value),
                "category": rep.get("category", ""),
            })

        # Fallback: if connector has no reports[], create one generic entry
        if not data.get("reports"):
            summary = _source_summary(src_name, data)
            if summary and summary not in ("Scanned", "Not listed"):
                ts = data.get("last_seen")
                events.append({
                    "date":    ts[:19] if ts else None,
                    "source":  src_name,
                    "label":   src_name.upper()[:3],
                    "verdict": data.get("verdict_hint", "unknown"),
                    "summary": summary,
                    "link":    _source_link(src_name, ioc.value, ioc.type.value),
                    "category": "",
                })

    # Current analysis event (always last)
    events.append({
        "date":    ioc.last_scan.isoformat() if ioc.last_scan else None,
        "source":  "eod",
        "label":   "EOD",
        "verdict": ioc.verdict.value if ioc.verdict else "unknown",
        "summary": f"Analysis complete — Risk score {ioc.score}/100",
        "link":    None,
        "current": True,
        "category": "",
    })

    # Sort: dated events chronologically, undated before "current"
    def sort_key(e):
        d = e.get("date")
        if e.get("current"):
            return "9999-99-99"
        return str(d)[:19] if d else "8888-01-01"

    events.sort(key=sort_key)

    # Deduplicate near-identical summaries from same source
    seen = set()
    unique = []
    for e in events:
        key = (e.get("source"), e.get("summary", "")[:40])
        if key not in seen:
            seen.add(key)
            unique.append(e)

    return unique[:15]


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
            if ioc_type == "url":
                return f"https://urlscan.io/search/#page.url:{quote(value, safe='')}"
            return f"https://urlscan.io/search/#domain:{quote(value, safe='')}"
        case "securitytrails":
            if ioc_type == "ip":
                return f"https://securitytrails.com/list/ip/{value}"
            return f"https://securitytrails.com/domain/{value}"
        case "criminalip":
            q = quote(f"ip:{value}" if ioc_type == "ip" else
                      f"domain:{value}" if ioc_type == "domain" else value)
            return f"https://search.criminalip.io/asset/search?query={q}"
        case "stopforumspam":
            return f"https://www.stopforumspam.com/search?q={quote(value, safe='')}"
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


@router.get("/graph", response_class=HTMLResponse)
async def graph_page(request: Request):
    """Standalone correlation graph explorer."""
    return templates.TemplateResponse("graph.html", {"request": request})
