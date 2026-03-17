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

    return templates.TemplateResponse("results.html", {
        "request":      request,
        "ioc":          ioc,
        "tags":         tags,
        "metadata":     metadata,
        "sources":      sources,
        "timeline":     timeline,
        "history":      history,
        "geo":          geo,
        "is_cached":    is_cached,
        "cache_age_h":  cache_age_h,
        "source_links": source_links,
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
    events = []

    SOURCE_LABELS = {
        "virustotal":    ("VT",  "vt"),
        "abuseipdb":     ("AB",  "abuse"),
        "greynoise":     ("GN",  "greynoise"),
        "shodan":        ("SH",  "shodan"),
        "pulsedive":     ("PD",  "pulsedive"),
        "malwarebazaar": ("MB",  "bazaar"),
        "urlscan":       ("US",  "urlscan"),
        "securitytrails":("ST",  "securitytrails"),
        "criminalip":    ("CIP", "criminalip"),
        "stopforumspam": ("SFS", "stopforumspam"),
    }

    for src_name, data in sources.items():
        if data.get("status") != "ok":
            continue
        label, badge = SOURCE_LABELS.get(src_name, (src_name[:3].upper(), src_name))
        ts = data.get("fetched_at") or data.get("last_seen")

        verdict = data.get("verdict_hint", "unknown")
        events.append({
            "date":    ts,
            "source":  src_name,
            "label":   label,
            "badge":   badge,
            "verdict": verdict,
            "summary": _source_summary(src_name, data),
            "link":    _source_link(src_name, ioc.value, ioc.type.value),
        })

    # Add current analysis event
    events.append({
        "date":    ioc.last_scan.isoformat() if ioc.last_scan else None,
        "source":  "eod",
        "label":   "EOD",
        "badge":   "eod",
        "verdict": ioc.verdict.value if ioc.verdict else "unknown",
        "summary": f"Analysis complete — Score {ioc.score}/100",
        "link":    None,
        "current": True,
    })

    # Sort by date ascending, nulls last
    events.sort(key=lambda e: e.get("date") or "9999")
    return events


def _source_summary(source: str, data: dict) -> str:
    match source:
        case "virustotal":
            mal   = data.get("malicious_count", 0)
            total = data.get("total_engines", 0)
            return f"{mal}/{total} engines detected"
        case "abuseipdb":
            score = data.get("abuse_score", 0)
            return f"{score}% abuse confidence"
        case "greynoise":
            cl = data.get("classification", "unknown")
            return f"Classification: {cl}"
        case "shodan":
            ports = data.get("ports") or []
            return f"{len(ports)} open ports" if ports else "No open ports"
        case "malwarebazaar":
            family = data.get("malware_family")
            return f"Malware family: {family}" if family else "Found in MalwareBazaar"
        case "urlscan":
            return f"Screenshot available" if data.get("screenshot_url") else "Scanned"
        case _:
            hint = data.get("verdict_hint", "")
            return hint.capitalize() if hint else "Data available"


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
        case "greynoise":
            return f"https://viz.greynoise.io/ip/{value}"
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
                "greynoise", "pulsedive", "securitytrails"]

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
