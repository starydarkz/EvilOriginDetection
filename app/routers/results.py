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

    return templates.TemplateResponse("results.html", {
        "request":     request,
        "ioc":         ioc,
        "tags":        tags,
        "metadata":    metadata,
        "sources":     sources,
        "timeline":    timeline,
        "history":     history,
        "geo":         geo,
        "is_cached":   is_cached,
        "cache_age_h": cache_age_h,
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

    for sr in ioc.source_results:
        if sr.status.value != "ok":
            continue
        try:
            norm = json.loads(sr.normalized or "{}")
        except Exception:
            continue

        # Hostnames → domain nodes
        for hostname in (norm.get("hostnames") or [])[:5]:
            if hostname and hostname not in seen_nodes:
                node_id = f"host_{hostname}"
                nodes.append({"data": {
                    "id": node_id, "label": hostname,
                    "type": "domain", "verdict": "unknown", "score": None,
                }})
                edges.append({"data": {
                    "source": f"ioc_{ioc.id}", "target": node_id,
                    "label": "resolves-to",
                }})
                seen_nodes.add(hostname)

        # ASN node
        asn = norm.get("asn") or norm.get("org")
        if asn and asn not in seen_nodes:
            node_id = f"asn_{asn}"
            nodes.append({"data": {
                "id": node_id, "label": asn,
                "type": "asn", "verdict": "unknown", "score": None,
            }})
            edges.append({"data": {
                "source": f"ioc_{ioc.id}", "target": node_id,
                "label": "belongs-to",
            }})
            seen_nodes.add(asn)

        # Malware family node
        family = norm.get("malware_family")
        if family and family not in seen_nodes:
            node_id = f"fam_{family}"
            nodes.append({"data": {
                "id": node_id, "label": family,
                "type": "malware", "verdict": "malicious", "score": None,
            }})
            edges.append({"data": {
                "source": f"ioc_{ioc.id}", "target": node_id,
                "label": "associated-with",
            }})
            seen_nodes.add(family)

        # VirusTotal relations → enrich graph
        if sr.source == "virustotal":
            try:
                raw = json.loads(sr.raw_json or "{}")
                relations = raw.get("_relations", {})
            except Exception:
                relations = {}

            # Resolutions: IP→Domain or Domain→IP
            for item in (relations.get("resolutions") or [])[:5]:
                attr = item.get("attributes", {})
                related = (attr.get("host_name") or attr.get("ip_address") or
                           item.get("id", ""))
                if related and related not in seen_nodes:
                    rtype = "domain" if "." in related and not related.replace(".","").isdigit() else "ip"
                    node_id = f"vt_res_{related}"
                    nodes.append({"data": {
                        "id": node_id, "label": related,
                        "type": rtype, "verdict": "unknown", "score": None,
                    }})
                    edges.append({"data": {
                        "source": f"ioc_{ioc.id}", "target": node_id,
                        "label": "resolves-to",
                    }})
                    seen_nodes.add(related)

            # Communicating files (hashes)
            for item in (relations.get("communicating_files") or [])[:3]:
                fhash = item.get("id", "")
                fname = item.get("attributes", {}).get("meaningful_name", fhash[:12] + "…")
                if fhash and fhash not in seen_nodes:
                    node_id = f"vt_file_{fhash[:12]}"
                    nodes.append({"data": {
                        "id": node_id, "label": fname,
                        "type": "hash", "verdict": "malicious", "score": None,
                    }})
                    edges.append({"data": {
                        "source": f"ioc_{ioc.id}", "target": node_id,
                        "label": "communicates-with",
                    }})
                    seen_nodes.add(fhash)

            # Contacted IPs/Domains from file analysis
            for rel_key, rtype, edge_label in [
                ("contacted_ips",     "ip",     "contacted"),
                ("contacted_domains", "domain", "contacted"),
            ]:
                for item in (relations.get(rel_key) or [])[:4]:
                    val = item.get("id", "")
                    if val and val not in seen_nodes:
                        node_id = f"vt_{rel_key}_{val}"
                        nodes.append({"data": {
                            "id": node_id, "label": val,
                            "type": rtype, "verdict": "unknown", "score": None,
                        }})
                        edges.append({"data": {
                            "source": f"ioc_{ioc.id}", "target": node_id,
                            "label": edge_label,
                        }})
                        seen_nodes.add(val)

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
