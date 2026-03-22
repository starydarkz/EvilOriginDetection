"""
analyze.py — Main analysis router.
POST /analyze  → receives IOC input, runs all connectors, saves to DB, returns results.
GET  /analyze/status/{task_id} → check async task status (future use).
"""
import asyncio
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models import IOC, SourceResult, ScanHistory, ScanTrigger, Verdict, SourceStatus
from app.parser import parse_input, ParsedIOC
from app.scoring import compute_score
from app.correlator import run_correlation
from app.connectors.base import NormalizedResult
from app.logger import log_query, get_client_ip, app_logger, exc_logger
import traceback
from config import get_settings, pick_key

# Connector imports
from app.connectors.virustotal   import VirusTotalConnector
from app.connectors.abuseipdb    import AbuseIPDBConnector
from app.connectors.shodan       import ShodanConnector
from app.connectors.pulsedive    import PulsediveConnector
from app.connectors.criminalip   import CriminalIPConnector
from app.connectors.malwarebazaar import MalwareBazaarConnector
from app.connectors.urlscan      import URLScanConnector
from app.connectors.securitytrails import SecurityTrailsConnector
from app.connectors.stopforumspam  import StopForumSpamConnector
from app.connectors.whatsmyname    import WhatsMyNameConnector
from app.connectors.threatfox      import ThreatFoxConnector
from app.connectors.urlhaus        import URLhausConnector
from app.connectors.feodotracker   import FeodoTrackerConnector
from app.connectors.otx            import OTXConnector
from app.connectors.ripestat       import RIPEstatConnector
from app.connectors.hashlookup     import HashlookupConnector, PassiveDNSConnector

router    = APIRouter()
templates = Jinja2Templates(directory="templates")
settings  = get_settings()


# ── Connector factory ─────────────────────────────────────────────────────────

def build_connectors() -> list:
    """Instantiate all connectors with rotated keys."""
    s = settings
    return [
        VirusTotalConnector(   pick_key(s.vt_key_1,              s.vt_key_2)),
        AbuseIPDBConnector(    pick_key(s.abuseipdb_key_1,       s.abuseipdb_key_2)),
        ShodanConnector(       pick_key(s.shodan_key_1,          s.shodan_key_2)),
        PulsediveConnector(    pick_key(s.pulsedive_key_1,       s.pulsedive_key_2)),
        CriminalIPConnector(   pick_key(s.criminalip_key_1,      s.criminalip_key_2)),
        MalwareBazaarConnector(pick_key(s.malwarebazaar_key_1,   s.malwarebazaar_key_2)),
        URLScanConnector(      pick_key(s.urlscan_key_1,         s.urlscan_key_2)),
        SecurityTrailsConnector(pick_key(s.securitytrails_key_1, s.securitytrails_key_2)),
        StopForumSpamConnector(pick_key(s.stopforumspam_key_1,   s.stopforumspam_key_2)),
        WhatsMyNameConnector(  pick_key(s.whatsmyname_key_1,     s.whatsmyname_key_2)),
        # ── New no-key sources ──────────────────────────────────────────
        ThreatFoxConnector(    api_key=None),
        URLhausConnector(      api_key=None),
        FeodoTrackerConnector( api_key=None),
        OTXConnector(          pick_key(s.otx_key_1, s.otx_key_2)),
        RIPEstatConnector(     api_key=None),
        HashlookupConnector(   api_key=None),
        PassiveDNSConnector(   api_key=None),
    ]


# ── Cache check ───────────────────────────────────────────────────────────────

async def get_cached_ioc(value: str, db: AsyncSession) -> Optional[IOC]:
    """Return IOC from DB if cache is still valid (cache_until > now)."""
    stmt  = select(IOC).where(IOC.value == value)
    result = await db.execute(stmt)
    ioc    = result.scalar_one_or_none()
    if ioc and ioc.cache_until and ioc.cache_until > datetime.now(timezone.utc).replace(tzinfo=None):
        return ioc
    return None


# ── Single IOC analysis ───────────────────────────────────────────────────────

async def analyze_single(
    parsed:      ParsedIOC,
    db:          AsyncSession,
    force_rescan: bool = False,
) -> tuple[IOC, list[NormalizedResult]]:
    """
    Run all connectors for one IOC.
    Returns (IOC db record, list of NormalizedResult).
    Handles cache: skips connectors if fresh cache exists and force_rescan=False.
    """
    # Check cache
    if not force_rescan:
        cached = await get_cached_ioc(parsed.value, db)
        if cached:
            # Load existing source results from DB
            stmt = select(SourceResult).where(SourceResult.ioc_id == cached.id)
            rows = await db.execute(stmt)
            # Return cached IOC — source results loaded from DB
            return cached, []

    connectors   = build_connectors()
    source_tasks = [c.query(parsed) for c in connectors]

    # Run all connectors in parallel
    norm_results: list[NormalizedResult] = await asyncio.gather(*source_tasks)

    # Log each connector result for debugging
    for r in norm_results:
        if r.status.value == "error":
            app_logger.warning(f"  [{r.source}] status=error — {r.error}")
        elif r.status.value == "ok":
            app_logger.debug(f"  [{r.source}] ok — verdict={r.verdict_hint}")
            # Extra debug for SFS to see what we get from evidence
            if r.source == "stopforumspam" and r.raw:
                ip_data = r.raw.get("ip", {}) or {}
                evidence = ip_data.get("evidence") or []
                assoc    = r.raw.get("_associated_emails", [])
                app_logger.info(
                    f"  [stopforumspam] appears={ip_data.get('appears',0)} "
                    f"freq={ip_data.get('frequency',0)} "
                    f"evidence_entries={len(evidence)} "
                    f"emails_found={len(assoc)}"
                )
                if evidence:
                    app_logger.info(f"  [stopforumspam] evidence[0] sample: {str(evidence[0])[:200]}")
        else:
            app_logger.debug(f"  [{r.source}] status={r.status.value}")

    # Compute score + verdict
    score, verdict = compute_score(norm_results)

    # Aggregate tags and metadata from all results
    all_tags: list[str] = []
    metadata: dict      = {}
    for r in norm_results:
        all_tags.extend(r.tags or [])
        for field in ("country", "city", "asn", "org", "isp", "network",
                      "malware_family", "file_name", "file_type", "file_size",
                      "first_submission", "registrar"):
            if getattr(r, field, None) and field not in metadata:
                metadata[field] = getattr(r, field)

    unique_tags = list(dict.fromkeys(all_tags))  # deduplicate, preserve order

    # Upsert IOC record
    stmt   = select(IOC).where(IOC.value == parsed.value)
    result = await db.execute(stmt)
    ioc    = result.scalar_one_or_none()

    now         = datetime.utcnow()
    cache_until = now + timedelta(hours=settings.cache_ttl_hours)

    if ioc:
        ioc.score       = score
        ioc.verdict     = verdict
        ioc.tags        = json.dumps(unique_tags)
        ioc.metadata_   = json.dumps(metadata)
        ioc.last_scan   = now
        ioc.cache_until = cache_until
    else:
        ioc = IOC(
            value       = parsed.value,
            type        = parsed.type,
            score       = score,
            verdict     = verdict,
            tags        = json.dumps(unique_tags),
            metadata_   = json.dumps(metadata),
            first_seen  = now,
            last_scan   = now,
            cache_until = cache_until,
        )
        db.add(ioc)

    await db.flush()  # get ioc.id

    # Save source results (replace existing for this ioc)
    for r in norm_results:
        stmt_del = SourceResult.__table__.delete().where(
            (SourceResult.ioc_id == ioc.id) &
            (SourceResult.source == r.source)
        )
        await db.execute(stmt_del)
        sr = SourceResult(
            ioc_id     = ioc.id,
            source     = r.source,
            status     = r.status,
            raw_json   = json.dumps(r.raw or {}),
            normalized = json.dumps(r.to_dict(), default=str),
            fetched_at = now,
        )
        db.add(sr)

    # Append scan history
    trigger = ScanTrigger.rescan if force_rescan else ScanTrigger.manual
    db.add(ScanHistory(
        ioc_id       = ioc.id,
        score        = score,
        verdict      = verdict,
        triggered_by = trigger,
        scanned_at   = now,
    ))

    await db.flush()
    return ioc, norm_results


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@router.post("/analyze", response_class=HTMLResponse)
async def analyze(
    request:      Request,
    ioc_input:    str  = Form(...),
    force_rescan: bool = Form(False),
    db:           AsyncSession = Depends(get_db),
):
    t0     = time.monotonic()
    parsed = parse_input(ioc_input)

    if not parsed:
        return templates.TemplateResponse("index.html", {
            "request": request,
            "error": "No valid IOCs detected. Check your input format.",
        })

    # For now: single IOC per request (as per design spec)
    # Future: batch support
    target = parsed[0]

    try:
        ioc, norm_results = await analyze_single(
            target, db, force_rescan=force_rescan
        )
    except Exception as e:
        tb = traceback.format_exc()
        exc_logger.error(f"analyze_single failed for {target.value!r}:\n{tb}")
        app_logger.error(f"500 on /analyze — {type(e).__name__}: {e}")
        raise

    # Build correlations if more than one IOC in same session (future)
    # correlations = run_correlation({target.value: norm_results})

    response_ms = int((time.monotonic() - t0) * 1000)

    # Log query (backend only, never in UI)
    log_query(
        request       = request,
        ioc_value     = target.value,
        ioc_type      = target.type.value,
        verdict       = ioc.verdict.value if ioc.verdict else None,
        forced_rescan = force_rescan,
        response_ms   = response_ms,
    )

    return RedirectResponse(
        url=f"/results/{ioc.id}",
        status_code=303,
    )
