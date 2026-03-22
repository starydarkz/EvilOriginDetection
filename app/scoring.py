"""
scoring.py — Risk score computation for Evil Origin Detection.

Takes a list of NormalizedResult objects and returns a 0-100 score + verdict.

Source weights (max contribution points):
  VirusTotal    → 45 pts  (most trusted, engine consensus)
  AbuseIPDB     → 20 pts  (community abuse reports)
  MalwareBazaar → 10 pts  (hash only — instant malicious signal)
  Pulsedive     → 10 pts  (threat feed presence)
  CriminalIP    →  8 pts  (risk score 0-100)
  URLScan       →  5 pts  (malicious verdict from scan)
  StopForumSpam →  5 pts  (spam frequency)
  Shodan        →  3 pts  (CVEs detected → suspicious signal)
  SecurityTrails →  2 pts  (informational only)
  WhatsMyName   →  1 pt   (OSINT presence)
"""
from app.models import Verdict
from app.connectors.base import NormalizedResult

WEIGHTS: dict[str, int] = {
    "virustotal":    45,
    "abuseipdb":     20,
    "malwarebazaar": 10,
    "criminalip":     8,
    "stopforumspam":  5,
    "shodan":         3,
    "securitytrails": 2,
    "whatsmyname":    1,
    # ── New sources ───────────────────────────────────────────────
    "threatfox":     15,   # C2/malware IOC database — high signal
    "urlhaus":       10,   # active malware delivery URLs — high signal
    "feodotracker":  12,   # confirmed botnet C2 — very high signal
    "ripestat":       0,   # informational only (routing/ASN)
    "hashlookup":     8,   # known file verdict
    "passivedns":     0,   # informational only (DNS history)
}


def compute_score(results: list[NormalizedResult]) -> tuple[int, Verdict]:
    """Returns (score 0-100, verdict).

    Hard overrides (bypass weighted average):
    - Feodo Tracker hit → malicious (confirmed botnet C2)
    - ThreatFox malicious hit → malicious
    - MalwareBazaar found → malicious
    - VT ≥ 5 engines → malicious
    - AbuseIPDB ≥ 80% → malicious
    - Credential leak detected → at least suspicious

    Clean requires ALL primary sources (VT + AbuseIPDB) to confirm clean.
    """
    total_weight = 0
    weighted_sum = 0.0

    has_credential_leak = False
    vt_engines     = 0
    vt_malicious   = 0
    abuse_score_v  = None

    for r in results:
        if r.status.value != "ok":
            continue

        # ── Hard override checks ───────────────────────────────
        # Confirmed botnet C2 / active malware distribution
        if r.source in ("feodotracker", "urlhaus") and r.verdict_hint == "malicious":
            return 95, Verdict.malicious

        # ThreatFox with high confidence
        if r.source == "threatfox" and r.verdict_hint == "malicious":
            conf = r.abuse_score or 0
            if conf >= 75:
                return 92, Verdict.malicious

        # MalwareBazaar — file is known malware
        if r.source == "malwarebazaar" and r.verdict_hint == "malicious":
            return 95, Verdict.malicious

        # VT hard override — 5+ engines
        if r.source == "virustotal" and r.total_engines:
            vt_engines   = r.total_engines
            vt_malicious = r.malicious_count or 0
            if vt_malicious >= 5:
                ratio = vt_malicious / vt_engines
                return min(99, round(50 + ratio * 49)), Verdict.malicious

        # AbuseIPDB hard override — ≥80%
        if r.source == "abuseipdb" and r.abuse_score is not None:
            abuse_score_v = r.abuse_score
            if abuse_score_v >= 80:
                return min(95, round(50 + abuse_score_v * 0.45)), Verdict.malicious

        # Credential leak → at least suspicious
        if r.credential_leaks:
            has_credential_leak = True

        # ── Weighted average ───────────────────────────────────
        weight = WEIGHTS.get(r.source, 2)
        ratio  = _source_ratio(r)

        if ratio is None:
            continue

        weighted_sum += ratio * weight
        total_weight += weight

    if total_weight == 0:
        if has_credential_leak:
            return 35, Verdict.suspicious
        return 0, Verdict.unknown

    raw_score = weighted_sum / total_weight * 100
    score     = max(0, min(100, round(raw_score)))

    # Credential leak bumps to at least suspicious
    if has_credential_leak and score < 30:
        score = 30

    return score, _score_to_verdict(score)


def _source_ratio(r: NormalizedResult) -> float | None:
    """
    Returns 0.0–1.0 threat ratio for one source, or None if no signal.
    None means the source has no scoreable data for this IOC type —
    it is excluded from the weighted average entirely.
    """

    # ── VirusTotal — engine consensus ─────────────────────────────
    if r.source == "virustotal":
        if r.total_engines and r.total_engines > 0:
            mal = r.malicious_count or 0
            sus = 0  # suspicious engines not exposed in current normalize
            return (mal + sus * 0.4) / r.total_engines
        return None

    # ── AbuseIPDB — confidence score 0-100 ────────────────────────
    if r.source == "abuseipdb":
        if r.abuse_score is not None:
            return r.abuse_score / 100
        return None

    # ── MalwareBazaar — binary: found = malware ───────────────────
    if r.source == "malwarebazaar":
        if r.file_name or r.malware_family:
            return 1.0   # found in bazaar → confirmed malware
        return 0.0       # not found → not malicious (hash is clean)

    # ── Pulsedive — risk level from feeds ─────────────────────────
    # ── Pulsedive — informational, excluded from scoring ────────────
    if r.source == "pulsedive":
        return None  # enrichment only, not a threat signal

    # ── CriminalIP — risk score 0-100 ─────────────────────────────
    if r.source == "criminalip":
        if r.abuse_score is not None:
            return r.abuse_score / 100
        # Fallback to verdict hint
        return {
            "malicious":  0.8,
            "suspicious": 0.4,
            "clean":      0.0,
        }.get(r.verdict_hint or "unknown")

    # ── URLScan — binary verdict from scan analysis ────────────────
    # ── URLScan — informational, excluded from scoring ──────────────
    if r.source == "urlscan":
        return None  # enrichment only (screenshot, tech stack, etc.)

    # ── StopForumSpam — spam frequency ────────────────────────────
    if r.source == "stopforumspam":
        freq = r.email_reports or 0
        if freq > 0:
            return min(freq / 15, 1.0)
        return 0.0   # explicitly not listed → clean signal

    # ── Shodan — CVEs detected = suspicious ───────────────────────
    if r.source == "shodan":
        # Check if any CVE tags were added during normalize
        has_cve = any(
            t.startswith("CVE-") for t in (r.tags or [])
        )
        if has_cve:
            return 0.6   # known vulnerabilities → suspicious
        if r.ports:
            return 0.0   # indexed but no CVEs → not a threat signal
        return None      # no data

    # ── SecurityTrails — informational, no threat score ───────────
    if r.source == "securitytrails":
        return None   # DNS/WHOIS data — no threat signal

    # ── WhatsMyName — presence on platforms ───────────────────────
    if r.source == "whatsmyname":
        hits = r.username_hits or []
        if hits:
            return 0.1
        return 0.0

    # ── ThreatFox — C2/malware IOC database ──────────────────────
    if r.source == "threatfox":
        if r.abuse_score is not None:
            return r.abuse_score / 100
        if r.verdict_hint == "malicious":
            return 0.9
        return None

    # ── URLhaus — active malware delivery ────────────────────────
    if r.source == "urlhaus":
        if r.verdict_hint == "malicious":
            tags = r.tags or []
            has_active = any("active" in t for t in tags)
            return 1.0 if has_active else 0.85
        return None

    # ── Feodo Tracker — confirmed botnet C2 ──────────────────────
    if r.source == "feodotracker":
        if r.verdict_hint == "malicious":
            return 1.0
        return None

    # ── hashlookup — known file verdict ──────────────────────────
    if r.source == "hashlookup":
        if r.verdict_hint == "malicious":
            return 1.0
        if r.verdict_hint == "clean":
            return 0.0
        return None

    # ── ripestat / passivedns — informational only ────────────────
    if r.source in ("ripestat", "passivedns"):
        return None

    # ── urlquery — direct reputation verdict ──────────────────────
    if r.source == "urlquery":
        if r.verdict_hint == "malicious":
            return 1.0
        if r.verdict_hint == "suspicious":
            return 0.5
        if r.verdict_hint == "clean":
            return 0.0
        return None

    return None


def _score_to_verdict(score: int) -> Verdict:
    """
    Verdict thresholds (calibrated for weighted scoring without pulsedive/urlscan):
    - malicious:  score >= 60  (high confidence threat signal from core sources)
    - suspicious: score >= 25  (some signal but not definitive)
    - clean:      score < 25   (core sources confirm clean or no signal)
    """
    if score >= 60: return Verdict.malicious
    if score >= 25: return Verdict.suspicious
    return Verdict.clean
