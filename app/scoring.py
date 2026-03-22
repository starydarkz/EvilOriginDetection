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
    "pulsedive":     10,
    "criminalip":     8,
    "urlscan":        5,
    "stopforumspam":  5,
    "shodan":         3,
    "securitytrails": 2,
    "whatsmyname":    1,
    # ── New sources ───────────────────────────────────────────────
    "threatfox":     15,   # C2/malware IOC database — high signal
    "urlhaus":       10,   # active malware delivery URLs — high signal
    "feodotracker":  12,   # confirmed botnet C2 — very high signal
    "otx":            8,   # community threat pulses
    "ripestat":       0,   # informational only (routing/ASN)
    "hashlookup":     8,   # known file verdict
    "passivedns":     0,   # informational only (DNS history)
}


def compute_score(results: list[NormalizedResult]) -> tuple[int, Verdict]:
    """Returns (score 0-100, verdict)."""
    total_weight = 0
    weighted_sum = 0.0

    for r in results:
        if r.status.value != "ok":
            continue

        weight = WEIGHTS.get(r.source, 2)
        ratio  = _source_ratio(r)

        if ratio is None:
            continue   # source gave no scoreable signal

        weighted_sum += ratio * weight
        total_weight += weight

    if total_weight == 0:
        return 0, Verdict.unknown

    raw_score = weighted_sum / total_weight * 100
    score     = max(0, min(100, round(raw_score)))
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
    if r.source == "pulsedive":
        hint = r.verdict_hint or "unknown"
        ratio = {
            "malicious":  1.0,
            "suspicious": 0.5,
            "clean":      0.05,
            "unknown":    None,
        }.get(hint)
        if ratio is None and r.pulse_count:
            # Has feeds but no clear verdict → mild signal
            return min(r.pulse_count / 20, 0.4)
        return ratio

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
    if r.source == "urlscan":
        if r.verdict_hint == "malicious":
            return 0.9
        if r.verdict_hint == "unknown":
            return 0.0   # scanned but no malicious verdict → clean signal
        return None      # no scan result at all

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

    # ── OTX — community threat pulses ────────────────────────────
    if r.source == "otx":
        if r.verdict_hint == "malicious":
            return 1.0
        if r.verdict_hint == "suspicious":
            return 0.5
        if r.pulse_count and r.pulse_count > 0:
            return min(r.pulse_count / 10, 0.6)
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

    return None


def _score_to_verdict(score: int) -> Verdict:
    if score >= 55: return Verdict.malicious
    if score >= 22: return Verdict.suspicious
    return Verdict.clean
