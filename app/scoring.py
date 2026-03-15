"""
scoring.py — Risk score computation for Evil Origin Detection.

Takes a list of NormalizedResult objects for a single IOC and
returns a final 0-100 score + verdict.

Source weights (tunable):
  VirusTotal   → up to 45 pts  (most trusted for malware)
  AbuseIPDB    → up to 20 pts
  GreyNoise    → up to 15 pts
  Pulsedive    → up to 10 pts
  CriminalIP   → up to 8 pts
  MalwareBazaar→ up to 10 pts (hash only — instant malicious signal)
  URLScan      → up to 5 pts
  StopForumSpam→ up to 5 pts
  Others       → up to 5 pts each (informational)
"""
from app.models import Verdict
from app.connectors.base import NormalizedResult


# Weight map: source_name → max contribution points
WEIGHTS: dict[str, int] = {
    "virustotal":    45,
    "abuseipdb":     20,
    "greynoise":     15,
    "pulsedive":     10,
    "malwarebazaar": 10,
    "criminalip":     8,
    "urlscan":        5,
    "stopforumspam":  5,
    "shodan":         3,
    "securitytrails": 2,
    "whatsmyname":    1,
}


def compute_score(results: list[NormalizedResult]) -> tuple[int, Verdict]:
    """
    Returns (score 0-100, verdict).
    """
    total_weight = 0
    weighted_sum = 0.0

    for r in results:
        if r.status.value not in ("ok",):
            continue

        weight = WEIGHTS.get(r.source, 2)
        ratio  = _source_ratio(r)

        if ratio is None:
            continue   # source gave no scoreable signal

        weighted_sum  += ratio * weight
        total_weight  += weight

    if total_weight == 0:
        return 0, Verdict.unknown

    raw_score = weighted_sum / total_weight * 100
    score     = max(0, min(100, round(raw_score)))
    verdict   = _score_to_verdict(score)
    return score, verdict


def _source_ratio(r: NormalizedResult) -> float | None:
    """Returns 0.0–1.0 threat ratio for one source, or None if no signal."""

    if r.source == "virustotal":
        if r.total_engines and r.total_engines > 0:
            mal  = (r.malicious_count or 0)
            return mal / r.total_engines
        return None

    if r.source == "abuseipdb":
        if r.abuse_score is not None:
            return r.abuse_score / 100
        return None

    if r.source == "greynoise":
        cl = r.classification or ""
        if cl == "malicious":  return 1.0
        if cl == "benign":     return 0.0
        if r.is_noise:         return 0.3
        return None

    if r.source == "pulsedive":
        hint = r.verdict_hint or ""
        return {"malicious": 1.0, "suspicious": 0.5,
                "clean": 0.0, "unknown": None}.get(hint)

    if r.source == "malwarebazaar":
        # If found in bazaar → definite malware
        return 1.0 if r.file_name or r.malware_family else None

    if r.source == "criminalip":
        if r.abuse_score is not None:
            return r.abuse_score / 100
        return 0.7 if r.verdict_hint == "malicious" else None

    if r.source == "urlscan":
        return 0.8 if r.verdict_hint == "malicious" else 0.0

    if r.source == "stopforumspam":
        freq = r.email_reports or 0
        return min(freq / 20, 1.0) if freq > 0 else 0.0

    return None


def _score_to_verdict(score: int) -> Verdict:
    if score >= 60: return Verdict.malicious
    if score >= 25: return Verdict.suspicious
    if score >= 0:  return Verdict.clean
    return Verdict.unknown
