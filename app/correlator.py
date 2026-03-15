"""
correlator.py — Cross-IOC correlation engine for Evil Origin Detection.

Takes a list of fully analyzed IOCResult objects and finds relationships
between them. Populates Correlation records in the DB.

Heuristics implemented:
  1. Same /24 subnet (IP pairs)
  2. Shared ASN / org
  3. Domain appears inside URL
  4. Shared malware family (hashes)
  5. Shared tags (>=2 matching threat tags)
  6. Shared country + both malicious (weak signal)
  7. PTR record matches domain in same batch
"""
from dataclasses import dataclass, field
from app.models import IOCType
from app.connectors.base import NormalizedResult


@dataclass
class CorrelationEdge:
    ioc_a:   str
    ioc_b:   str
    score:   int               # 0–100 confidence
    reasons: list[str] = field(default_factory=list)


def run_correlation(
    ioc_results: dict[str, list[NormalizedResult]]
) -> list[CorrelationEdge]:
    """
    ioc_results: { ioc_value: [NormalizedResult, ...] }
    Returns list of CorrelationEdge (deduplicated, one per pair).
    """
    values  = list(ioc_results.keys())
    edges: list[CorrelationEdge] = []

    for i in range(len(values)):
        for j in range(i + 1, len(values)):
            a_val     = values[i]
            b_val     = values[j]
            a_results = ioc_results[a_val]
            b_results = ioc_results[b_val]

            found = _correlate_pair(a_val, b_val, a_results, b_results)
            if found:
                max_score = max(f.score for f in found)
                reasons   = [r for f in found for r in f.reasons]
                edges.append(CorrelationEdge(
                    ioc_a=a_val, ioc_b=b_val,
                    score=max_score, reasons=reasons
                ))

    return edges


# ── Individual heuristics ─────────────────────────────────────────────────────

def _correlate_pair(
    a: str, b: str,
    a_res: list[NormalizedResult],
    b_res: list[NormalizedResult],
) -> list[CorrelationEdge]:
    findings = []

    def add(score: int, reason: str):
        findings.append(CorrelationEdge(a, b, score, [reason]))

    a_meta = _meta(a_res)
    b_meta = _meta(b_res)

    # 1. Same /24 subnet
    if _is_ip(a) and _is_ip(b):
        if _same_24(a, b):
            add(70, f"Same /24 subnet ({'.'.join(a.split('.')[:3])}.0/24)")

    # 2. Shared ASN / org
    a_asn = a_meta.get("asn") or a_meta.get("org")
    b_asn = b_meta.get("asn") or b_meta.get("org")
    if a_asn and b_asn and a_asn == b_asn:
        add(50, f"Shared ASN/Org: {a_asn}")

    # 3. Domain inside URL
    if _is_domain(a) and _is_url(b) and a in b:
        add(85, f"Domain '{a}' found in URL '{b}'")
    if _is_domain(b) and _is_url(a) and b in a:
        add(85, f"Domain '{b}' found in URL '{a}'")

    # 4. Shared malware family
    a_family = a_meta.get("malware_family")
    b_family = b_meta.get("malware_family")
    if a_family and b_family and a_family.lower() == b_family.lower():
        add(90, f"Shared malware family: {a_family}")

    # 5. Shared threat tags (≥2 matching)
    a_tags = set(t.lower() for t in a_meta.get("tags", []))
    b_tags = set(t.lower() for t in b_meta.get("tags", []))
    shared_tags = a_tags & b_tags - {"", "scanner-noise"}
    if len(shared_tags) >= 2:
        add(60, f"Shared tags: {', '.join(list(shared_tags)[:3])}")

    # 6. Same country + both malicious (weak)
    a_country = a_meta.get("country")
    b_country = b_meta.get("country")
    a_verdict = a_meta.get("verdict_hint")
    b_verdict = b_meta.get("verdict_hint")
    if (a_country and a_country == b_country
            and a_verdict == "malicious" and b_verdict == "malicious"):
        add(30, f"Both malicious, same country: {a_country}")

    # 7. PTR / hostname matches domain in batch
    a_hostnames = set(h.lower() for h in a_meta.get("hostnames", []))
    if _is_domain(b) and b.lower() in a_hostnames:
        add(80, f"PTR record of {a} resolves to {b}")
    b_hostnames = set(h.lower() for h in b_meta.get("hostnames", []))
    if _is_domain(a) and a.lower() in b_hostnames:
        add(80, f"PTR record of {b} resolves to {a}")

    return findings


# ── Helpers ───────────────────────────────────────────────────────────────────

def _meta(results: list[NormalizedResult]) -> dict:
    """Merge fields from all source results into a single flat dict."""
    merged: dict = {"tags": [], "hostnames": []}
    for r in results:
        for field in ("asn", "org", "country", "malware_family", "verdict_hint"):
            if getattr(r, field, None) and not merged.get(field):
                merged[field] = getattr(r, field)
        merged["tags"]      += (r.tags or [])
        merged["hostnames"] += (r.hostnames or [])
    return merged


def _is_ip(v: str) -> bool:
    import re
    return bool(re.match(
        r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$", v
    ))

def _is_domain(v: str) -> bool:
    return "." in v and not v.startswith("http") and "@" not in v

def _is_url(v: str) -> bool:
    return v.startswith("http")

def _same_24(a: str, b: str) -> bool:
    try:
        return a.rsplit(".", 1)[0] == b.rsplit(".", 1)[0]
    except Exception:
        return False
