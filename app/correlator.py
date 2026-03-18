"""
correlator.py — Cross-IOC correlation engine for Evil Origin Detection.

Takes a dict of {ioc_value: [NormalizedResult]} and finds relationships.

Heuristics:
  1.  Same /24 subnet (IP pairs)                          → score 70
  2.  Shared ASN / org                                    → score 50
  3.  Domain appears inside URL                           → score 85
  4.  Shared malware family                               → score 90
  5.  Shared threat tags (≥2 matching)                    → score 60
  6.  Both malicious + same country (weak)                → score 30
  7.  PTR record matches domain in batch                  → score 80
  8.  Shared open port (both have same notable port)      → score 40
  9.  Same redirect chain URL                             → score 75
  10. Domain in hostnames of IP (DNS A record match)      → score 85
"""
from dataclasses import dataclass, field
from app.models import IOCType
from app.connectors.base import NormalizedResult


@dataclass
class CorrelationEdge:
    ioc_a:   str
    ioc_b:   str
    score:   int
    reasons: list[str] = field(default_factory=list)


def run_correlation(
    ioc_results: dict[str, list[NormalizedResult]]
) -> list[CorrelationEdge]:
    """
    ioc_results: { ioc_value: [NormalizedResult, ...] }
    Returns deduplicated list of CorrelationEdge, one per pair.
    """
    values = list(ioc_results.keys())
    edges: list[CorrelationEdge] = []

    for i in range(len(values)):
        for j in range(i + 1, len(values)):
            a_val = values[i]
            b_val = values[j]
            found = _correlate_pair(
                a_val, b_val,
                ioc_results[a_val],
                ioc_results[b_val],
            )
            if found:
                max_score = max(f.score for f in found)
                reasons   = [r for f in found for r in f.reasons]
                edges.append(CorrelationEdge(
                    ioc_a=a_val, ioc_b=b_val,
                    score=max_score, reasons=reasons,
                ))

    return edges


# ── Pair correlator ───────────────────────────────────────────────────────────

def _correlate_pair(
    a: str, b: str,
    a_res: list[NormalizedResult],
    b_res: list[NormalizedResult],
) -> list[CorrelationEdge]:
    findings = []

    def add(score: int, reason: str):
        findings.append(CorrelationEdge(a, b, score, [reason]))

    am = _meta(a_res)
    bm = _meta(b_res)

    # 1. Same /24 subnet
    if _is_ip(a) and _is_ip(b) and _same_24(a, b):
        add(70, f"Same /24 subnet ({'.'.join(a.split('.')[:3])}.0/24)")

    # 2. Shared ASN / org
    a_asn = am.get("asn") or am.get("org")
    b_asn = bm.get("asn") or bm.get("org")
    if a_asn and b_asn and a_asn == b_asn:
        add(50, f"Shared ASN/Org: {a_asn}")

    # 3. Domain inside URL
    if _is_domain(a) and _is_url(b) and a in b:
        add(85, f"Domain '{a}' found in URL '{b}'")
    if _is_domain(b) and _is_url(a) and b in a:
        add(85, f"Domain '{b}' found in URL '{a}'")

    # 4. Shared malware family
    a_fam = am.get("malware_family", "")
    b_fam = bm.get("malware_family", "")
    if a_fam and b_fam and a_fam.lower() == b_fam.lower():
        add(90, f"Shared malware family: {a_fam}")

    # 5. Shared threat tags (≥2 matching, excluding noise)
    NOISE_TAGS = {"", "scanner-noise", "riot-known-good", "forum-spam"}
    a_tags = {t.lower() for t in am.get("tags", [])} - NOISE_TAGS
    b_tags = {t.lower() for t in bm.get("tags", [])} - NOISE_TAGS
    shared = a_tags & b_tags
    if len(shared) >= 2:
        add(60, f"Shared tags: {', '.join(sorted(shared)[:4])}")

    # 6. Both malicious + same country (weak signal)
    a_country = am.get("country")
    b_country = bm.get("country")
    if (a_country and a_country == b_country
            and am.get("verdict_hint") == "malicious"
            and bm.get("verdict_hint") == "malicious"):
        add(30, f"Both malicious, same country: {a_country}")

    # 7. PTR / hostname matches domain in batch
    a_hosts = {h.lower() for h in am.get("hostnames", [])}
    b_hosts = {h.lower() for h in bm.get("hostnames", [])}
    if _is_domain(b) and b.lower() in a_hosts:
        add(80, f"PTR record of {a} resolves to {b}")
    if _is_domain(a) and a.lower() in b_hosts:
        add(80, f"PTR record of {b} resolves to {a}")

    # 8. Shared notable open port (both expose same suspicious/uncommon port)
    NOTABLE_PORTS = {
        4444, 1337, 31337, 9001, 6667,  # suspicious
        3389, 5900, 23,                   # RDP, VNC, Telnet
    }
    a_ports = set(am.get("ports", [])) & NOTABLE_PORTS
    b_ports = set(bm.get("ports", [])) & NOTABLE_PORTS
    shared_ports = a_ports & b_ports
    if shared_ports:
        add(40, f"Both expose notable port(s): {', '.join(str(p) for p in sorted(shared_ports))}")

    # 9. Shared redirect URL (both redirect through the same intermediate URL)
    a_redirects = set(am.get("redirects", []))
    b_redirects = set(bm.get("redirects", []))
    shared_redirects = a_redirects & b_redirects
    if shared_redirects:
        ex = next(iter(shared_redirects))
        add(75, f"Shared redirect URL: {ex[:80]}")

    # 10. Domain resolves to IP (DNS A record match)
    if _is_ip(a) and _is_domain(b) and a in b_hosts:
        add(85, f"DNS A record: {b} → {a}")
    if _is_ip(b) and _is_domain(a) and b in a_hosts:
        add(85, f"DNS A record: {a} → {b}")

    return findings


# ── Meta extractor ────────────────────────────────────────────────────────────

def _meta(results: list[NormalizedResult]) -> dict:
    """Merge all source results into a single flat dict for correlation."""
    merged: dict = {
        "tags":      [],
        "hostnames": [],
        "ports":     [],
        "redirects": [],
    }
    for r in results:
        for field in ("asn", "org", "country", "malware_family", "verdict_hint"):
            if getattr(r, field, None) and not merged.get(field):
                merged[field] = getattr(r, field)
        merged["tags"]      += (r.tags      or [])
        merged["hostnames"] += (r.hostnames or [])
        merged["ports"]     += (r.ports     or [])
        merged["redirects"] += (r.redirects or [])
    # Deduplicate lists
    merged["tags"]      = list(dict.fromkeys(merged["tags"]))
    merged["hostnames"] = list(dict.fromkeys(merged["hostnames"]))
    merged["ports"]     = list(dict.fromkeys(merged["ports"]))
    merged["redirects"] = list(dict.fromkeys(merged["redirects"]))
    return merged


# ── Type helpers ──────────────────────────────────────────────────────────────

def _is_ip(v: str) -> bool:
    import re
    return bool(re.match(
        r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$",
        v or ""
    ))

def _is_domain(v: str) -> bool:
    v = v or ""
    return "." in v and not v.startswith("http") and "@" not in v

def _is_url(v: str) -> bool:
    return (v or "").startswith("http")

def _same_24(a: str, b: str) -> bool:
    try:
        return a.rsplit(".", 1)[0] == b.rsplit(".", 1)[0]
    except Exception:
        return False
