"""test_scoring.py — Unit tests for the scoring engine."""
from app.scoring import compute_score, _score_to_verdict
from app.connectors.base import NormalizedResult
from app.models import Verdict, SourceStatus, IOCType
from app.parser import ParsedIOC


def make_result(source: str, **kwargs) -> NormalizedResult:
    ioc    = ParsedIOC("1.2.3.4", IOCType.ip, "ip=1.2.3.4")
    result = NormalizedResult(source, ioc, SourceStatus.ok)
    for k, v in kwargs.items():
        setattr(result, k, v)
    return result


def test_all_skipped_returns_unknown():
    ioc    = ParsedIOC("1.2.3.4", IOCType.ip, "ip=1.2.3.4")
    r      = NormalizedResult("virustotal", ioc, SourceStatus.skipped)
    score, verdict = compute_score([r])
    assert verdict == Verdict.unknown

def test_vt_all_malicious():
    r = make_result("virustotal", malicious_count=38, total_engines=38)
    score, verdict = compute_score([r])
    assert score >= 60
    assert verdict == Verdict.malicious

def test_vt_all_clean():
    r = make_result("virustotal", malicious_count=0, total_engines=38)
    score, verdict = compute_score([r])
    assert score < 25
    assert verdict == Verdict.clean

def test_abuseipdb_high():
    r = make_result("abuseipdb", abuse_score=90)
    score, verdict = compute_score([r])
    assert verdict in (Verdict.malicious, Verdict.suspicious)

def test_greynoise_benign_lowers_score():
    r1 = make_result("virustotal", malicious_count=5, total_engines=38)
    r2 = make_result("greynoise", classification="benign")
    score1, _ = compute_score([r1])
    score2, _ = compute_score([r1, r2])
    assert score2 <= score1  # benign greynoise should not raise score

def test_malwarebazaar_instant_malicious():
    r = make_result("malwarebazaar", file_name="trojan.exe", malware_family="Qbot")
    score, verdict = compute_score([r])
    assert verdict == Verdict.malicious

def test_score_verdict_boundaries():
    assert _score_to_verdict(0)   == Verdict.clean
    assert _score_to_verdict(24)  == Verdict.clean
    assert _score_to_verdict(25)  == Verdict.suspicious
    assert _score_to_verdict(59)  == Verdict.suspicious
    assert _score_to_verdict(60)  == Verdict.malicious
    assert _score_to_verdict(100) == Verdict.malicious
