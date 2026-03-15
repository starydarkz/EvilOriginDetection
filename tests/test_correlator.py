"""test_correlator.py — Unit tests for the correlation engine."""
from app.correlator import run_correlation, _same_24, _is_ip, _is_domain, _is_url
from app.connectors.base import NormalizedResult
from app.models import IOCType, SourceStatus
from app.parser import ParsedIOC


def make_result(source: str, ioc_value: str, ioc_type: IOCType, **kwargs) -> NormalizedResult:
    ioc    = ParsedIOC(ioc_value, ioc_type, ioc_value)
    result = NormalizedResult(source, ioc, SourceStatus.ok)
    for k, v in kwargs.items():
        setattr(result, k, v)
    return result


def test_same_24_true():
    assert _same_24("192.168.1.100", "192.168.1.200") is True

def test_same_24_false():
    assert _same_24("192.168.1.100", "192.168.2.100") is False

def test_is_ip():
    assert _is_ip("1.2.3.4") is True
    assert _is_ip("evil.com") is False

def test_is_domain():
    assert _is_domain("evil.com") is True
    assert _is_domain("https://evil.com") is False

def test_is_url():
    assert _is_url("https://evil.com") is True
    assert _is_url("evil.com") is False

def test_same_subnet_correlation():
    r1 = make_result("virustotal", "10.0.0.1", IOCType.ip)
    r2 = make_result("virustotal", "10.0.0.2", IOCType.ip)
    edges = run_correlation({"10.0.0.1": [r1], "10.0.0.2": [r2]})
    assert len(edges) == 1
    assert edges[0].score >= 60
    assert any("subnet" in reason.lower() for reason in edges[0].reasons)

def test_domain_in_url_correlation():
    r1 = make_result("virustotal", "evil.com",              IOCType.domain)
    r2 = make_result("virustotal", "https://evil.com/path", IOCType.url)
    edges = run_correlation({
        "evil.com":              [r1],
        "https://evil.com/path": [r2],
    })
    assert len(edges) == 1
    assert edges[0].score >= 80

def test_shared_malware_family():
    r1 = make_result("virustotal", "aaa" * 32, IOCType.hash, malware_family="Qbot")
    r2 = make_result("virustotal", "bbb" * 32, IOCType.hash, malware_family="Qbot")
    edges = run_correlation({
        "aaa" * 32: [r1],
        "bbb" * 32: [r2],
    })
    assert len(edges) == 1
    assert edges[0].score >= 85

def test_no_correlation_different_subnets():
    r1 = make_result("virustotal", "10.0.0.1", IOCType.ip)
    r2 = make_result("virustotal", "10.1.0.1", IOCType.ip)
    edges = run_correlation({"10.0.0.1": [r1], "10.1.0.1": [r2]})
    # No subnet match, no other shared fields → no edges
    assert len(edges) == 0

def test_shared_asn():
    r1 = make_result("shodan", "1.1.1.1", IOCType.ip, org="AS12345 Evil Corp")
    r2 = make_result("shodan", "1.1.1.2", IOCType.ip, org="AS12345 Evil Corp")
    edges = run_correlation({"1.1.1.1": [r1], "1.1.1.2": [r2]})
    assert any("ASN" in r for e in edges for r in e.reasons)
