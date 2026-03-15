"""
test_connectors.py — Unit tests for connector base class and type support.
Real API calls are NOT made here — only structure and dispatch logic is tested.
"""
import pytest
import asyncio
from app.connectors.base import BaseConnector, NormalizedResult
from app.connectors.virustotal    import VirusTotalConnector
from app.connectors.abuseipdb     import AbuseIPDBConnector
from app.connectors.greynoise     import GreyNoiseConnector
from app.connectors.shodan        import ShodanConnector
from app.connectors.malwarebazaar import MalwareBazaarConnector
from app.connectors.urlscan       import URLScanConnector
from app.connectors.stopforumspam import StopForumSpamConnector
from app.models import IOCType, SourceStatus
from app.parser import ParsedIOC


def ioc(value, type_): return ParsedIOC(value, type_, value)


# ── Type support ──────────────────────────────────────────────────────

def test_vt_supports_ip():
    assert VirusTotalConnector().supports(ioc("1.2.3.4", IOCType.ip))

def test_vt_supports_hash():
    assert VirusTotalConnector().supports(ioc("a"*64, IOCType.hash))

def test_vt_not_supports_email():
    assert not VirusTotalConnector().supports(ioc("x@y.com", IOCType.email))

def test_abuseipdb_only_ip():
    c = AbuseIPDBConnector()
    assert     c.supports(ioc("1.2.3.4", IOCType.ip))
    assert not c.supports(ioc("evil.com", IOCType.domain))

def test_greynoise_only_ip():
    assert GreyNoiseConnector().supports(ioc("1.2.3.4", IOCType.ip))
    assert not GreyNoiseConnector().supports(ioc("evil.com", IOCType.domain))

def test_malwarebazaar_only_hash():
    c = MalwareBazaarConnector()
    assert     c.supports(ioc("a"*64, IOCType.hash))
    assert not c.supports(ioc("1.2.3.4", IOCType.ip))

def test_malwarebazaar_no_key_required():
    assert MalwareBazaarConnector().requires_key() is False

def test_stopforumspam_no_key_required():
    assert StopForumSpamConnector().requires_key() is False

def test_stopforumspam_ip_and_email():
    c = StopForumSpamConnector()
    assert c.supports(ioc("1.2.3.4",   IOCType.ip))
    assert c.supports(ioc("x@y.com",   IOCType.email))
    assert not c.supports(ioc("evil.com", IOCType.domain))

def test_urlscan_url_and_domain():
    c = URLScanConnector()
    assert c.supports(ioc("https://evil.com", IOCType.url))
    assert c.supports(ioc("evil.com",         IOCType.domain))
    assert not c.supports(ioc("1.2.3.4",      IOCType.ip))


# ── No key → status no_key ─────────────────────────────────────────────

def test_vt_no_key_returns_no_key_status():
    c   = VirusTotalConnector(api_key=None)
    result = asyncio.get_event_loop().run_until_complete(
        c.query(ioc("1.2.3.4", IOCType.ip))
    )
    assert result.status == SourceStatus.no_key

def test_skipped_type_returns_skipped():
    c = AbuseIPDBConnector(api_key="fake")
    result = asyncio.get_event_loop().run_until_complete(
        c.query(ioc("evil.com", IOCType.domain))
    )
    assert result.status == SourceStatus.skipped


# ── Normalization (with mock data) ─────────────────────────────────────

def test_vt_normalize_malicious():
    c   = VirusTotalConnector(api_key="x")
    i   = ioc("1.2.3.4", IOCType.ip)
    raw = {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 30, "suspicious": 2, "harmless": 6, "undetected": 0},
        "tags": ["c2", "botnet"],
        "country": "RU",
    }}}
    result = NormalizedResult("virustotal", i, SourceStatus.ok)
    c.normalize(raw, i, result)
    assert result.malicious_count == 30
    assert result.total_engines   == 38
    assert result.verdict_hint    == "malicious"
    assert "c2" in result.tags

def test_abuseipdb_normalize():
    from app.connectors.abuseipdb import AbuseIPDBConnector
    c   = AbuseIPDBConnector(api_key="x")
    i   = ioc("1.2.3.4", IOCType.ip)
    raw = {"data": {"abuseConfidenceScore": 90, "countryCode": "CN",
                    "isp": "Evil ISP", "usageType": "Data Center",
                    "isTor": False, "lastReportedAt": "2025-01-01"}}
    result = NormalizedResult("abuseipdb", i, SourceStatus.ok)
    c.normalize(raw, i, result)
    assert result.abuse_score   == 90
    assert result.verdict_hint  == "malicious"
    assert result.country       == "CN"
