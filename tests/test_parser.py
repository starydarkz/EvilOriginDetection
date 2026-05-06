"""test_parser.py — Unit tests for the IOC parser."""
import pytest
from app.parser import parse_input, detect_type, ParsedIOC
from app.models import IOCType


def test_ip_prefix():
    results = parse_input("ip=1.2.3.4")
    assert len(results) == 1
    assert results[0].type  == IOCType.ip
    assert results[0].value == "1.2.3.4"

def test_domain_prefix():
    results = parse_input("domain=evil.com")
    assert results[0].type == IOCType.domain

def test_hash_sha256():
    h = "a" * 64
    results = parse_input(f"hash={h}")
    assert results[0].type      == IOCType.hash
    assert results[0].hash_algo == "sha256"

def test_hash_md5():
    h = "b" * 32
    results = parse_input(f"hash={h}")
    assert results[0].hash_algo == "md5"

def test_url_prefix():
    results = parse_input("url=https://evil.com/payload")
    assert results[0].type == IOCType.url

def test_mail_prefix():
    results = parse_input("mail=phish@evil.com")
    assert results[0].type == IOCType.email

def test_network_prefix():
    results = parse_input("red=192.168.1.0/24")
    assert results[0].type == IOCType.network

def test_ipv6_prefix():
    results = parse_input("ip=2001:4860:4860::8888")
    assert len(results) == 1
    assert results[0].type == IOCType.ip

def test_ipv6_network_prefix():
    results = parse_input("red=2001:db8::/32")
    assert len(results) == 1
    assert results[0].type == IOCType.network

def test_auto_detect_ip():
    assert detect_type("8.8.8.8") == IOCType.ip

def test_auto_detect_domain():
    assert detect_type("malicious.net") == IOCType.domain

def test_auto_detect_url():
    assert detect_type("https://evil.com") == IOCType.url

def test_auto_detect_email():
    assert detect_type("user@example.com") == IOCType.email

def test_deduplication():
    raw = "ip=1.2.3.4\nip=1.2.3.4\nIP=1.2.3.4"
    results = parse_input(raw)
    assert len(results) == 1

def test_comments_skipped():
    raw = "# this is a comment\nip=1.2.3.4"
    results = parse_input(raw)
    assert len(results) == 1

def test_multiline():
    raw = "ip=1.1.1.1\ndomain=evil.com\nhash=" + "a"*64
    results = parse_input(raw)
    assert len(results) == 3

def test_comma_separated():
    raw = "ip=1.1.1.1, domain=evil.com"
    results = parse_input(raw)
    assert len(results) == 2

def test_unknown_skipped():
    results = parse_input("notavalidioc")
    assert len(results) == 0

def test_invalid_prefixed_ip_skipped():
    results = parse_input("ip=999.999.999.999")
    assert len(results) == 0

def test_invalid_prefixed_hash_skipped():
    results = parse_input("hash=notahash")
    assert len(results) == 0
