"""
parser.py — IOC input parser for Evil Origin Detection.

Supports:
  ip=       IPv4 / IPv6 address
  red=      CIDR network range
  domain=   domain or subdomain
  hash=     MD5 / SHA1 / SHA256 / SHA512
  url=      full URL (http/https)
  mail=     email address

Also auto-detects type when no prefix is provided.
"""
import re
import ipaddress
from dataclasses import dataclass
from typing import Optional
from app.models import IOCType


# ── Regex patterns ─────────────────────────────────────────────────────────────

_RE = {
    "ipv4":    re.compile(
        r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$"
    ),
    "ipv6":    re.compile(
        r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"
        r"|^::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$"
        r"|^([0-9a-fA-F]{1,4}:){1,7}:$"
    ),
    "cidr":    re.compile(
        r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)"
        r"\/(3[0-2]|[12]?\d)$"
    ),
    "domain":  re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
        r"+[a-zA-Z]{2,}$"
    ),
    "md5":     re.compile(r"^[a-fA-F0-9]{32}$"),
    "sha1":    re.compile(r"^[a-fA-F0-9]{40}$"),
    "sha256":  re.compile(r"^[a-fA-F0-9]{64}$"),
    "sha512":  re.compile(r"^[a-fA-F0-9]{128}$"),
    "url":     re.compile(r"^https?://", re.IGNORECASE),
    "email":   re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$"),
}

# Prefix → IOCType mapping
_PREFIXES: dict[str, IOCType] = {
    "ip":     IOCType.ip,
    "red":    IOCType.network,
    "domain": IOCType.domain,
    "hash":   IOCType.hash,
    "url":    IOCType.url,
    "mail":   IOCType.email,
}


@dataclass
class ParsedIOC:
    value:       str
    type:        IOCType
    raw_input:   str            # original line before stripping prefix
    hash_algo:   Optional[str] = None   # md5 | sha1 | sha256 | sha512


# ── Auto-detection ──────────────────────────────────────────────────────────────

def detect_type(value: str) -> Optional[IOCType]:
    """Infer IOC type from value without prefix hint."""
    v = value.strip()
    if _RE["url"].match(v):     return IOCType.url
    if _RE["email"].match(v):   return IOCType.email
    if _is_network(v):          return IOCType.network
    if _is_ip(v):               return IOCType.ip
    if (_RE["sha512"].match(v) or _RE["sha256"].match(v) or
        _RE["sha1"].match(v)   or _RE["md5"].match(v)):
        return IOCType.hash
    if _RE["domain"].match(v):  return IOCType.domain
    return None


def detect_hash_algo(value: str) -> Optional[str]:
    if _RE["md5"].match(value):    return "md5"
    if _RE["sha1"].match(value):   return "sha1"
    if _RE["sha256"].match(value): return "sha256"
    if _RE["sha512"].match(value): return "sha512"
    return None


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def _is_network(value: str) -> bool:
    try:
        ipaddress.ip_network(value.strip(), strict=False)
        return "/" in value
    except ValueError:
        return False


def _matches_type(value: str, ioc_type: IOCType) -> bool:
    v = value.strip()
    if ioc_type == IOCType.ip:
        return _is_ip(v)
    if ioc_type == IOCType.network:
        return _is_network(v)
    if ioc_type == IOCType.domain:
        return bool(_RE["domain"].match(v))
    if ioc_type == IOCType.hash:
        return detect_hash_algo(v) is not None
    if ioc_type == IOCType.url:
        return bool(_RE["url"].match(v))
    if ioc_type == IOCType.email:
        return bool(_RE["email"].match(v))
    return False


# ── Main parser ─────────────────────────────────────────────────────────────────

def parse_input(raw: str) -> list[ParsedIOC]:
    """
    Parse a multiline / comma-separated IOC string.
    Returns a deduplicated list of ParsedIOC objects.
    Lines starting with # are treated as comments and skipped.
    """
    lines = []
    for chunk in raw.replace(",", "\n").split("\n"):
        chunk = chunk.strip()
        if chunk and not chunk.startswith("#"):
            lines.append(chunk)

    seen: set[str] = set()
    results: list[ParsedIOC] = []

    for line in lines:
        ioc_type: Optional[IOCType] = None
        value = line

        # Check for prefix= format
        if "=" in line:
            prefix, _, rest = line.partition("=")
            prefix = prefix.strip().lower()
            rest   = rest.strip()
            if prefix in _PREFIXES and rest:
                ioc_type = _PREFIXES[prefix]
                value    = rest
                if not _matches_type(value, ioc_type):
                    ioc_type = None

        # Auto-detect if no valid prefix
        if ioc_type is None:
            ioc_type = detect_type(value)

        if ioc_type is None:
            continue  # unrecognizable — skip

        key = value.lower()
        if key in seen:
            continue
        seen.add(key)

        hash_algo = detect_hash_algo(value) if ioc_type == IOCType.hash else None

        results.append(ParsedIOC(
            value=value,
            type=ioc_type,
            raw_input=line,
            hash_algo=hash_algo,
        ))

    return results
