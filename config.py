"""
config.py — Centralized settings for Evil Origin Detection.

All configuration is via environment variables.
On Render: set them in Dashboard → Environment → Environment Variables.
Locally: copy .env.example to .env and fill in your keys.

Token rotation: each source supports two keys (KEY_1 and KEY_2).
At query time, one is picked randomly; if it fails the other is used.
"""
import random
from functools import lru_cache
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── App ───────────────────────────────────────────────────────────
    cache_ttl_hours: int   = 24
    log_level:       str   = "INFO"
    db_path:         str   = "./eod.db"
    log_path:        str   = "./logs/eod.log"

    # ── VirusTotal ────────────────────────────────────────────────────
    vt_key_1: Optional[str] = None
    vt_key_2: Optional[str] = None

    # ── AbuseIPDB ─────────────────────────────────────────────────────
    abuseipdb_key_1: Optional[str] = None
    abuseipdb_key_2: Optional[str] = None

    # ── Shodan ────────────────────────────────────────────────────────
    shodan_key_1: Optional[str] = None
    shodan_key_2: Optional[str] = None

    # ── Pulsedive ─────────────────────────────────────────────────────
    pulsedive_key_1: Optional[str] = None
    pulsedive_key_2: Optional[str] = None

    # ── Criminal IP ───────────────────────────────────────────────────
    criminalip_key_1: Optional[str] = None
    criminalip_key_2: Optional[str] = None

    # ── MalwareBazaar — no key required ──────────────────────────────
    malwarebazaar_key_1: Optional[str] = None
    malwarebazaar_key_2: Optional[str] = None

    # ── URLScan.io ────────────────────────────────────────────────────
    urlscan_key_1: Optional[str] = None
    urlscan_key_2: Optional[str] = None

    # ── SecurityTrails ────────────────────────────────────────────────
    securitytrails_key_1: Optional[str] = None
    securitytrails_key_2: Optional[str] = None

    # ── StopForumSpam — no key required ──────────────────────────────
    stopforumspam_key_1: Optional[str] = None
    stopforumspam_key_2: Optional[str] = None

    # ── WhatsMyName — no key required ─────────────────────────────────
    whatsmyname_key_1: Optional[str] = None
    whatsmyname_key_2: Optional[str] = None

    # ── NEW SOURCES ──────────────────────────────────────────────────
    # ThreatFox, URLhaus, Feodo Tracker, CIRCL hashlookup, RIPEstat, Passive DNS
    # → all free, no key required

    # AlienVault OTX — optional key for higher rate limits
    # Free registration at: https://otx.alienvault.com/
    otx_key_1: Optional[str] = None
    otx_key_2: Optional[str] = None


@lru_cache
def get_settings() -> Settings:
    return Settings()


def pick_key(key1: Optional[str], key2: Optional[str]) -> Optional[str]:
    """
    Token rotation strategy: random selection with fallback.
    - If both keys present: pick one randomly
    - If only one present: use it
    - If neither: return None (connector will return status=no_key)
    """
    available = [k for k in (key1, key2) if k and k.strip()]
    if not available:
        return None
    return random.choice(available)
