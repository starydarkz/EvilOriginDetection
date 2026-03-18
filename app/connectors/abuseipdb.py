"""
abuseipdb.py — AbuseIPDB connector.
Supports: IP only.
Categories: threat · abuse · host_info
Docs: https://docs.abuseipdb.com/

With verbose=true we get the last reports[] which include:
  - reportedAt (ISO date)
  - comment
  - categories[] (int IDs)
  - reporterId, reporterCountryCode

These are extracted into result.reports[] for the activity timeline.
"""
from app.models import IOCType
from app.parser import ParsedIOC
from .base import BaseConnector, NormalizedResult
from typing import ClassVar

BASE = "https://api.abuseipdb.com/api/v2"

CATEGORIES = {
    1:  "DNS Compromise",   2:  "DNS Poisoning",
    3:  "Fraud Orders",     4:  "DDoS Attack",
    5:  "FTP Brute-Force",  6:  "Ping of Death",
    7:  "Phishing",         8:  "Fraud VoIP",
    9:  "Open Proxy",       10: "Web Spam",
    11: "Email Spam",       12: "Blog Spam",
    13: "VPN IP",           14: "Port Scan",
    15: "Hacking",          16: "SQL Injection",
    17: "Spoofing",         18: "Brute-Force",
    19: "Bad Web Bot",      20: "Exploited Host",
    21: "Web App Attack",   22: "SSH",
    23: "IoT Targeted",
}


class AbuseIPDBConnector(BaseConnector):
    SOURCE_NAME     = "abuseipdb"
    SUPPORTED_TYPES = {IOCType.ip}
    DATA_CATEGORIES: ClassVar[set[str]] = {"threat", "abuse", "host_info"}

    async def _fetch(self, ioc: ParsedIOC) -> dict:
        params = {
            "ipAddress":    ioc.value,
            "maxAgeInDays": "90",
            "verbose":      "",
        }
        async with self._client(
            {"Key": self.api_key, "Accept": "application/json"}
        ) as c:
            r = await c.get(f"{BASE}/check", params=params)
            r.raise_for_status()
            return r.json()

    def normalize(self, raw: dict, ioc: ParsedIOC,
                  result: NormalizedResult) -> None:
        d = raw.get("data", {})

        # ── Threat / abuse ────────────────────────────────────────
        result.abuse_score = d.get("abuseConfidenceScore")
        result.last_seen   = d.get("lastReportedAt")

        score = result.abuse_score or 0
        result.verdict_hint = (
            "malicious"  if score >= 75 else
            "suspicious" if score >= 25 else
            "clean"
        )

        # ── Host info ─────────────────────────────────────────────
        result.country     = d.get("countryCode")
        result.isp         = d.get("isp")
        result.org         = d.get("domain")
        result.usage_type  = d.get("usageType")
        result.is_tor      = d.get("isTor", False)

        # ── Tags from unique categories across all reports ─────────
        reports_raw = d.get("reports", []) or []
        cat_ids: set[int] = set()
        for report in reports_raw:
            for cat_id in (report.get("categories") or []):
                cat_ids.add(cat_id)
        result.tags = [
            CATEGORIES[cid] for cid in sorted(cat_ids)
            if cid in CATEGORIES
        ]

        # ── Individual reports → timeline ──────────────────────────
        # Extract top 10 most recent, each with date + categories
        result.reports = []
        for rep in reports_raw[:10]:
            reported_at = rep.get("reportedAt", "")
            cats = [
                CATEGORIES[c] for c in (rep.get("categories") or [])
                if c in CATEGORIES
            ]
            comment = (rep.get("comment") or "").strip()
            summary = ", ".join(cats) if cats else "Abuse report"
            if comment and len(comment) < 120:
                summary += f" — {comment}"
            result.reports.append({
                "date":     reported_at[:19] if reported_at else None,
                "summary":  summary,
                "source":   "abuseipdb",
                "category": cats[0] if cats else "abuse",
                "country":  rep.get("reporterCountryCode"),
            })
