"""
abuseipdb.py — AbuseIPDB connector. Supports: IP only.
Docs: https://docs.abuseipdb.com/

With verbose=true we get the last reports which include categories.
Category IDs mapped to human-readable labels per AbuseIPDB docs.
"""
from app.models import IOCType
from app.parser import ParsedIOC
from .base import BaseConnector, NormalizedResult

BASE = "https://api.abuseipdb.com/api/v2"

# AbuseIPDB category ID → label
# https://www.abuseipdb.com/categories
CATEGORIES = {
    1:  "DNS Compromise",
    2:  "DNS Poisoning",
    3:  "Fraud Orders",
    4:  "DDoS Attack",
    5:  "FTP Brute-Force",
    6:  "Ping of Death",
    7:  "Phishing",
    8:  "Fraud VoIP",
    9:  "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}


class AbuseIPDBConnector(BaseConnector):
    SOURCE_NAME     = "abuseipdb"
    SUPPORTED_TYPES = {IOCType.ip}

    async def _fetch(self, ioc: ParsedIOC) -> dict:
        params = {
            "ipAddress":    ioc.value,
            "maxAgeInDays": "90",
            "verbose":      "",      # includes last reports with categories
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
        result.abuse_score = d.get("abuseConfidenceScore")
        result.country     = d.get("countryCode")
        result.isp         = d.get("isp")
        result.org         = d.get("domain")
        result.usage_type  = d.get("usageType")
        result.is_tor      = d.get("isTor", False)
        result.last_seen   = d.get("lastReportedAt")

        # Extract unique category labels from recent reports
        reports    = d.get("reports", []) or []
        cat_ids: set[int] = set()
        for report in reports:
            for cat_id in (report.get("categories") or []):
                cat_ids.add(cat_id)

        result.tags = [
            CATEGORIES[cid] for cid in sorted(cat_ids)
            if cid in CATEGORIES
        ]

        score = result.abuse_score or 0
        result.verdict_hint = (
            "malicious"  if score >= 75 else
            "suspicious" if score >= 25 else
            "clean"
        )
