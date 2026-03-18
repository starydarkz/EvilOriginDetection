"""
stopforumspam.py — StopForumSpam connector.
Supports: IP, Email. No API key required.
Categories: abuse · threat
Docs: https://www.stopforumspam.com/usage

API response for IP:
{
  "ip": {
    "appears": 1,
    "frequency": 42,
    "lastseen": "2024-01-15 12:34:56",
    "confidence": 89.23,
    "country": "RU"
  }
}
"""
from app.models import IOCType
from app.parser import ParsedIOC
from .base import BaseConnector, NormalizedResult
from typing import ClassVar

BASE = "https://api.stopforumspam.org/api"


class StopForumSpamConnector(BaseConnector):
    SOURCE_NAME     = "stopforumspam"
    SUPPORTED_TYPES = {IOCType.ip, IOCType.email}
    DATA_CATEGORIES: ClassVar[set[str]] = {"abuse", "threat"}

    def requires_key(self) -> bool:
        return False

    async def _fetch(self, ioc: ParsedIOC) -> dict:
        param = "ip" if ioc.type == IOCType.ip else "email"
        async with self._client() as c:
            r = await c.get(BASE, params={param: ioc.value, "json": "1"})
            r.raise_for_status()
            return r.json()

    def normalize(self, raw: dict, ioc: ParsedIOC,
                  result: NormalizedResult) -> None:
        key  = "ip" if ioc.type == IOCType.ip else "email"
        data = raw.get(key, {}) or {}

        freq       = data.get("frequency", 0) or 0
        found      = data.get("appears",   0) or 0
        lastseen   = data.get("lastseen")
        confidence = data.get("confidence")
        country    = data.get("country")

        result.email_reports = freq
        result.last_seen     = lastseen
        result.country       = country

        result.verdict_hint = (
            "malicious"  if freq > 10 else
            "suspicious" if found     else
            "clean"
        )

        if found:
            result.tags.append("forum-spam")
        if confidence and float(confidence) >= 80:
            result.tags.append(f"confidence:{int(float(confidence))}%")

        # ── Reports for timeline ───────────────────────────────────
        result.reports = []
        if found and freq > 0:
            detail = f"Reported {freq} time(s) for forum spam"
            if confidence:
                detail += f" — confidence {int(float(confidence))}%"
            if country:
                detail += f" · from {country}"
            result.reports.append({
                "date":     lastseen[:19] if lastseen else None,
                "summary":  f"StopForumSpam — {detail}",
                "source":   "stopforumspam",
                "category": "abuse",
            })
