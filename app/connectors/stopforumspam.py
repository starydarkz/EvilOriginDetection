"""
stopforumspam.py — StopForumSpam connector.
Supports: IP, Email. No API key required.
Categories: abuse · threat · relations
Docs: https://www.stopforumspam.com/usage

For IP queries, we also fetch evidence submissions which include
associated email addresses — stored in raw["_associated_emails"]
and used for graph correlation.

API response with evidence=1:
{
  "ip": {
    "appears": 1,
    "frequency": 42,
    "lastseen": "2024-01-15 12:34:56",
    "confidence": 89.23,
    "country": "RU",
    "evidence": [
      {"date": "2024-01-15", "email": "spam@evil.com", "username": "baduser"},
      ...
    ]
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
    DATA_CATEGORIES: ClassVar[set[str]] = {"abuse", "threat", "relations"}

    def requires_key(self) -> bool:
        return False

    async def _fetch(self, ioc: ParsedIOC) -> dict:
        param = "ip" if ioc.type == IOCType.ip else "email"
        params = {param: ioc.value, "json": "1"}

        # For IPs: also request evidence to get associated emails
        if ioc.type == IOCType.ip:
            params["evidence"] = "1"

        async with self._client() as c:
            r = await c.get(BASE, params=params)
            r.raise_for_status()
            return r.json()

    def normalize(self, raw: dict, ioc: ParsedIOC,
                  result: NormalizedResult) -> None:
        key  = "ip" if ioc.type == IOCType.ip else "email"
        data = raw.get(key, {}) or {}

        freq       = data.get("frequency",  0)    or 0
        found      = data.get("appears",    0)    or 0
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

        # ── Associated emails from evidence (IP queries only) ──────
        # evidence[] contains submissions that reported this IP,
        # each entry may include the email used during the spam attempt
        associated_emails = []
        if ioc.type == IOCType.ip:
            evidence = data.get("evidence") or []
            seen_emails = set()
            for entry in (evidence if isinstance(evidence, list) else []):
                if not isinstance(entry, dict):
                    continue
                email = (entry.get("email") or "").strip().lower()
                # Skip hashed emails (they look like hex strings, no @)
                if email and "@" in email and email not in seen_emails:
                    seen_emails.add(email)
                    associated_emails.append({
                        "email": email,
                        "date":  entry.get("date"),
                        "username": entry.get("username", ""),
                    })
            # Store for graph router
            if associated_emails:
                raw["_associated_emails"] = associated_emails[:10]

        # ── Reports for timeline ───────────────────────────────────
        result.reports = []
        if found and freq > 0:
            detail = f"Reported {freq} time(s) for forum spam"
            if confidence:
                detail += f" — confidence {int(float(confidence))}%"
            if country:
                detail += f" · origin {country}"
            if associated_emails:
                detail += f" · {len(associated_emails)} associated email(s)"
            result.reports.append({
                "date":     lastseen[:19] if lastseen else None,
                "summary":  f"StopForumSpam — {detail}",
                "source":   "stopforumspam",
                "category": "abuse",
            })
            # Individual email entries as timeline events
            for entry in associated_emails[:3]:
                if entry.get("date"):
                    result.reports.append({
                        "date":    entry["date"][:19],
                        "summary": f"Spam submission from {entry['email']}"
                                   + (f" (user: {entry['username']})"
                                      if entry.get("username") else ""),
                        "source":   "stopforumspam",
                        "category": "abuse",
                    })
