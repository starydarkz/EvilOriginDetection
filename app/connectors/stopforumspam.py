"""
stopforumspam.py — StopForumSpam connector.
Supports: IP, Email. No API key required.
Categories: abuse · threat · relations
Docs: https://www.stopforumspam.com/usage

For IP queries, we fetch evidence submissions to find associated emails.
SFS hashes email fields by default, but the 'evidence' text field and
username field sometimes contain plaintext emails — we extract these
with a regex. We also make a second call to the search endpoint which
returns richer submission data including partial emails.

API with evidence=1:
{
  "ip": {
    "appears": 1,
    "frequency": 42,
    "lastseen": "2024-01-15 12:34:56",
    "confidence": 89.23,
    "country": "RU",
    "evidence": [
      {
        "date": "2024-01-15 10:23:00",
        "username": "spammer123",
        "email": "<hashed>",          ← hashed, not useful
        "evidence": "Spam posted..."   ← may contain plaintext email
      }
    ]
  }
}
"""
import re
from app.models import IOCType
from app.parser import ParsedIOC
from .base import BaseConnector, NormalizedResult
from typing import ClassVar

BASE = "https://api.stopforumspam.org/api"

# Regex to extract emails from free-text evidence fields
EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
)


class StopForumSpamConnector(BaseConnector):
    SOURCE_NAME     = "stopforumspam"
    SUPPORTED_TYPES = {IOCType.ip, IOCType.email}
    DATA_CATEGORIES: ClassVar[set[str]] = {"abuse", "threat", "relations"}
    TIMEOUT         = 15.0

    def requires_key(self) -> bool:
        return False

    async def _fetch(self, ioc: ParsedIOC) -> dict:
        param = "ip" if ioc.type == IOCType.ip else "email"
        params = {param: ioc.value, "json": "1"}

        if ioc.type == IOCType.ip:
            params["evidence"] = "1"

        async with self._client() as c:
            r = await c.get(BASE, params=params)
            r.raise_for_status()
            data = r.json()

            # Second call: nobadip=1 gives a different response structure
            # that sometimes includes more submission detail
            if ioc.type == IOCType.ip and data.get("ip", {}).get("appears"):
                try:
                    r2 = await c.get(BASE, params={
                        "ip": ioc.value, "json": "1",
                        "nobadip": "1", "evidence": "1"
                    })
                    if r2.status_code == 200:
                        data["_nobadip"] = r2.json()
                except Exception:
                    pass

            return data

    def normalize(self, raw: dict, ioc: ParsedIOC,
                  result: NormalizedResult) -> None:
        key  = "ip" if ioc.type == IOCType.ip else "email"
        data = raw.get(key, {}) or {}

        freq       = data.get("frequency",  0) or 0
        found      = data.get("appears",    0) or 0
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

        # ── Extract associated emails from evidence ────────────────
        associated_emails = []

        if ioc.type == IOCType.ip and found:
            seen = set()

            def extract_emails_from_entry(entry: dict) -> list[str]:
                """Pull emails from all text fields in a submission entry."""
                found_emails = []
                for field in ("email", "username", "evidence", "comment"):
                    val = str(entry.get(field) or "")
                    # Direct email field — only if it looks like an email
                    if field == "email" and "@" in val and len(val) < 120:
                        e = val.strip().lower()
                        if e not in seen:
                            seen.add(e)
                            found_emails.append(e)
                    # Free-text fields — extract via regex
                    elif field in ("evidence", "comment", "username"):
                        for match in EMAIL_RE.findall(val):
                            e = match.strip().lower()
                            if e not in seen:
                                seen.add(e)
                                found_emails.append(e)
                return found_emails

            # Evidence from primary response
            for entry in (data.get("evidence") or []):
                if not isinstance(entry, dict):
                    continue
                emails = extract_emails_from_entry(entry)
                for email in emails:
                    associated_emails.append({
                        "email":    email,
                        "date":     entry.get("date"),
                        "username": entry.get("username", ""),
                    })

            # Evidence from nobadip response (different structure)
            nobadip_data = raw.get("_nobadip", {}) or {}
            nb_ip = nobadip_data.get("ip", {}) or {}
            for entry in (nb_ip.get("evidence") or []):
                if not isinstance(entry, dict):
                    continue
                emails = extract_emails_from_entry(entry)
                for email in emails:
                    associated_emails.append({
                        "email":    email,
                        "date":     entry.get("date"),
                        "username": entry.get("username", ""),
                    })

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
                detail += f" · {len(associated_emails)} email(s) linked"
            result.reports.append({
                "date":     lastseen[:19] if lastseen else None,
                "summary":  f"StopForumSpam — {detail}",
                "source":   "stopforumspam",
                "category": "abuse",
            })
            # Individual email-linked entries
            for entry in associated_emails[:3]:
                if entry.get("date"):
                    result.reports.append({
                        "date":     entry["date"][:19],
                        "summary":  f"Spam submission from {entry['email']}"
                                    + (f" (user: {entry['username']})"
                                       if entry.get("username") else ""),
                        "source":   "stopforumspam",
                        "category": "abuse",
                    })
