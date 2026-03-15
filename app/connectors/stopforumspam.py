"""
stopforumspam.py — StopForumSpam connector.
Supports: IP, Email. No API key required.
Docs: https://www.stopforumspam.com/usage
"""
from app.models import IOCType
from app.parser import ParsedIOC
from .base import BaseConnector, NormalizedResult

BASE = "https://api.stopforumspam.org/api"


class StopForumSpamConnector(BaseConnector):
    SOURCE_NAME     = "stopforumspam"
    SUPPORTED_TYPES = {IOCType.ip, IOCType.email}

    def requires_key(self) -> bool:
        return False

    async def _fetch(self, ioc: ParsedIOC) -> dict:
        param = "ip" if ioc.type == IOCType.ip else "email"
        async with self._client() as c:
            r = await c.get(BASE, params={param: ioc.value, "json": "1"})
            r.raise_for_status()
            return r.json()

    def normalize(self, raw: dict, ioc: ParsedIOC, result: NormalizedResult) -> None:
        key   = "ip" if ioc.type == IOCType.ip else "email"
        data  = raw.get(key, {})
        freq  = data.get("frequency", 0)
        found = data.get("appears", 0)
        result.email_reports = freq
        result.verdict_hint  = ("malicious"  if freq > 10 else
                                "suspicious" if found else "clean")
        if found:
            result.tags.append("forum-spam")
