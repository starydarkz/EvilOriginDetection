"""
greynoise.py — GreyNoise Community API connector.
Supports: IP only.
Docs: https://docs.greynoise.io/reference
"""
from app.models import IOCType
from app.parser import ParsedIOC
from .base import BaseConnector, NormalizedResult

BASE = "https://api.greynoise.io/v3"


class GreyNoiseConnector(BaseConnector):
    SOURCE_NAME     = "greynoise"
    SUPPORTED_TYPES = {IOCType.ip}

    async def _fetch(self, ioc: ParsedIOC) -> dict:
        async with self._client({"key": self.api_key}) as c:
            r = await c.get(f"{BASE}/community/{ioc.value}")
            r.raise_for_status()
            return r.json()

    def normalize(self, raw: dict, ioc: ParsedIOC, result: NormalizedResult) -> None:
        result.classification = raw.get("classification")   # malicious | benign | unknown
        result.is_noise       = raw.get("noise", False)
        result.org            = raw.get("name")
        result.last_seen      = raw.get("last_seen")
        cl = result.classification or ""
        result.verdict_hint = ("malicious" if cl == "malicious" else
                               "clean"     if cl == "benign"    else "unknown")
        if result.is_noise and cl != "malicious":
            result.tags.append("scanner-noise")
