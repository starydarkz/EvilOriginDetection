"""
greynoise.py — GreyNoise Community API connector.
Supports: IP only.
Docs: https://docs.greynoise.io/reference/get_v3-community-ip

Auth: header 'key: YOUR_API_KEY'
Free community endpoint: /v3/community/{ip}
- 200 = IP seen by GreyNoise
- 404 = IP not in GreyNoise dataset (not an error — just "not seen")
- 429 = rate limit exceeded
"""
from app.models import IOCType
from app.parser import ParsedIOC
from .base import BaseConnector, NormalizedResult

BASE = "https://api.greynoise.io/v3"


class GreyNoiseConnector(BaseConnector):
    SOURCE_NAME     = "greynoise"
    SUPPORTED_TYPES = {IOCType.ip}

    async def _fetch(self, ioc: ParsedIOC) -> dict:
        # GreyNoise Community API uses 'key' header
        headers = {"key": self.api_key} if self.api_key else {}
        async with self._client(headers) as c:
            r = await c.get(f"{BASE}/community/{ioc.value}")

            # 404 = IP not in GreyNoise — valid response, just not seen
            if r.status_code == 404:
                return {"ip": ioc.value, "noise": False,
                        "riot": False, "message": "not found"}

            # 429 = rate limited
            if r.status_code == 429:
                raise Exception("GreyNoise rate limit exceeded")

            r.raise_for_status()
            return r.json()

    def normalize(self, raw: dict, ioc: ParsedIOC,
                  result: NormalizedResult) -> None:
        result.classification = raw.get("classification")
        result.is_noise       = raw.get("noise", False)
        result.org            = raw.get("name")
        result.last_seen      = raw.get("last_seen")

        cl = result.classification or ""
        result.verdict_hint = (
            "malicious" if cl == "malicious" else
            "clean"     if cl == "benign"    else
            "unknown"
        )

        # RIOT = known benign infrastructure (Google DNS, Cloudflare, etc.)
        if raw.get("riot"):
            result.verdict_hint = "clean"
            result.tags.append("riot-known-good")

        if result.is_noise and cl != "malicious":
            result.tags.append("scanner-noise")

        if cl == "malicious":
            result.tags.append("greynoise-malicious")
