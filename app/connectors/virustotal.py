"""
virustotal.py — VirusTotal v3 connector.
Supports: IP, Domain, Hash (MD5/SHA1/SHA256), URL
Docs: https://developers.virustotal.com/reference
"""
import base64
from typing import Optional
from app.models import IOCType
from app.parser import ParsedIOC
from .base import BaseConnector, NormalizedResult

BASE = "https://www.virustotal.com/api/v3"


class VirusTotalConnector(BaseConnector):
    SOURCE_NAME     = "virustotal"
    SUPPORTED_TYPES = {IOCType.ip, IOCType.domain, IOCType.hash, IOCType.url}

    async def _fetch(self, ioc: ParsedIOC) -> dict:
        endpoint = self._endpoint(ioc)
        async with self._client({"x-apikey": self.api_key}) as client:
            r = await client.get(f"{BASE}{endpoint}")
            r.raise_for_status()
            return r.json()

    def _endpoint(self, ioc: ParsedIOC) -> str:
        match ioc.type:
            case IOCType.ip:
                return f"/ip_addresses/{ioc.value}"
            case IOCType.domain:
                return f"/domains/{ioc.value}"
            case IOCType.hash:
                return f"/files/{ioc.value}"
            case IOCType.url:
                # VT requires base64url-encoded URL, no padding
                encoded = base64.urlsafe_b64encode(
                    ioc.value.encode()
                ).decode().rstrip("=")
                return f"/urls/{encoded}"

    def normalize(self, raw: dict, ioc: ParsedIOC,
                  result: NormalizedResult) -> None:
        attr  = raw.get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})

        result.malicious_count = stats.get("malicious", 0)
        result.total_engines   = sum(stats.values()) if stats else 0
        result.tags            = attr.get("tags", [])
        result.country         = attr.get("country")
        result.asn             = attr.get("asn")
        result.org             = attr.get("as_owner")
        result.network         = attr.get("network")
        result.last_seen       = attr.get("last_modification_date")

        # Compute a quick verdict hint
        suspicious = stats.get("suspicious", 0)
        total      = result.total_engines or 1
        ratio      = (result.malicious_count + suspicious * 0.5) / total
        if ratio >= 0.3:
            result.verdict_hint = "malicious"
        elif ratio >= 0.05:
            result.verdict_hint = "suspicious"
        elif result.malicious_count == 0:
            result.verdict_hint = "clean"
        else:
            result.verdict_hint = "unknown"

        # Hash-specific
        if ioc.type == IOCType.hash:
            result.file_name      = (attr.get("names") or [None])[0]
            result.file_type      = attr.get("type_description")
            result.file_size      = attr.get("size")
            result.malware_family = (attr.get("popular_threat_name") or
                                     attr.get("suggested_threat_label"))
            result.first_submission = attr.get("first_submission_date")
