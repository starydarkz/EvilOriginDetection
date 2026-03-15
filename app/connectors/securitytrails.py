"""
securitytrails.py — SecurityTrails connector.
Supports: IP, Domain
Docs: https://docs.securitytrails.com/reference
"""
from app.models import IOCType
from app.parser import ParsedIOC
from .base import BaseConnector, NormalizedResult

BASE = "https://api.securitytrails.com/v1"


class SecurityTrailsConnector(BaseConnector):
    SOURCE_NAME     = "securitytrails"
    SUPPORTED_TYPES = {IOCType.ip, IOCType.domain}

    async def _fetch(self, ioc: ParsedIOC) -> dict:
        headers = {"APIKEY": self.api_key}
        async with self._client(headers) as c:
            if ioc.type == IOCType.domain:
                r = await c.get(f"{BASE}/domain/{ioc.value}")
            else:
                r = await c.get(f"{BASE}/ips/nearby/{ioc.value}")
            r.raise_for_status()
            return r.json()

    def normalize(self, raw: dict, ioc: ParsedIOC, result: NormalizedResult) -> None:
        if ioc.type == IOCType.domain:
            records = raw.get("current_dns", {})
            result.dns_records  = records
            result.registrar    = raw.get("whois", {}).get("registrar")
            result.creation_date = raw.get("whois", {}).get("createdDate")
            result.expiry_date  = raw.get("whois", {}).get("expiresDate")
            a_records = records.get("a", {}).get("values", [])
            result.hostnames    = [r.get("ip") for r in a_records if r.get("ip")]
        else:
            blocks = raw.get("blocks", [])
            result.network = blocks[0].get("network") if blocks else None
