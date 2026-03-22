"""
hashlookup.py — CIRCL hashlookup + mnemonic Passive DNS connector.

CIRCL hashlookup: https://hashlookup.circl.lu/lookup/{sha1|sha256}/{hash}
  No API key. 180M+ known files (legit software + malware).
  Returns: file name, product, publisher, known-malicious flag.

mnemonic Passive DNS: https://api.mnemonic.no/pdns/v3/{query}
  No API key. Historical DNS resolutions.
  Returns: DNS history, co-hosted domains, first/last seen.

Both are bundled here as they're low-weight info sources.
"""
from app.models  import IOCType
from app.parser  import ParsedIOC
from .base       import BaseConnector, NormalizedResult
from typing      import ClassVar

HASHLOOKUP = "https://hashlookup.circl.lu/lookup"
PDNS       = "https://api.mnemonic.no/pdns/v3"


class HashlookupConnector(BaseConnector):
    """CIRCL hashlookup — for hash IOCs."""
    SOURCE_NAME:     ClassVar[str]   = "hashlookup"
    SUPPORTED_TYPES: ClassVar[set]   = {IOCType.hash}
    DATA_CATEGORIES: ClassVar[set]   = {"file"}
    TIMEOUT:         ClassVar[float] = 10.0

    def requires_key(self) -> bool:
        return False

    async def _fetch(self, ioc: ParsedIOC) -> dict:
        import httpx

        h = ioc.value.lower()
        # Determine hash type by length
        if len(h) == 64:
            algo = "sha256"
        elif len(h) == 40:
            algo = "sha1"
        elif len(h) == 32:
            algo = "md5"
        else:
            return {"_unsupported": True}

        async with httpx.AsyncClient(timeout=self.TIMEOUT) as c:
            r = await c.get(f"{HASHLOOKUP}/{algo}/{h}")
            if r.status_code == 404:
                return {"_not_found": True}
            r.raise_for_status()
            return r.json()

    def normalize(self, raw: dict, ioc: ParsedIOC,
                  result: NormalizedResult) -> None:
        if raw.get("_not_found") or raw.get("_unsupported"):
            result.verdict_hint = "unknown"
            return

        result.known_file = True

        # File metadata
        result.file_name  = (raw.get("FileName")     or
                              raw.get("OriginalFilename") or
                              raw.get("ProductName"))
        result.known_file_name = result.file_name

        product   = raw.get("ProductName")     or raw.get("product")
        publisher = raw.get("Publisher")       or raw.get("CompanyName")
        version   = raw.get("FileVersion")     or raw.get("ProductVersion")
        desc      = raw.get("FileDescription") or raw.get("InternalName")

        # Is it known malicious?
        ks_result = raw.get("KnownMalicious") or raw.get("known_malicious") or ""
        if ks_result and str(ks_result).lower() not in ("false", "0", "no", ""):
            result.verdict_hint  = "malicious"
            result.malware_family = str(ks_result)
        else:
            result.verdict_hint = "clean"

        # Tags
        tags = []
        if product:
            tags.append(product[:30])
        if publisher:
            tags.append(publisher[:30])
        if raw.get("Authentihash"):
            tags.append("signed")
        result.tags = tags[:8]

        # Build summary
        parts = []
        if product:
            parts.append(product)
        if publisher:
            parts.append(f"by {publisher}")
        if version:
            parts.append(f"v{version}")

        summary_str = f"hashlookup — {'⚠ KNOWN MALICIOUS' if result.verdict_hint == 'malicious' else '✓ Known file'}"
        if parts:
            summary_str += f" · {' '.join(parts)}"
        if desc:
            summary_str += f" · {desc[:50]}"

        result.reports = [{
            "date":     None,
            "summary":  summary_str,
            "source":   "hashlookup",
            "category": "file",
            "verdict":  result.verdict_hint,
        }]


class PassiveDNSConnector(BaseConnector):
    """mnemonic Passive DNS — for IP and domain IOCs."""
    SOURCE_NAME:     ClassVar[str]   = "passivedns"
    SUPPORTED_TYPES: ClassVar[set]   = {IOCType.ip, IOCType.domain}
    DATA_CATEGORIES: ClassVar[set]   = {"dns_whois"}
    TIMEOUT:         ClassVar[float] = 12.0

    def requires_key(self) -> bool:
        return False

    async def _fetch(self, ioc: ParsedIOC) -> dict:
        import httpx

        ip = ioc.value.split(":")[0] if ":" in ioc.value else ioc.value

        async with httpx.AsyncClient(timeout=self.TIMEOUT,
                                     follow_redirects=True) as c:
            r = await c.get(
                f"{PDNS}/{ip}",
                params={"limit": 25},
                headers={"Accept": "application/json"},
            )
            if r.status_code in (404, 400):
                return {"_not_found": True}
            r.raise_for_status()
            return r.json()

    def normalize(self, raw: dict, ioc: ParsedIOC,
                  result: NormalizedResult) -> None:
        if raw.get("_not_found"):
            result.verdict_hint = "unknown"
            return

        data = raw.get("data", []) or []
        if not data:
            result.verdict_hint = "unknown"
            return

        result.verdict_hint = "unknown"  # PDNS is informational

        # Build passive DNS records
        pdns_records = []
        seen_pairs: set = set()

        for rec in data[:20]:
            if not isinstance(rec, dict):
                continue
            rrtype  = rec.get("rrtype")  or rec.get("type")  or ""
            query   = rec.get("query")   or rec.get("qname") or ""
            answer  = rec.get("answer")  or rec.get("rdata") or ""
            first   = (rec.get("firstSeenTimestamp") or
                       rec.get("first_seen") or "")[:10]
            last    = (rec.get("lastSeenTimestamp")  or
                       rec.get("last_seen")  or "")[:10]
            count   = rec.get("count") or 1

            key = f"{rrtype}:{query}:{answer}"
            if key in seen_pairs:
                continue
            seen_pairs.add(key)

            pdns_records.append({
                "rrtype":     rrtype,
                "query":      query,
                "answer":     answer,
                "first_seen": first,
                "last_seen":  last,
                "count":      count,
            })

        result.passive_dns = pdns_records

        # For IP: collect co-hosted domains (A/AAAA records pointing to this IP)
        if ioc.type == IOCType.ip:
            domains = [
                r["query"] for r in pdns_records
                if r.get("rrtype") in ("A", "AAAA", "a", "aaaa")
                and r.get("query")
            ]
            # Deduplicate
            seen_d: set = set()
            result.hostnames = []
            for d in domains:
                if d not in seen_d:
                    seen_d.add(d)
                    result.hostnames.append(d)
            result.hostnames = result.hostnames[:15]

        # For domain: collect resolved IPs
        if ioc.type == IOCType.domain:
            resolved = [
                r["answer"] for r in pdns_records
                if r.get("rrtype") in ("A", "AAAA", "a", "aaaa")
                and r.get("answer")
            ]
            result.hostnames = list(dict.fromkeys(resolved))[:10]

        # Tags
        unique_types = list(dict.fromkeys(r["rrtype"] for r in pdns_records if r.get("rrtype")))
        result.tags = [f"pdns:{t}" for t in unique_types[:5]]
        if len(pdns_records) > 10:
            result.tags.append(f"{len(pdns_records)}-dns-records")

        # Timeline — notable DNS changes
        result.reports = []
        if pdns_records:
            earliest = min(
                (r["first_seen"] for r in pdns_records if r.get("first_seen")),
                default=None
            )
            latest = max(
                (r["last_seen"] for r in pdns_records if r.get("last_seen")),
                default=None
            )
            n_domains = len(set(
                r["query"] for r in pdns_records
                if ioc.type == IOCType.ip and r.get("query")
            ))
            summary_parts = [f"Passive DNS — {len(pdns_records)} record(s)"]
            if n_domains > 1:
                summary_parts.append(f"{n_domains} domains co-hosted")
            if earliest:
                summary_parts.append(f"since {earliest}")
            result.reports.append({
                "date":     latest or None,
                "summary":  " · ".join(summary_parts),
                "source":   "passivedns",
                "category": "dns_whois",
            })
