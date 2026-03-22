"""
ripestat.py — RIPEstat (RIPE NCC) + BGP Ranking (CIRCL) connector.

Authoritative BGP/routing/RIR data for IPs and ASNs.
No API key required.

Endpoints used:
  RIPEstat: https://stat.ripe.net/data/{widget}/data.json?resource={ip}
  BGP Rank: https://bgpranking.circl.lu/json/asn?asn={asn}
"""
from app.models  import IOCType
from app.parser  import ParsedIOC
from .base       import BaseConnector, NormalizedResult
from typing      import ClassVar

RIPE = "https://stat.ripe.net/data"
BGP_RANK = "https://bgpranking.circl.lu/json/asn"


class RIPEstatConnector(BaseConnector):
    SOURCE_NAME:     ClassVar[str]   = "ripestat"
    SUPPORTED_TYPES: ClassVar[set]   = {IOCType.ip}
    DATA_CATEGORIES: ClassVar[set]   = {"host_info"}
    TIMEOUT:         ClassVar[float] = 15.0

    def requires_key(self) -> bool:
        return False

    async def _fetch(self, ioc: ParsedIOC) -> dict:
        import httpx, asyncio

        ip = ioc.value.split(":")[0] if ":" in ioc.value else ioc.value

        async with httpx.AsyncClient(timeout=self.TIMEOUT,
                                     follow_redirects=True) as c:
            # Run RIPEstat calls concurrently
            tasks = {
                "abuse":   c.get(f"{RIPE}/abuse-contact-finder/data.json",
                                 params={"resource": ip}),
                "prefix":  c.get(f"{RIPE}/prefix-overview/data.json",
                                 params={"resource": ip}),
                "geo":     c.get(f"{RIPE}/geoloc/data.json",
                                 params={"resource": ip}),
                "rir":     c.get(f"{RIPE}/rir/data.json",
                                 params={"resource": ip}),
                "bgp":     c.get(f"{RIPE}/bgp-state/data.json",
                                 params={"resource": ip, "rrcs": "0,5,10"}),
            }
            responses = {}
            results_raw = await asyncio.gather(
                *tasks.values(), return_exceptions=True
            )
            for key, res in zip(tasks.keys(), results_raw):
                if isinstance(res, Exception):
                    responses[key] = {}
                elif res.status_code == 200:
                    try:
                        responses[key] = res.json().get("data", {})
                    except Exception:
                        responses[key] = {}
                else:
                    responses[key] = {}

            # Get ASN from prefix-overview for BGP ranking
            asn = None
            prefix_data = responses.get("prefix", {})
            asns = prefix_data.get("asns", [])
            if asns and isinstance(asns, list) and isinstance(asns[0], dict):
                asn = str(asns[0].get("asn", ""))

            # BGP Ranking for this ASN
            bgp_rank_data = {}
            if asn:
                try:
                    r_rank = await c.get(BGP_RANK,
                                         params={"asn": asn},
                                         timeout=8.0)
                    if r_rank.status_code == 200:
                        bgp_rank_data = r_rank.json()
                except Exception:
                    pass

            responses["bgp_rank"] = bgp_rank_data
            responses["_asn"]     = asn
            return responses

    def normalize(self, raw: dict, ioc: ParsedIOC,
                  result: NormalizedResult) -> None:
        # ── Abuse contact ────────────────────────────────────────
        abuse_data = raw.get("abuse", {}) or {}
        abuse_contacts = abuse_data.get("abuse_contacts", [])
        if abuse_contacts:
            result.abuse_contact = (
                abuse_contacts[0] if isinstance(abuse_contacts[0], str)
                else str(abuse_contacts[0])
            )

        # ── Prefix / ASN ─────────────────────────────────────────
        prefix_data = raw.get("prefix", {}) or {}
        block       = prefix_data.get("block", {}) or {}
        result.bgp_prefix = block.get("resource") or prefix_data.get("resource")

        asns = prefix_data.get("asns", [])
        if asns and isinstance(asns, list) and asns:
            first_asn = asns[0] if isinstance(asns[0], dict) else {}
            if not result.asn:
                asn_val = first_asn.get("asn")
                result.asn = str(asn_val) if asn_val else raw.get("_asn")
            if not result.org:
                result.org = first_asn.get("holder")

        # ── Geolocation (RIPE data) ───────────────────────────────
        geo_data     = raw.get("geo", {}) or {}
        geo_locations = geo_data.get("locations", [])
        if geo_locations and isinstance(geo_locations, list):
            loc = geo_locations[0]
            if isinstance(loc, dict):
                if not result.country:
                    result.country   = loc.get("country")
                if not result.city:
                    result.city      = loc.get("city")
                if not result.latitude:
                    result.latitude  = loc.get("latitude")
                if not result.longitude:
                    result.longitude = loc.get("longitude")

        # ── RIR info ─────────────────────────────────────────────
        rir_data = raw.get("rir", {}) or {}
        rirs     = rir_data.get("rirs", [])
        if rirs and isinstance(rirs, list):
            r0 = rirs[0] if isinstance(rirs[0], dict) else {}
            result.rir = r0.get("rir")

        # ── BGP state ────────────────────────────────────────────
        bgp_data = raw.get("bgp", {}) or {}
        routes   = bgp_data.get("routes", [])
        if routes and isinstance(routes, list):
            r0 = routes[0] if isinstance(routes[0], dict) else {}
            if not result.bgp_prefix:
                result.bgp_prefix = r0.get("prefix")

        # ── BGP Ranking ──────────────────────────────────────────
        rank_data = raw.get("bgp_rank", {}) or {}
        if rank_data:
            # CIRCL response: {"response": {"ranking": {"rank": 0.005, "position": 1234}}}
            ranking = (rank_data.get("response", {}) or {}).get("ranking", {}) or {}
            if not ranking:
                # Alternate format
                ranking = rank_data.get("ranking", {}) or {}
            rank  = ranking.get("rank")
            pos   = ranking.get("position")
            total = ranking.get("total")
            if rank is not None:
                result.asn_rank = float(rank)
            if pos is not None:
                result.asn_rank_position = int(pos)

        # ── Verdict — RIPEstat is informational only ─────────────
        result.verdict_hint = "unknown"

        # ── Tags — only flag high-risk ASN, routing info goes to BGP tab ─
        tags = []
        if result.asn_rank is not None and result.asn_rank > 0.7:
            tags.append("high-risk-asn")
        result.tags = tags

        # ── Reports ──────────────────────────────────────────────
        result.reports = []
        if result.abuse_contact or result.bgp_prefix or result.rir:
            details = []
            if result.rir:
                details.append(f"RIR: {result.rir}")
            if result.bgp_prefix:
                details.append(f"prefix: {result.bgp_prefix}")
            if result.abuse_contact:
                details.append(f"abuse: {result.abuse_contact}")
            if result.asn_rank is not None:
                pct = round(result.asn_rank * 100, 1)
                details.append(f"ASN risk percentile: {pct}%")
            result.reports.append({
                "date":     None,
                "summary":  "RIPEstat — " + " · ".join(details),
                "source":   "ripestat",
                "category": "host_info",
            })
