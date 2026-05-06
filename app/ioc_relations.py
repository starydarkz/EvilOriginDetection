"""ioc_relations.py — Extract related IOCs from normalized and raw source data."""
import ipaddress
import re
from urllib.parse import urlparse

IOC_TYPES = {"ip", "domain", "url", "email", "hash", "network", "username"}
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{128}\b")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}\.?$")
_URL_RE = re.compile(r"^https?://", re.I)
_IP_DOMAIN_RE = re.compile(
    r"^((?:25[0-5]|2[0-4]\d|[01]?\d\d?)\."
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\."
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\."
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?))(.+)$"
)


def _as_dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _as_list(value) -> list:
    return value if isinstance(value, list) else []


def infer_ioc_type(value: str) -> str | None:
    value = str(value or "").strip().strip("'").strip('"').rstrip(".,;)")
    if not value:
        return None
    if _URL_RE.match(value):
        return "url"
    if _EMAIL_RE.fullmatch(value):
        return "email"
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
            return "network"
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if _HASH_RE.fullmatch(value):
        return "hash"
    if _DOMAIN_RE.match(value):
        return "domain"
    return None


def _clean_value(value) -> str:
    if isinstance(value, (dict, list, tuple, set)):
        return ""
    return str(value or "").strip().strip("'").strip('"').rstrip(".,;)")


def _add(out: list[dict], seen: set[tuple[str, str]], value, source: str,
         relationship: str, ioc_type: str | None = None, verdict: str | None = None,
         malware: str | None = None, **extra) -> None:
    value = _clean_value(value)
    if not value:
        return
    ioc_type = (ioc_type or infer_ioc_type(value) or "").lower()
    if ioc_type not in IOC_TYPES:
        return
    key = (ioc_type, value.lower())
    if key in seen:
        return
    seen.add(key)
    item = {
        "value": value,
        "type": ioc_type,
        "relationship": relationship,
        "source": source,
    }
    if verdict:
        item["verdict"] = verdict
    if malware:
        item["malware"] = malware
    for k, v in extra.items():
        if v is not None:
            item[k] = v
    out.append(item)


def _add_text_iocs(out: list[dict], seen: set[tuple[str, str]], text, source: str,
                   relationship: str) -> None:
    text = str(text or "")
    for email in _EMAIL_RE.findall(text):
        _add(out, seen, email, source, relationship, "email", "suspicious")
    for h in _HASH_RE.findall(text):
        _add(out, seen, h, source, relationship, "hash", "suspicious")


def _split_vt_resolution_id(value: str) -> tuple[str, str]:
    value = _clean_value(value)
    if not value:
        return "", ""
    m = _IP_DOMAIN_RE.match(value)
    if m:
        ip = m.group(1)
        host = m.group(2).strip()
        if infer_ioc_type(host) == "domain":
            return ip, host
    if infer_ioc_type(value) == "ip":
        return value, ""
    if infer_ioc_type(value) == "domain":
        return "", value
    return "", ""


def extract_related_iocs(source: str, ioc_value: str, ioc_type: str,
                         normalized: dict | None, raw: dict | None) -> list[dict]:
    normalized = _as_dict(normalized)
    raw = _as_dict(raw)
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    source = source or "unknown"
    ioc_value_l = str(ioc_value or "").lower()

    def add(value, relationship, typ=None, verdict=None, malware=None, **extra):
        value_s = _clean_value(value)
        if not value_s or value_s.lower() == ioc_value_l:
            return
        _add(out, seen, value_s, source, relationship, typ, verdict, malware, **extra)

    for rel in _as_list(normalized.get("related_iocs")) + _as_list(raw.get("related_iocs")):
        rel = _as_dict(rel)
        add(rel.get("value") or rel.get("ioc") or rel.get("indicator"),
            rel.get("relationship") or "related",
            rel.get("type") or rel.get("ioc_type"),
            rel.get("verdict"),
            rel.get("malware") or rel.get("malware_family"))

    for hostname in _as_list(normalized.get("hostnames")):
        add(hostname, "hostname", "domain")

    for hostname in _as_list(raw.get("hostnames")):
        add(hostname, "hostname", "domain")

    for domain in _as_list(normalized.get("link_domains")):
        add(domain, "linked-domain", "domain")

    for rec in _as_list(normalized.get("passive_dns")):
        rec = _as_dict(rec)
        query = _clean_value(rec.get("query")).rstrip(".")
        answer = _clean_value(rec.get("answer")).rstrip(".")
        rrtype = str(rec.get("rrtype") or "").upper()
        if ioc_type == "ip":
            add(query, f"passive-dns {rrtype}".strip(), "domain",
                first_seen=rec.get("first_seen"), last_seen=rec.get("last_seen"), count=rec.get("count"))
        elif ioc_type == "domain":
            add(answer, f"passive-dns {rrtype}".strip(), None,
                first_seen=rec.get("first_seen"), last_seen=rec.get("last_seen"), count=rec.get("count"))
        else:
            add(query, f"passive-dns {rrtype}".strip(), None)
            add(answer, f"passive-dns {rrtype}".strip(), None)

    relations = _as_dict(raw.get("_relations"))
    for item in _as_list(relations.get("resolutions")):
        item = _as_dict(item)
        attr = _as_dict(item.get("attributes"))
        ip_value = attr.get("ip_address")
        host_value = attr.get("host_name")
        if not ip_value or not host_value:
            split_ip, split_host = _split_vt_resolution_id(item.get("id"))
            ip_value = ip_value or split_ip
            host_value = host_value or split_host
        add(ip_value, "dns-resolution", "ip")
        add(host_value, "dns-resolution", "domain")
    for key, relationship in (("contacted_ips", "contacted"), ("contacted_domains", "contacted")):
        for item in _as_list(relations.get(key)):
            item = _as_dict(item)
            add(item.get("id"), relationship, "ip" if key.endswith("ips") else "domain", "suspicious")
    for key, relationship in (("communicating_files", "communicates-with"), ("dropped_files", "drops")):
        for item in _as_list(relations.get(key)):
            item = _as_dict(item)
            attrs = _as_dict(item.get("attributes"))
            add(item.get("id"), relationship, "hash", "malicious",
                malware=_as_dict(attrs.get("popular_threat_classification")).get("suggested_threat_label"),
                file_name=attrs.get("meaningful_name"))

    for item in _as_list(raw.get("_linked_iocs")):
        item = _as_dict(item)
        add(item.get("value"), item.get("relationship") or "linked", item.get("type"), "suspicious")

    for domain in _as_list(raw.get("_connected_domains")):
        add(domain, "connected-domain", "domain", "suspicious")

    lists = _as_dict(raw.get("_lists"))
    for ip in _as_list(lists.get("ips")):
        add(ip, "contacted", "ip", "suspicious")
    for domain in _as_list(lists.get("domains")):
        add(domain, "contacted", "domain", "suspicious")
    for h in _as_list(lists.get("hashes")):
        add(h, "loads", "hash", "suspicious")

    for entry in _as_list(raw.get("_associated_emails")):
        entry = _as_dict(entry)
        add(entry.get("email"), "spam-submission", "email", "suspicious", date=entry.get("date"))
        username = _clean_value(entry.get("username"))
        if username and "@" not in username:
            add(username, "spam-username", "username", "suspicious", date=entry.get("date"))

    ip_data = _as_dict(raw.get("ip"))
    nb_ip = _as_dict(_as_dict(raw.get("_nobadip")).get("ip"))
    for entry in _as_list(ip_data.get("evidence")) + _as_list(nb_ip.get("evidence")):
        entry = _as_dict(entry)
        username = _clean_value(entry.get("username"))
        if username and "@" not in username:
            add(username, "spam-username", "username", "suspicious", date=entry.get("date"))
        for field in ("email", "username", "evidence", "comment"):
            _add_text_iocs(out, seen, entry.get(field), source, "spam-evidence")

    freq = normalized.get("email_reports") or ip_data.get("frequency")
    if freq:
        add(f"{freq} spam reports", "reported-for-spam", "username", "suspicious")

    for hit in _as_list(normalized.get("username_hits")):
        hit = _as_dict(hit)
        add(hit.get("url"), f"account-on {hit.get('site') or ''}".strip(), "url", "suspicious")

    dns_records = _as_dict(normalized.get("dns_records"))
    for rec in _as_list(_as_dict(dns_records.get("a")).get("values")):
        rec = _as_dict(rec)
        add(rec.get("ip"), "a-record", "ip")
    for rec in _as_list(_as_dict(dns_records.get("aaaa")).get("values")):
        rec = _as_dict(rec)
        add(rec.get("ipv6") or rec.get("ip"), "aaaa-record", "ip")
    for rec in _as_list(_as_dict(dns_records.get("mx")).get("values")):
        rec = _as_dict(rec)
        add(rec.get("hostname") or rec.get("value"), "mx-record", "domain")

    return out[:80]
