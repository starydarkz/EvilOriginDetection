"""test_ioc_relations.py — Related IOC extraction tests."""
from app.ioc_relations import extract_related_iocs


def _by_value(items):
    return {item["value"]: item for item in items}


def test_extract_stopforumspam_related_iocs():
    related = extract_related_iocs(
        "stopforumspam",
        "185.220.101.47",
        "ip",
        {"email_reports": 45},
        {
            "ip": {
                "frequency": 45,
                "evidence": [
                    {"username": "spammer47", "comment": "mail abuse@example.net"},
                ],
            },
            "_associated_emails": [
                {"email": "known@example.org", "username": "known_user"},
            ],
        },
    )
    values = _by_value(related)

    assert values["45 spam reports"]["type"] == "username"
    assert values["spammer47"]["type"] == "username"
    assert values["abuse@example.net"]["type"] == "email"
    assert values["known@example.org"]["relationship"] == "spam-submission"


def test_extract_passive_dns_related_iocs_for_ip():
    related = extract_related_iocs(
        "passivedns",
        "185.220.101.47",
        "ip",
        {
            "passive_dns": [
                {
                    "rrtype": "A",
                    "query": "mail.example.net",
                    "answer": "185.220.101.47",
                    "first_seen": "2024-01-01",
                    "last_seen": "2025-01-01",
                    "count": 3,
                }
            ]
        },
        {},
    )
    values = _by_value(related)

    assert values["mail.example.net"]["type"] == "domain"
    assert values["mail.example.net"]["relationship"] == "passive-dns A"
    assert values["mail.example.net"]["count"] == 3


def test_extract_virustotal_related_iocs():
    related = extract_related_iocs(
        "virustotal",
        "185.220.101.47",
        "ip",
        {},
        {
            "_relations": {
                "resolutions": [
                    {"attributes": {"host_name": "vt.example.net", "ip_address": "185.220.101.47"}},
                ],
                "contacted_domains": [
                    {"id": "c2.example.org"},
                ],
                "communicating_files": [
                    {"id": "a" * 64, "attributes": {"meaningful_name": "evil.exe"}},
                ],
            }
        },
    )
    values = _by_value(related)

    assert values["vt.example.net"]["type"] == "domain"
    assert values["c2.example.org"]["relationship"] == "contacted"
    assert values["a" * 64]["type"] == "hash"
    assert values["a" * 64]["file_name"] == "evil.exe"


def test_extract_virustotal_splits_concatenated_resolution_ids():
    related = extract_related_iocs(
        "virustotal",
        "185.220.101.47",
        "ip",
        {},
        {
            "_relations": {
                "resolutions": [
                    {"id": "185.220.101.47tor-exit-47.for-privacy.net"},
                ],
            }
        },
    )
    values = _by_value(related)

    assert "tor-exit-47.for-privacy.net" in values
    assert "185.220.101.47tor-exit-47.for-privacy.net" not in values
