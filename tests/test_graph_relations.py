"""test_graph_relations.py — Unit tests for graph enrichment relations."""
import json
import pytest

from app.models import IOCType, SourceStatus, Verdict
from app.routers.results import _graph_data_inner


class DummyResult:
    def __init__(self, ioc):
        self._ioc = ioc

    def scalar_one_or_none(self):
        return self._ioc


class DummyDB:
    def __init__(self, ioc):
        self._ioc = ioc

    async def execute(self, stmt):
        return DummyResult(self._ioc)


class DummyIOC:
    id = 1
    value = "185.220.101.47"
    type = IOCType.ip
    verdict = Verdict.suspicious
    score = 45
    metadata_ = "{}"

    def __init__(self):
        self.source_results = []


class DummySourceResult:
    def __init__(self, source, normalized, raw):
        self.source = source
        self.status = SourceStatus.ok
        self.normalized = json.dumps(normalized)
        self.raw_json = json.dumps(raw)


@pytest.mark.asyncio
async def test_graph_adds_stopforumspam_and_passivedns_relations():
    ioc = DummyIOC()
    ioc.source_results = [
        DummySourceResult(
            "stopforumspam",
            {"email_reports": 45},
            {
                "ip": {
                    "frequency": 45,
                    "evidence": [
                        {"username": "spammer47", "date": "2025-01-01"},
                    ],
                },
                "_associated_emails": [
                    {"email": "abuse@example.net", "username": "spammer47"},
                ],
            },
        ),
        DummySourceResult(
            "passivedns",
            {
                "passive_dns": [
                    {
                        "rrtype": "A",
                        "query": "mail.example.net",
                        "answer": "185.220.101.47",
                        "first_seen": "2024-01-01",
                        "last_seen": "2025-01-01",
                        "count": 3,
                    },
                ]
            },
            {},
        ),
    ]

    graph = await _graph_data_inner(1, DummyDB(ioc))
    labels = {node["data"]["label"] for node in graph["nodes"]}
    edge_labels = {edge["data"]["label"] for edge in graph["edges"]}

    assert "45 spam reports" in labels
    assert "abuse@example.net" in labels
    assert "spammer47" in labels
    assert "mail.example.net" in labels
    assert "reported-for-spam" in edge_labels
    assert "spam-submission" in edge_labels
    assert "spam-username" in edge_labels
    assert "passive-dns" in edge_labels
