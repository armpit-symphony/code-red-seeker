import sys
import asyncio
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from finding_dedupe import attach_fingerprints, filter_duplicate_findings, finding_fingerprint  # noqa: E402


class AsyncCursor:
    def __init__(self, items):
        self.items = list(items)

    def __aiter__(self):
        self.index = 0
        return self

    async def __anext__(self):
        if self.index >= len(self.items):
            raise StopAsyncIteration
        item = self.items[self.index]
        self.index += 1
        return item


class FakeFindingsCollection:
    def __init__(self, existing):
        self.existing = existing

    def find(self, query, projection):
        wanted = set(query["fingerprint"]["$in"])
        return AsyncCursor([{"fingerprint": value} for value in self.existing if value in wanted])


class FakeDatabase:
    def __init__(self, existing):
        self.findings = FakeFindingsCollection(existing)


def sample_finding(**overrides):
    finding = {
        "audit_run_id": "run-1",
        "title": "Unsafe subprocess",
        "severity": "high",
        "affected_surfaces": ["app.py"],
        "source_name": "custom-patterns",
        "source_rule_id": "command-injection",
        "evidence": "subprocess with shell=True",
    }
    finding.update(overrides)
    return finding


def test_finding_fingerprint_is_stable_for_equivalent_input():
    left = sample_finding(affected_surfaces=["app.py", "service.py"])
    right = sample_finding(affected_surfaces=["service.py", "app.py"])

    assert finding_fingerprint(left) == finding_fingerprint(right)


def test_attach_fingerprints_adds_missing_fingerprint():
    findings = attach_fingerprints([sample_finding()])

    assert len(findings[0]["fingerprint"]) == 64


def test_filter_duplicate_findings_removes_existing_and_batch_duplicates():
    first = sample_finding()
    existing_fingerprint = finding_fingerprint(first)
    duplicate_in_batch = sample_finding()
    new_finding = sample_finding(title="Hardcoded token", evidence="token value")

    unique, duplicate_count = asyncio.run(
        filter_duplicate_findings(
            FakeDatabase({existing_fingerprint}),
            "run-1",
            [first, duplicate_in_batch, new_finding],
        )
    )

    assert duplicate_count == 2
    assert len(unique) == 1
    assert unique[0]["title"] == "Hardcoded token"
