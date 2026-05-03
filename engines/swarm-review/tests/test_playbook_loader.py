import os
from core.playbooks import load_all_playbooks


def test_playbooks_load():
    root = os.path.join(os.path.dirname(__file__), "..", "playbooks")
    playbooks = load_all_playbooks(root)
    assert "xss" in playbooks
    assert "sqli" in playbooks


def test_validation_harness():
    from core.harness.validate import load_findings, score_false_positives

    path = os.path.join(os.path.dirname(__file__), "fixtures", "sample_report.json")
    findings = load_findings(path)
    score = score_false_positives(findings)
    assert score["total"] == 1
    assert score["missing_evidence"] == 0


def test_openclaw_schema_validation():
    from core.openclaw_schema import load_schema, validate

    schema_path = os.path.join(os.path.dirname(__file__), "..", "configs", "openclaw_schema.json")
    schema = load_schema(schema_path)
    summary = {
        "schema_version": "1.0",
        "target": "example.com",
        "profile": "cautious",
        "reports": {"json": "a", "markdown": "b", "html": "c"},
        "evidence_zip": None,
        "tech_detected": [],
        "vuln_scan": None,
    }
    errors = validate(summary, schema)
    assert errors == []
