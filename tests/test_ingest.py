from mcp_triage.ingest import parse_findings
from mcp_triage.models import Severity


def test_all_findings_parsed(findings):
    assert len(findings) == 27
    assert all(f.id for f in findings)


def test_severity_parsed(findings):
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    assert {f.id for f in crit} == {"F-025", "F-027"}


def test_category_inference_when_missing():
    parsed = parse_findings([
        {"rule": "possible SSRF in outbound fetch", "server": "x", "tool": "y"},
        {"message": "static api key found in env", "server": "x"},
        {"title": "unauthenticated server exposed", "server": "x"},
    ])
    assert parsed[0].category == "MCP10:2025"
    assert parsed[1].category == "MCP01:2025"
    assert parsed[2].category == "MCP07:2025"


def test_common_scanner_field_aliases():
    parsed = parse_findings([{"rule": "R1", "match": "some evidence", "severity": "high"}])
    assert parsed[0].title == "R1"
    assert parsed[0].evidence == "some evidence"
    assert parsed[0].severity == Severity.HIGH
