"""The core: the 27 -> 6 funnel must reproduce faithfully."""

import pytest

from mcp_triage.models import ReasonCode, Verdict
from mcp_triage.triage import TriageEngine


@pytest.fixture
def report(inventory, findings):
    return TriageEngine(inventory).triage(findings)


def test_funnel_reproduces_27_to_6(report):
    funnel = report.funnel()
    assert funnel == {
        "standard_instruction": 8,
        "designed_feature": 10,
        "false_positive": 3,
        "genuine": 6,
    }
    assert report.total == 27
    assert len(report.genuine) == 6


def test_noise_reduction_matches_appsec_santa(report):
    # 21 of 27 removed -> ~78%, the audited figure the pitch cites.
    assert round(report.noise_reduction, 2) == 0.78


def test_genuine_set_is_exactly_the_right_findings(report):
    assert {r.finding.id for r in report.genuine} == {
        "F-022", "F-023", "F-024", "F-025", "F-026", "F-027"
    }


def _by_id(report, fid):
    return next(r for r in report.results if r.finding.id == fid)


def test_reason_codes(report):
    assert _by_id(report, "F-022").reason == ReasonCode.MISSING_EGRESS_ALLOWLIST
    assert _by_id(report, "F-023").reason == ReasonCode.STATIC_SECRET
    assert _by_id(report, "F-024").reason == ReasonCode.BROAD_FS_SCOPE
    assert _by_id(report, "F-025").reason == ReasonCode.UNMITIGATED_EXEC
    assert _by_id(report, "F-026").reason == ReasonCode.WEAK_AUTH
    assert _by_id(report, "F-027").reason == ReasonCode.ADVERSARIAL_INJECTION


def test_benign_instruction_vs_adversarial(report):
    # Imperative prose is designed behavior...
    assert _by_id(report, "F-001").verdict == Verdict.DESIGNED_BEHAVIOR
    assert _by_id(report, "F-001").reason == ReasonCode.BENIGN_INSTRUCTION
    # ...but hidden adversarial instructions are genuine tool poisoning.
    assert _by_id(report, "F-027").verdict == Verdict.GENUINE


def test_false_positives_are_keyword_only(report):
    for fid in ("F-019", "F-020", "F-021"):
        r = _by_id(report, fid)
        assert r.verdict == Verdict.FALSE_POSITIVE
        assert r.reason == ReasonCode.NO_SUCH_CAPABILITY


def test_mitigated_network_vs_unmitigated(report):
    # github egress is allow-listed -> designed; web-fetch is open -> genuine.
    assert _by_id(report, "F-009").verdict == Verdict.DESIGNED_BEHAVIOR
    assert _by_id(report, "F-022").verdict == Verdict.GENUINE


def test_same_keyword_different_verdict_by_context(report):
    # 'execute' appears in F-003 (benign prose), F-018 (mitigated SQL),
    # F-019 (false positive name match), F-025 (genuine injection).
    assert _by_id(report, "F-003").verdict == Verdict.DESIGNED_BEHAVIOR
    assert _by_id(report, "F-018").verdict == Verdict.DESIGNED_BEHAVIOR
    assert _by_id(report, "F-019").verdict == Verdict.FALSE_POSITIVE
    assert _by_id(report, "F-025").verdict == Verdict.GENUINE


def test_supply_chain_unpinned_vs_pinned(inventory):
    from mcp_triage.inventory import parse_inventory
    from mcp_triage.ingest import parse_findings

    # web-fetch runs `npx -y @acme/mcp-web-fetch` (no version pin) -> genuine.
    engine = TriageEngine(inventory)
    unpinned = parse_findings([
        {"id": "SC-1", "category": "MCP04:2025", "server": "web-fetch",
         "title": "dependency", "severity": "medium"}
    ])
    r = engine.triage_one(unpinned[0])
    assert r.verdict == Verdict.GENUINE
    assert r.reason == ReasonCode.UNPINNED_DEPENDENCY

    # A version-pinned server is designed behavior.
    pinned_inv = parse_inventory({"mcpServers": {
        "pinned": {"command": "npx", "args": ["-y", "@acme/tool@1.4.2"], "tools": []}
    }})
    r2 = TriageEngine(pinned_inv).triage_one(
        parse_findings([{"id": "SC-2", "category": "MCP04:2025", "server": "pinned", "title": "dep"}])[0]
    )
    assert r2.verdict == Verdict.DESIGNED_BEHAVIOR


def test_optional_judge_readjudicates_low_confidence(inventory, findings):
    calls = []

    def stub_judge(finding, server, tool):
        calls.append(finding.id)
        return Verdict.FALSE_POSITIVE, 0.99, "stub override"

    stub_judge.name = "stub"
    report = TriageEngine(inventory, judge=stub_judge).triage(findings)
    # Judge only fires on < 0.8 confidence (the mitigated 'designed features').
    assert calls, "judge should have been consulted"
    mitigated = _by_id(report, "F-009")
    assert mitigated.judge == "stub"
    assert mitigated.verdict == Verdict.FALSE_POSITIVE
    # High-confidence genuine findings are untouched by the judge.
    assert _by_id(report, "F-025").judge == "deterministic"
