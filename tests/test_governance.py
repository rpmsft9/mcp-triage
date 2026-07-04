from mcp_triage.governance import egress_policy, score_fleet
from mcp_triage.report import render_markdown
from mcp_triage.triage import TriageEngine


def _report(inventory, findings):
    return TriageEngine(inventory).triage(findings)


def test_shadow_server_is_critical(inventory, findings):
    scores = {s.server: s for s in score_fleet(inventory, _report(inventory, findings))}
    # Shadow server + adversarial tool poisoning -> maxed-out risk.
    assert scores["notes-sync"].risk == 100
    assert scores["notes-sync"].grade == "F"
    # Clean servers grade well.
    assert scores["utils"].grade == "A"


def test_every_server_scored(inventory, findings):
    scores = score_fleet(inventory, _report(inventory, findings))
    assert {s.server for s in scores} == {s.name for s in inventory.servers}


def test_recommendations_cover_key_gaps(inventory, findings):
    scores = {s.server: s for s in score_fleet(inventory, _report(inventory, findings))}
    owasp_by_server = {name: {r.owasp for r in s.recommendations} for name, s in scores.items()}
    assert "MCP09:2025" in owasp_by_server["notes-sync"]   # shadow server
    assert "MCP07:2025" in owasp_by_server["filesystem"]   # no auth
    assert "MCP01:2025" in owasp_by_server["postgres"]     # static secret
    assert "MCP10:2025" in owasp_by_server["web-fetch"]    # open egress
    assert "MCP02:2025" in owasp_by_server["filesystem"]   # broad fs scope
    assert "MCP05:2025" in owasp_by_server["shell"]        # unsandboxed exec
    assert "MCP04:2025" in owasp_by_server["web-fetch"]    # unpinned dependency


def test_governance_works_without_findings(inventory):
    # Inventory-only mode still surfaces least-privilege gaps.
    from mcp_triage.triage import TriageReport
    scores = {s.server: s for s in score_fleet(inventory, TriageReport([]))}
    assert scores["web-fetch"].recommendations  # open egress caught w/o a finding


def test_egress_policy_lists_network_servers(inventory):
    policy = egress_policy(inventory)
    assert "web-fetch" in policy and policy["web-fetch"] == []       # deny-all default
    assert policy["github"] == ["api.github.com"]
    assert "postgres" not in policy  # no network tools


def test_markdown_report_renders(inventory, findings):
    md = render_markdown(inventory, _report(inventory, findings))
    assert "27 raw findings → 6 genuine" in md
    assert "MCP05:2025" in md
    assert "Proposed egress allow-lists" in md
    assert "SSRF" in md
