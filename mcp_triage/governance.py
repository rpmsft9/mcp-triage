"""Fleet governance: score servers and recommend least-privilege + egress policy.

Two inputs feed this: the confirmed (genuine) triage results, and the inventory
itself — because some least-privilege gaps (an auth-less server, an empty egress
allow-list) are governance failures whether or not a scanner happened to flag
them. Recommendations map to the OWASP MCP Top 10.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .models import Inventory, Server, TriageResult
from .owasp import category as owasp_category
from .triage import TriageReport


@dataclass
class Recommendation:
    owasp: str
    action: str
    detail: str


@dataclass
class ServerScore:
    server: str
    risk: int                       # 0-100, higher = worse
    genuine_findings: list[TriageResult] = field(default_factory=list)
    recommendations: list[Recommendation] = field(default_factory=list)

    @property
    def grade(self) -> str:
        return "A" if self.risk < 15 else "B" if self.risk < 35 else "C" if self.risk < 60 else "D" if self.risk < 80 else "F"


def _recommend_for_server(server: Server, genuine: list[TriageResult]) -> list[Recommendation]:
    recs: list[Recommendation] = []

    if not server.approved:
        recs.append(Recommendation("MCP09:2025", "Quarantine shadow server",
                                   f"'{server.name}' is unregistered; add to the approved registry or block it."))
    if server.auth == "none" and server.has_sensitive_tool:
        recs.append(Recommendation("MCP07:2025", "Require authentication",
                                   f"'{server.name}' exposes sensitive tools with auth=none; require OAuth."))
    if server.env and not server.secret_manager and server.auth != "oauth":
        recs.append(Recommendation("MCP01:2025", "Move secrets to a vault",
                                   f"Secrets {server.env} are static; source from a secret manager and rotate."))
    if server.unpinned_dependency:
        recs.append(Recommendation("MCP04:2025", "Pin server dependency",
                                   f"'{server.name}' runs unpinned package '{server.dependency_spec}'; "
                                   f"pin to a fixed version and verify provenance."))

    # Egress allow-list for any network-capable tool without one.
    if any(t.network for t in server.tools) and not server.egress_allowlist:
        hosts = _suggest_hosts(server)
        recs.append(Recommendation("MCP10:2025", "Enforce egress allow-list",
                                   f"'{server.name}' makes outbound requests with no allow-list; "
                                   f"restrict egress (suggested: {hosts})."))

    # Least-privilege filesystem scope per tool.
    for t in server.tools:
        if t.fs_scope_is_broad:
            recs.append(Recommendation("MCP02:2025", "Tighten filesystem scope",
                                       f"tool '{t.name}' can access '{t.fs_scope}'; scope to its working directory."))
        if t.exec and not (t.sandboxed or t.validates_args):
            recs.append(Recommendation("MCP05:2025", "Sandbox / validate execution",
                                       f"tool '{t.name}' executes with unvalidated input; parameterize and sandbox."))

    return recs


def _suggest_hosts(server: Server) -> str:
    guesses = {"github": "api.github.com", "postgres": "db.internal", "slack": "slack.com"}
    for key, host in guesses.items():
        if key in server.name.lower():
            return host
    return "<explicit hosts only>"


def score_fleet(inventory: Inventory, report: TriageReport) -> list[ServerScore]:
    by_server: dict[str, list[TriageResult]] = {}
    for r in report.genuine:
        by_server.setdefault(r.finding.server or "(unknown)", []).append(r)

    scores: list[ServerScore] = []
    for server in inventory.servers:
        genuine = by_server.get(server.name, [])
        risk = min(100, sum(r.finding.severity.weight for r in genuine) * 6)
        # governance penalties independent of findings
        if not server.approved:
            risk = min(100, risk + 30)
        if server.auth == "none" and server.has_sensitive_tool:
            risk = min(100, risk + 15)
        recs = _recommend_for_server(server, genuine)
        scores.append(ServerScore(server.name, risk, genuine, recs))

    scores.sort(key=lambda s: s.risk, reverse=True)
    return scores


def egress_policy(inventory: Inventory) -> dict[str, list[str]]:
    """Proposed egress allow-list per server (empty list = deny-all default)."""
    policy: dict[str, list[str]] = {}
    for s in inventory.servers:
        if any(t.network for t in s.tools):
            policy[s.name] = s.egress_allowlist or []
    return policy
