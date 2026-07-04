"""Render triage + governance results as a Markdown report."""

from __future__ import annotations

from .governance import ServerScore, egress_policy, score_fleet
from .models import FUNNEL_LABELS, Inventory
from .owasp import category as owasp_category
from .triage import TriageReport


def _funnel_block(report: TriageReport) -> list[str]:
    funnel = report.funnel()
    genuine = funnel.get("genuine", 0)
    lines = [
        "## Triage funnel",
        "",
        f"**{report.total} raw findings → {genuine} genuine concerns** "
        f"({report.noise_reduction * 100:.0f}% noise removed)",
        "",
        "| Bucket | Count |",
        "| --- | ---: |",
    ]
    for bucket, label in FUNNEL_LABELS:
        lines.append(f"| {label} | {funnel.get(bucket, 0)} |")
    lines.append("")
    return lines


def _genuine_block(report: TriageReport) -> list[str]:
    lines = ["## Genuine concerns (ranked)", ""]
    if not report.genuine:
        lines += ["_None — every finding was designed behavior or a false positive._", ""]
        return lines
    ranked = sorted(report.genuine, key=lambda r: r.finding.severity.weight, reverse=True)
    for r in ranked:
        f = r.finding
        cat = owasp_category(f.category)
        where = " / ".join(x for x in (f.server, f.tool) if x)
        lines += [
            f"### [{f.severity.value.upper()}] {f.title}",
            f"- **OWASP:** {cat.id} — {cat.title}",
            f"- **Where:** {where or '(fleet)'}",
            f"- **Why it's real:** {r.rationale}",
            f"- **Fix:** {cat.remediation}",
            "",
        ]
    return lines


def _governance_block(inventory: Inventory, scores: list[ServerScore]) -> list[str]:
    lines = ["## Fleet governance", "", "| Server | Risk | Grade | Genuine | Recommendations |",
             "| --- | ---: | :---: | ---: | ---: |"]
    for s in scores:
        lines.append(f"| {s.server} | {s.risk} | {s.grade} | {len(s.genuine_findings)} | {len(s.recommendations)} |")
    lines.append("")

    lines += ["### Least-privilege & policy recommendations", ""]
    any_recs = False
    for s in scores:
        if not s.recommendations:
            continue
        any_recs = True
        lines.append(f"**{s.server}**")
        for rec in s.recommendations:
            lines.append(f"- `{rec.owasp}` **{rec.action}** — {rec.detail}")
        lines.append("")
    if not any_recs:
        lines += ["_No governance gaps detected._", ""]

    policy = egress_policy(inventory)
    if policy:
        lines += ["### Proposed egress allow-lists", "", "```json", "{"]
        items = list(policy.items())
        for i, (server, hosts) in enumerate(items):
            comma = "," if i < len(items) - 1 else ""
            shown = hosts if hosts else ["<deny-all: set explicit hosts>"]
            lines.append(f'  "{server}": {shown}{comma}'.replace("'", '"'))
        lines += ["}", "```", ""]
    return lines


def render_markdown(inventory: Inventory, report: TriageReport) -> str:
    scores = score_fleet(inventory, report)
    lines = [
        "# MCP Triage & Governance Report",
        "",
        f"_Fleet: {len(inventory.servers)} servers, {inventory.tool_count} tools._",
        "",
    ]
    lines += _funnel_block(report)
    lines += _genuine_block(report)
    lines += _governance_block(inventory, scores)
    return "\n".join(lines)
