"""Command-line interface for mcp-triage.

    mcp-triage inventory  <config>
    mcp-triage triage     <config> <findings> [--llm] [--json]
    mcp-triage govern     <config>
    mcp-triage report     <config> <findings> [--llm] [-o out.md]
"""

from __future__ import annotations

import argparse
import json
import sys

from .governance import egress_policy, score_fleet
from .ingest import load_findings
from .inventory import load_inventory
from .models import FUNNEL_LABELS
from .owasp import category as owasp_category
from .report import render_markdown
from .triage import TriageEngine


def _build_engine(config: str, use_llm: bool) -> tuple:
    inventory = load_inventory(config)
    judge = None
    if use_llm:
        from .llm import AnthropicJudge
        judge = AnthropicJudge()
    return inventory, TriageEngine(inventory, judge=judge)


def cmd_inventory(args) -> int:
    inv = load_inventory(args.config)
    print(f"Fleet: {len(inv.servers)} servers, {inv.tool_count} tools\n")
    for s in inv.servers:
        flags = []
        if not s.approved:
            flags.append("SHADOW")
        if s.auth == "none":
            flags.append("no-auth")
        if any(t.network for t in s.tools) and not s.egress_allowlist:
            flags.append("open-egress")
        tag = f"  [{', '.join(flags)}]" if flags else ""
        print(f"- {s.name} (auth={s.auth}, {len(s.tools)} tools){tag}")
        for t in s.tools:
            caps = [c for c, on in (("net", t.network), ("exec", t.exec), ("fs", t.has_fs)) if on]
            print(f"    · {t.name} [{','.join(caps) or 'none'}]")
    return 0


def cmd_triage(args) -> int:
    inv, engine = _build_engine(args.config, args.llm)
    findings = load_findings(args.findings)
    report = engine.triage(findings)

    if args.json:
        print(json.dumps({
            "total": report.total,
            "genuine": len(report.genuine),
            "noise_reduction": round(report.noise_reduction, 3),
            "funnel": report.funnel(),
            "results": [r.to_dict() for r in report.results],
        }, indent=2))
        return 0

    funnel = report.funnel()
    print(f"{report.total} raw findings → {len(report.genuine)} genuine "
          f"({report.noise_reduction * 100:.0f}% noise removed)\n")
    for bucket, label in FUNNEL_LABELS:
        print(f"  {funnel.get(bucket, 0):>3}  {label}")
    print("\nGenuine concerns:")
    for r in sorted(report.genuine, key=lambda x: x.finding.severity.weight, reverse=True):
        cat = owasp_category(r.finding.category)
        where = " / ".join(x for x in (r.finding.server, r.finding.tool) if x)
        print(f"  [{r.finding.severity.value.upper():>8}] {cat.id}  {r.finding.title}  ({where})")
    return 0


def cmd_govern(args) -> int:
    inv = load_inventory(args.config)
    from .triage import TriageReport
    scores = score_fleet(inv, TriageReport([]))
    print("Fleet governance (inventory-only, no findings):\n")
    for s in scores:
        print(f"- {s.server}: grade {s.grade} ({len(s.recommendations)} recommendations)")
        for rec in s.recommendations:
            print(f"    · [{rec.owasp}] {rec.action}: {rec.detail}")
    policy = egress_policy(inv)
    if policy:
        print("\nProposed egress allow-lists:")
        print(json.dumps({k: (v or ["<deny-all>"]) for k, v in policy.items()}, indent=2))
    return 0


def cmd_report(args) -> int:
    inv, engine = _build_engine(args.config, args.llm)
    report = engine.triage(load_findings(args.findings))
    md = render_markdown(inv, report)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(md)
        print(f"Wrote report to {args.output}")
    else:
        print(md)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mcp-triage", description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)

    pi = sub.add_parser("inventory", help="summarize the MCP fleet")
    pi.add_argument("config")
    pi.set_defaults(func=cmd_inventory)

    pt = sub.add_parser("triage", help="triage scanner findings against the inventory")
    pt.add_argument("config")
    pt.add_argument("findings")
    pt.add_argument("--llm", action="store_true", help="use the Anthropic judge for low-confidence findings")
    pt.add_argument("--json", action="store_true", help="emit JSON")
    pt.set_defaults(func=cmd_triage)

    pg = sub.add_parser("govern", help="least-privilege + egress recommendations from the inventory")
    pg.add_argument("config")
    pg.set_defaults(func=cmd_govern)

    pr = sub.add_parser("report", help="full Markdown triage + governance report")
    pr.add_argument("config")
    pr.add_argument("findings")
    pr.add_argument("--llm", action="store_true")
    pr.add_argument("-o", "--output", help="write to file instead of stdout")
    pr.set_defaults(func=cmd_report)
    return p


def main(argv: list[str] | None = None) -> int:
    # Windows consoles default to cp1252; ensure Unicode output works.
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):  # pragma: no cover - platform-dependent
        pass
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
