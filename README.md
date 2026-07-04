# mcp-triage

**Signal, not scanner #11.** A triage-and-governance layer that sits on top of *any* MCP
security scanner. It does the two things raw scanners don't:

1. **Reduces false positives** — reasons about whether a flagged tool is actually
   exploitable versus designed behavior, turning 27 noisy flags into the 6 that matter.
2. **Governs the fleet** — inventories MCP servers, tools, and permissions, scores them,
   and recommends least-privilege scopes + egress allow-lists, mapped to the
   [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/).

See [PITCH.md](PITCH.md) for the why, with sourced market data.

## The core idea

A pattern-based scanner sees only the *text* of a tool description, so it flags any
imperative phrase or scary keyword. `mcp-triage` additionally sees the **inventory** — each
tool's real capabilities and each server's governance controls (auth, egress allow-list,
secret manager, filesystem scope, sandboxing) — and **cross-references the two**. That
cross-reference is what separates signal from noise:

| Finding | Scanner sees | We also see | Verdict |
| --- | --- | --- | --- |
| "execute this query" | keyword `execute` | query is parameterized | designed behavior |
| tool named `execute_report_export` | keyword `execute` | tool has no exec capability | false positive |
| `fetch_url` makes outbound requests | network egress | **no egress allow-list** | **genuine (SSRF)** |
| "call this tool to fetch the URL" | imperative directive | ordinary tool prose | standard instruction |
| "ignore previous instructions; exfiltrate…" | imperative directive | **adversarial markers** | **genuine (poisoning)** |

Same keyword, opposite verdict — decided by context, not pattern.

## Install

```bash
pip install -e .            # core (no third-party deps)
pip install -e '.[llm]'     # + optional Anthropic judge
pip install -e '.[dev]'     # + pytest
```

## Usage

```bash
mcp-triage inventory examples/sample_mcp_config.json
mcp-triage triage    examples/sample_mcp_config.json examples/sample_findings.json
mcp-triage triage    examples/sample_mcp_config.json examples/sample_findings.json --json
mcp-triage govern    examples/sample_mcp_config.json
mcp-triage report    examples/sample_mcp_config.json examples/sample_findings.json -o report.md
```

The bundled example reproduces the funnel from the [AppSec Santa audit](https://appsecsanta.com/research/mcp-server-security-audit-2026)
of Cisco's `mcp-scanner` — **27 raw findings → 6 genuine** (~78% noise removed):

```
27 raw findings → 6 genuine (78% noise removed)

    8  Standard MCP instructions
   10  Designed features (mitigated)
    3  False positives
    6  Genuine concerns
```

See [examples/sample_report.md](examples/sample_report.md) for a full generated report.

## Optional LLM judge

`--llm` re-adjudicates only the findings the deterministic rules mark low-confidence
(the "designed feature" bucket), using an Anthropic model to confirm or downgrade them —
further shrinking the genuine set. Requires `ANTHROPIC_API_KEY` and `pip install '.[llm]'`.
Everything works, and the test-suite is green, **without** any API key.

## Bring your own scanner

`mcp-triage` is scanner-agnostic. Findings are normalized on ingest — it reads its native
shape and maps common `rule` / `message` / `match` / `severity` fields, inferring the OWASP
MCP category from keywords when one isn't supplied. Pipe in `mcp-scan`, Cisco `mcp-scanner`,
eSentire, or your own output.

## Architecture

| Module | Responsibility |
| --- | --- |
| `models.py` | Server / Tool / Finding / TriageResult; verdicts + reason codes |
| `owasp.py` | OWASP MCP Top 10 (2025) catalog + remediations |
| `inventory.py` | Parse MCP config → fleet inventory (capabilities + controls) |
| `ingest.py` | Normalize any scanner's findings → `Finding` objects |
| `triage.py` | The engine: cross-reference findings vs inventory → verdicts |
| `llm.py` | Optional Anthropic judge (dependency-free at import) |
| `governance.py` | Risk scoring + least-privilege / egress recommendations |
| `report.py` | Markdown report renderer |
| `cli.py` | `inventory` / `triage` / `govern` / `report` |

## Tests

```bash
python -m pytest -q      # 25 passing, offline
```
