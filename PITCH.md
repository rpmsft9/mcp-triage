# MCP Triage & Governance — signal, not scanner #11

**The one-liner:** Everyone can generate MCP security findings. Nobody separates the 6 that matter from the 27 that don't, and nobody governs the fleet once they're found. We do both.

## The problem

MCP is the fastest-growing attack surface in AI, and independent scans converge on the same picture: **33%** of servers carry critical vulnerabilities ([Enkrypt AI](https://www.enkryptai.com/blog/we-scanned-1-000-mcp-servers-33-had-critical-vulnerabilities), 1,000 servers), **~37%** are exploitable via SSRF ([BlueRock](https://www.practical-devsecops.com/mcp-security-statistics-2026-report/), 7,000+), only **8.5%** use OAuth ([Astrix](https://astrix.security/learn/blog/state-of-mcp-server-security-2025/), 5,200+), and a **majority (66%)** have at least one security finding ([AgentSeal](https://agentseal.org/blog/mcp-server-security-findings), 1,808). The flaws are mundane — SSRF, path traversal, injection — because MCP servers are built by ML and systems engineers, not security engineers.

That's a large, real problem. But it has spawned a crowded field of raw scanners (Cisco `mcp-scanner`, Invariant `mcp-scan`, eSentire, plus commercial entrants). Building scanner #11 is a losing move.

The research exposes **two gaps the scanners don't close:**

1. **Noise.** Pattern-based scanners drown teams in noise. One audit of Cisco's `mcp-scanner` found a **~78% false-positive rate** — 27 flags collapsed to just **6 genuine concerns** once designed tool behavior was excluded ([AppSec Santa](https://appsecsanta.com/research/mcp-server-security-audit-2026)). Imperative tool descriptions ("call this tool," "execute this query") trip the same YARA rules meant to catch injection. Findings without triage aren't security; they're a backlog.
2. **Governance.** Static scanning tells you a server is risky. It doesn't inventory your MCP fleet, score it, enforce least-privilege, or lock down egress. Nobody is doing enterprise-grade policy on MCP servers the way we already do for identities and service accounts.

## The wedge

A **triage-and-governance layer that sits on top of any scanner** — it ingests findings from the tools that already exist, so we don't compete with them, we make them usable:

- **False-positive reducer.** An LLM-assisted judge that reasons about each flag in context — is this tool *exploitable*, or is it *designed behavior*? Turns 27 noisy flags into the 6 that warrant action, with a rationale for each kill/keep so a security team can trust the cut.
- **Fleet governance.** Inventory every MCP server, tool, and permission. Score each against the **OWASP MCP Top 10**. Recommend and enforce least-privilege scopes and egress allow-lists — the identity-and-permission discipline MCP fleets don't have yet.

## Why we win

This is direct expression of MCP-server-security and agent-identity-governance expertise — not a pivot into an adjacent space. The triage angle is the specific unmet need: the market is saturated with finding *generators* and starved for finding *filters*. Being scanner-agnostic means every competitor's output becomes our input; their growth is our funnel, not our threat.

Crucially, the wedge already has a real, citable data point behind it: the "27 → 6" collapse isn't a hypothetical — it's the literal result of the AppSec Santa audit of Cisco's scanner (27 YARA detections → 6 genuine after removing 8 standard MCP instructions, 10 designed features, and 3 false positives). Lead with that source by name; it *is* the proof that triage is the unmet need.

## The 90-second demo

Point it at a directory of MCP servers → it inventories tools + permissions, ingests a scanner's raw findings, and returns a ranked, deduplicated shortlist with per-finding "real / designed-behavior" rationale and a least-privilege + egress policy mapped to OWASP MCP Top 10. The "27 → 6" moment is the whole sell — lead with it.

---

## Sources

- Critical vulnerabilities — **33%** of 1,000 servers: [Enkrypt AI, Oct 2025](https://www.enkryptai.com/blog/we-scanned-1-000-mcp-servers-33-had-critical-vulnerabilities)
- OAuth adoption — **8.5%** of 5,200+ servers (53% static keys; 79% keys via env vars): [Astrix Security, Oct 2025](https://astrix.security/learn/blog/state-of-mcp-server-security-2025/)
- SSRF — **36.7%** of 7,000+ servers: [BlueRock Security, 2026](https://www.practical-devsecops.com/mcp-security-statistics-2026-report/) (secondary: Equixly, March 2025, 30%)
- At least one finding — **66%** of 1,808 servers: [AgentSeal](https://agentseal.org/blog/mcp-server-security-findings)
- YARA false-positive rate — **~78%** (21 of 27 flags) on Cisco `mcp-scanner` v4.3.0: [AppSec Santa, Apr 2026](https://appsecsanta.com/research/mcp-server-security-audit-2026)

**Honesty note:** these five figures come from different studies with different samples — present them as a convergent picture from multiple independent scans, not as output of a single study.
