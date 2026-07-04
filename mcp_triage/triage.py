"""The triage engine — the product's core.

A pattern-based scanner flags a keyword. We decide whether that flag is a
*genuine* concern, *designed behavior*, or a *false positive* by cross-
referencing the finding against the real inventory: the tool's actual
capabilities and the server's governance controls (auth, egress allow-lists,
secret manager, filesystem scope, sandboxing).

Everything here is deterministic and explainable. An optional LLM ``judge``
(see ``llm.py``) can be plugged in to re-adjudicate the findings the rules mark
as low-confidence, further shrinking the genuine set — but the tool is fully
functional, and the test-suite green, without any API key.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, Optional

from .models import (
    FUNNEL_LABELS,
    Finding,
    Inventory,
    ReasonCode,
    Server,
    Tool,
    TriageResult,
    Verdict,
)

# Markers that distinguish an *adversarial* injected instruction (real tool
# poisoning) from ordinary imperative tool prose ("call this tool to ...").
ADVERSARIAL_MARKERS = (
    "ignore previous",
    "ignore all previous",
    "disregard",
    "do not tell",
    "don't tell",
    "without telling",
    "without informing",
    "secretly",
    "exfiltrat",
    "send the file",
    "send file",
    "send contents",
    "send the contents",
    "base64",
    "attacker",
    "http://",
    "https://",
)

INJECTION_CATS = {"MCP03:2025", "MCP06:2025"}
# capability implied by each capability-style category
CAP_FOR_CATEGORY = {
    "MCP01:2025": "secret",
    "MCP02:2025": "fs",
    "MCP05:2025": "exec",
    "MCP10:2025": "network",
}

# A judge takes (finding, server, tool) and returns (verdict, confidence,
# rationale) or None to defer to the deterministic result.
Judge = Callable[[Finding, Optional[Server], Optional[Tool]], Optional[tuple]]


def _has_marker(text: str) -> bool:
    low = text.lower()
    return any(m in low for m in ADVERSARIAL_MARKERS)


def _mitigated(cap: str, server: Optional[Server], tool: Optional[Tool]) -> tuple[bool, str]:
    """Is the (present) capability adequately governed? Returns (mitigated, why)."""
    if cap == "network":
        if server and server.egress_allowlist:
            return True, f"egress restricted to {', '.join(server.egress_allowlist)}"
        return False, "outbound requests are not restricted by an egress allow-list"
    if cap == "secret":
        if server and (server.secret_manager or server.auth == "oauth"):
            src = "a secret manager" if server.secret_manager else "short-lived OAuth tokens"
            return True, f"credentials sourced from {src}"
        return False, "long-lived static credentials exposed (no vault / OAuth)"
    if cap == "exec":
        if tool and (tool.sandboxed or tool.validates_args):
            how = "sandboxed" if tool.sandboxed else "parameterized/validated"
            return True, f"execution is {how}"
        return False, "unsanitized input can reach the executor"
    if cap == "fs":
        if tool and tool.fs_scope_is_broad:
            return False, f"filesystem scope '{tool.fs_scope}' is over-broad"
        return True, f"filesystem scope '{tool.fs_scope}' is constrained"
    return True, "no capability-specific risk"


_GENUINE_REASON = {
    "network": ReasonCode.MISSING_EGRESS_ALLOWLIST,
    "secret": ReasonCode.STATIC_SECRET,
    "exec": ReasonCode.UNMITIGATED_EXEC,
    "fs": ReasonCode.BROAD_FS_SCOPE,
}


class TriageEngine:
    def __init__(self, inventory: Inventory, judge: Optional[Judge] = None):
        self.inventory = inventory
        self.judge = judge

    def triage_one(self, finding: Finding) -> TriageResult:
        server = self.inventory.server(finding.server)
        tool = server.tool(finding.tool) if server else None
        result = self._deterministic(finding, server, tool)

        # Optional LLM re-adjudication for anything the rules aren't sure about.
        if self.judge is not None and result.confidence < 0.8:
            verdict = self.judge(finding, server, tool)
            if verdict is not None:
                v, conf, rationale = verdict
                result = TriageResult(
                    finding=finding,
                    verdict=v,
                    reason=result.reason,
                    confidence=conf,
                    rationale=rationale,
                    judge=getattr(self.judge, "name", "llm"),
                )
        return result

    def triage(self, findings: list[Finding]) -> "TriageReport":
        return TriageReport([self.triage_one(f) for f in findings])

    # ------------------------------------------------------------------
    def _deterministic(
        self, finding: Finding, server: Optional[Server], tool: Optional[Tool]
    ) -> TriageResult:
        cat = (finding.category or "").upper()

        # Shadow / unapproved server is genuine regardless of the finding text.
        if server is not None and not server.approved and cat.startswith("MCP09"):
            return self._r(finding, Verdict.GENUINE, ReasonCode.SHADOW_SERVER, 0.9,
                           f"server '{server.name}' is not in the approved fleet registry")

        # Injection / tool-poisoning: adversarial content vs. benign prose.
        if cat in INJECTION_CATS:
            if _has_marker(finding.evidence):
                return self._r(finding, Verdict.GENUINE, ReasonCode.ADVERSARIAL_INJECTION, 0.9,
                               "description carries hidden adversarial instructions to the model")
            return self._r(finding, Verdict.DESIGNED_BEHAVIOR, ReasonCode.BENIGN_INSTRUCTION, 0.8,
                           "imperative tool prose, not an injected directive — standard MCP instruction")

        # Supply chain / dependency tampering (server-level).
        if cat.startswith("MCP04"):
            if server and server.unpinned_dependency:
                return self._r(finding, Verdict.GENUINE, ReasonCode.UNPINNED_DEPENDENCY, 0.8,
                               f"runs unpinned package '{server.dependency_spec}' — no version/provenance pin")
            return self._r(finding, Verdict.DESIGNED_BEHAVIOR, ReasonCode.MITIGATED_CAPABILITY, 0.7,
                           "server dependency is version-pinned")

        # Insufficient auth (server-level).
        if cat.startswith("MCP07"):
            if server and server.auth == "none" and server.has_sensitive_tool:
                return self._r(finding, Verdict.GENUINE, ReasonCode.WEAK_AUTH, 0.85,
                               f"server '{server.name}' exposes sensitive tools with no authentication")
            return self._r(finding, Verdict.DESIGNED_BEHAVIOR, ReasonCode.MITIGATED_CAPABILITY, 0.7,
                           "authentication present or no sensitive tools exposed")

        # Capability-style categories: cross-reference real capability + controls.
        cap = CAP_FOR_CATEGORY.get(cat)
        if cap:
            has_cap = server.has_capability(cap, tool) if server else False
            if not has_cap:
                return self._r(finding, Verdict.FALSE_POSITIVE, ReasonCode.NO_SUCH_CAPABILITY, 0.85,
                               f"keyword match only — target has no '{cap}' capability")
            mitigated, why = _mitigated(cap, server, tool)
            if mitigated:
                return self._r(finding, Verdict.DESIGNED_BEHAVIOR, ReasonCode.MITIGATED_CAPABILITY, 0.75,
                               f"designed behavior, controlled: {why}")
            return self._r(finding, Verdict.GENUINE, _GENUINE_REASON[cap], 0.85, why)

        # Unknown category — flag for human review, low confidence.
        return self._r(finding, Verdict.GENUINE, ReasonCode.ADVERSARIAL_INJECTION, 0.4,
                       "no OWASP MCP mapping — needs manual review")

    @staticmethod
    def _r(finding, verdict, reason, confidence, rationale) -> TriageResult:
        return TriageResult(finding, verdict, reason, confidence, rationale)


@dataclass
class TriageReport:
    results: list[TriageResult] = field(default_factory=list)

    @property
    def genuine(self) -> list[TriageResult]:
        return [r for r in self.results if r.verdict == Verdict.GENUINE]

    @property
    def total(self) -> int:
        return len(self.results)

    def funnel(self) -> dict[str, int]:
        counts = Counter(r.bucket for r in self.results)
        return {bucket: counts.get(bucket, 0) for bucket, _ in FUNNEL_LABELS}

    @property
    def noise_reduction(self) -> float:
        """Fraction of raw findings removed as non-actionable."""
        if not self.results:
            return 0.0
        return 1.0 - (len(self.genuine) / len(self.results))
