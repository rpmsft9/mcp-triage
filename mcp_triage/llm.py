"""Optional Anthropic-backed triage judge.

This is the "LLM-assisted false-positive reducer" from the pitch. It is
strictly optional: the engine is fully functional and deterministic without it.
When enabled (``--llm`` + ANTHROPIC_API_KEY), it re-adjudicates the findings the
deterministic rules flagged as low-confidence, reasoning about whether a flag is
exploitable or designed behavior.

Kept dependency-free at import time so the package installs and tests run
without the ``anthropic`` SDK.
"""

from __future__ import annotations

import json
import os
from typing import Optional

from .models import Finding, Server, Tool, Verdict
from .owasp import category as owasp_category

MODEL = "claude-opus-4-8"

_SYSTEM = """You are an MCP security triage analyst. You reduce false positives \
from pattern-based scanners. Given a scanner finding plus the target tool's real \
capabilities and the server's governance controls, decide whether the finding is:
- "genuine": a real, exploitable weakness that needs action;
- "designed_behavior": the flagged behavior is the tool's intended function and \
is adequately controlled;
- "false_positive": a keyword/vocabulary match with no security substance.
Respond ONLY with compact JSON: {"verdict": "...", "confidence": 0.0-1.0, "rationale": "one sentence"}."""


def _finding_context(finding: Finding, server: Optional[Server], tool: Optional[Tool]) -> str:
    cat = owasp_category(finding.category)
    ctx = {
        "finding": {
            "owasp": f"{cat.id} {cat.title}",
            "title": finding.title,
            "severity": finding.severity.value,
            "evidence": finding.evidence,
        },
        "server": None,
        "tool": None,
    }
    if server:
        ctx["server"] = {
            "name": server.name,
            "auth": server.auth,
            "approved": server.approved,
            "secret_manager": server.secret_manager,
            "egress_allowlist": server.egress_allowlist,
            "env_secrets": server.env,
        }
    if tool:
        ctx["tool"] = {
            "name": tool.name,
            "description": tool.description,
            "network": tool.network,
            "exec": tool.exec,
            "sandboxed": tool.sandboxed,
            "validates_args": tool.validates_args,
            "fs_scope": tool.fs_scope,
        }
    return json.dumps(ctx, indent=2)


class AnthropicJudge:
    """Callable judge: (finding, server, tool) -> (Verdict, confidence, rationale) | None."""

    name = f"anthropic:{MODEL}"

    def __init__(self, model: str = MODEL, api_key: Optional[str] = None):
        self.model = model
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self._client = None

    def _ensure_client(self):
        if self._client is not None:
            return
        if not self._api_key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY is not set. Run without --llm for deterministic triage, "
                "or export a key. Install the SDK with: pip install 'mcp-triage[llm]'."
            )
        try:
            import anthropic  # noqa: local import — optional dependency
        except ImportError as exc:  # pragma: no cover - env-dependent
            raise RuntimeError(
                "The 'anthropic' package is not installed. Install with: pip install 'mcp-triage[llm]'."
            ) from exc
        self._client = anthropic.Anthropic(api_key=self._api_key)

    def __call__(self, finding: Finding, server: Optional[Server], tool: Optional[Tool]):
        self._ensure_client()
        msg = self._client.messages.create(
            model=self.model,
            max_tokens=256,
            system=_SYSTEM,
            messages=[{"role": "user", "content": _finding_context(finding, server, tool)}],
        )
        text = "".join(getattr(b, "text", "") for b in msg.content).strip()
        return self._parse(text)

    @staticmethod
    def _parse(text: str):
        try:
            start, end = text.index("{"), text.rindex("}") + 1
            data = json.loads(text[start:end])
            verdict = Verdict(data["verdict"])
            return verdict, float(data.get("confidence", 0.7)), str(data.get("rationale", "")).strip()
        except (ValueError, KeyError):  # pragma: no cover - model-dependent
            return None
