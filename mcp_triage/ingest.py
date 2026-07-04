"""Normalize raw scanner findings into ``Finding`` objects.

We are scanner-agnostic: every competitor's output becomes our input. This
module accepts our native shape and best-effort maps a couple of common
scanner field names (rule/message/match) so real tools can be piped in.
"""

from __future__ import annotations

import json
from pathlib import Path

from .models import Finding, Severity

# Map free-text scanner rule/message keywords to an OWASP MCP category, so
# findings that arrive without an explicit category still get placed.
_KEYWORD_CATEGORY: list[tuple[tuple[str, ...], str]] = [
    (("ssrf", "egress", "outbound", "over-shar", "oversharing"), "MCP10:2025"),
    (("secret", "token", "api key", "apikey", "credential", "password"), "MCP01:2025"),
    (("command inject", "shell", "rce", "code execution", "exec"), "MCP05:2025"),
    (("path travers", "arbitrary file", "scope creep", "least privilege"), "MCP02:2025"),
    (("tool poison", "hidden instruction", "prompt inject"), "MCP03:2025"),
    (("intent", "flow subvers"), "MCP06:2025"),
    (("auth", "unauthenticated", "authorization"), "MCP07:2025"),
    (("audit", "telemetry", "logging"), "MCP08:2025"),
    (("shadow", "unregistered", "unapproved"), "MCP09:2025"),
    (("supply chain", "dependency", "tamper"), "MCP04:2025"),
]


def _guess_category(text: str) -> str:
    low = text.lower()
    for keywords, cat in _KEYWORD_CATEGORY:
        if any(k in low for k in keywords):
            return cat
    return "UNKNOWN"


def _parse_finding(raw: dict, index: int) -> Finding:
    category = raw.get("category") or _guess_category(
        f"{raw.get('rule', '')} {raw.get('title', '')} {raw.get('message', '')}"
    )
    return Finding(
        id=str(raw.get("id") or f"F-{index:03d}"),
        category=category,
        title=raw.get("title") or raw.get("rule") or raw.get("message") or "finding",
        server=raw.get("server"),
        tool=raw.get("tool"),
        severity=Severity.parse(raw.get("severity")),
        evidence=raw.get("evidence") or raw.get("match") or raw.get("message") or "",
        scanner=raw.get("scanner", "unknown"),
        raw=raw,
    )


def parse_findings(data) -> list[Finding]:
    if isinstance(data, dict):
        data = data.get("findings", [])
    return [_parse_finding(raw, i) for i, raw in enumerate(data)]


def load_findings(path: str | Path) -> list[Finding]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return parse_findings(data)
