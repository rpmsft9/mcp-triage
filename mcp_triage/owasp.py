"""OWASP MCP Top 10 (2025) catalog.

Source (verbatim IDs/titles):
https://github.com/OWASP/www-project-mcp-top-10/blob/main/index.md
https://owasp.org/www-project-mcp-top-10/
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class OwaspCategory:
    id: str
    title: str
    summary: str
    remediation: str


MCP_TOP_10: dict[str, OwaspCategory] = {
    "MCP01:2025": OwaspCategory(
        "MCP01:2025",
        "Token Mismanagement & Secret Exposure",
        "Long-lived static credentials, secrets passed via env vars, or tokens without scope/expiry.",
        "Source secrets from a vault, prefer short-lived OAuth tokens, scope per-operation.",
    ),
    "MCP02:2025": OwaspCategory(
        "MCP02:2025",
        "Privilege Escalation via Scope Creep",
        "Tools granted broader capability (filesystem, network, exec) than their function requires.",
        "Apply least privilege: scope filesystem paths and capabilities to the tool's actual need.",
    ),
    "MCP03:2025": OwaspCategory(
        "MCP03:2025",
        "Tool Poisoning",
        "Hidden or adversarial instructions embedded in tool descriptions/metadata.",
        "Pin and review tool descriptions; reject tools carrying imperative-to-the-model directives.",
    ),
    "MCP04:2025": OwaspCategory(
        "MCP04:2025",
        "Software Supply Chain Attacks & Dependency Tampering",
        "Compromised or tampered MCP server packages and their dependencies.",
        "Pin versions, verify signatures/provenance, and scan dependencies.",
    ),
    "MCP05:2025": OwaspCategory(
        "MCP05:2025",
        "Command Injection & Execution",
        "Unvalidated input reaching a shell or query executor.",
        "Parameterize queries, validate/allow-list arguments, sandbox execution.",
    ),
    "MCP06:2025": OwaspCategory(
        "MCP06:2025",
        "Intent Flow Subversion",
        "Manipulation of the agent's intended plan/flow through crafted tool output or instructions.",
        "Isolate tool output from instructions; verify intent before privileged actions.",
    ),
    "MCP07:2025": OwaspCategory(
        "MCP07:2025",
        "Insufficient Authentication & Authorization",
        "Servers exposing sensitive tools with weak or absent authentication.",
        "Require authentication; enforce per-tool authorization for sensitive operations.",
    ),
    "MCP08:2025": OwaspCategory(
        "MCP08:2025",
        "Lack of Audit and Telemetry",
        "No logging of tool invocations, making abuse undetectable.",
        "Log tool calls with actor, args, and outcome; ship to central telemetry.",
    ),
    "MCP09:2025": OwaspCategory(
        "MCP09:2025",
        "Shadow MCP Servers",
        "Unapproved/unregistered MCP servers running outside governance.",
        "Maintain an approved-server registry; block or quarantine unregistered servers.",
    ),
    "MCP10:2025": OwaspCategory(
        "MCP10:2025",
        "Context Injection & Over-Sharing",
        "Uncontrolled egress / over-broad data sharing (e.g. SSRF, unrestricted outbound requests).",
        "Enforce egress allow-lists; restrict and validate outbound destinations.",
    ),
}


def category(cid: str) -> OwaspCategory:
    """Look up a category, tolerating bare ids like 'MCP10' or 'mcp10:2025'."""
    if not cid:
        return _UNKNOWN
    key = cid.strip().upper()
    if key in MCP_TOP_10:
        return MCP_TOP_10[key]
    # tolerate "MCP10" without the ":2025" suffix
    for full, cat in MCP_TOP_10.items():
        if full.split(":")[0] == key.split(":")[0]:
            return cat
    return _UNKNOWN


def title(cid: str) -> str:
    return category(cid).title


_UNKNOWN = OwaspCategory("UNKNOWN", "Uncategorized", "No OWASP MCP mapping.", "Review manually.")
