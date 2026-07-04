"""Core data model for mcp-triage.

The design principle: a *scanner* sees only the text of a tool description. Our
triage engine additionally sees the **inventory** — the real capabilities and
governance controls of each tool/server — and cross-references the two. That
cross-reference is what turns a keyword match into a verdict.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> int:
        return {
            Severity.INFO: 1,
            Severity.LOW: 2,
            Severity.MEDIUM: 4,
            Severity.HIGH: 8,
            Severity.CRITICAL: 12,
        }[self]

    @classmethod
    def parse(cls, value: str | None) -> "Severity":
        if not value:
            return cls.MEDIUM
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            return cls.MEDIUM


class Verdict(str, Enum):
    """The triage decision for a single finding."""

    GENUINE = "genuine"
    DESIGNED_BEHAVIOR = "designed_behavior"
    FALSE_POSITIVE = "false_positive"


class ReasonCode(str, Enum):
    """Why the engine reached its verdict — drives the funnel breakdown."""

    # genuine
    ADVERSARIAL_INJECTION = "adversarial_injection"
    UNMITIGATED_EXEC = "unmitigated_exec"
    MISSING_EGRESS_ALLOWLIST = "missing_egress_allowlist"
    STATIC_SECRET = "static_secret"
    BROAD_FS_SCOPE = "broad_fs_scope"
    WEAK_AUTH = "weak_auth"
    SHADOW_SERVER = "shadow_server"
    UNPINNED_DEPENDENCY = "unpinned_dependency"
    # designed behavior
    BENIGN_INSTRUCTION = "benign_instruction"
    MITIGATED_CAPABILITY = "mitigated_capability"
    # false positive
    NO_SUCH_CAPABILITY = "no_such_capability"

    @property
    def funnel_bucket(self) -> str:
        return _FUNNEL_BUCKET[self]


_FUNNEL_BUCKET: dict[ReasonCode, str] = {
    ReasonCode.ADVERSARIAL_INJECTION: "genuine",
    ReasonCode.UNMITIGATED_EXEC: "genuine",
    ReasonCode.MISSING_EGRESS_ALLOWLIST: "genuine",
    ReasonCode.STATIC_SECRET: "genuine",
    ReasonCode.BROAD_FS_SCOPE: "genuine",
    ReasonCode.WEAK_AUTH: "genuine",
    ReasonCode.SHADOW_SERVER: "genuine",
    ReasonCode.UNPINNED_DEPENDENCY: "genuine",
    ReasonCode.BENIGN_INSTRUCTION: "standard_instruction",
    ReasonCode.MITIGATED_CAPABILITY: "designed_feature",
    ReasonCode.NO_SUCH_CAPABILITY: "false_positive",
}

# Human-readable funnel bucket labels, in display order.
FUNNEL_LABELS: list[tuple[str, str]] = [
    ("standard_instruction", "Standard MCP instructions"),
    ("designed_feature", "Designed features (mitigated)"),
    ("false_positive", "False positives"),
    ("genuine", "Genuine concerns"),
]

BROAD_FS_SCOPES = {"/", "~", "*", "$home", "%userprofile%", "c:\\", "c:/", ".*"}


@dataclass
class Tool:
    """A single MCP tool and its *real* capabilities/controls."""

    name: str
    description: str = ""
    network: bool = False           # makes outbound network requests
    exec: bool = False              # executes commands / queries
    sandboxed: bool = False         # exec runs in a sandbox
    validates_args: bool = False    # exec args are parameterized/validated
    fs_scope: Optional[str] = None  # filesystem path the tool can touch

    @property
    def has_fs(self) -> bool:
        return self.fs_scope is not None

    @property
    def fs_scope_is_broad(self) -> bool:
        if not self.fs_scope:
            return False
        return self.fs_scope.strip().lower() in BROAD_FS_SCOPES

    @property
    def is_sensitive(self) -> bool:
        """Write/exec/network capability that warrants authentication."""
        name = self.name.lower()
        destructive = any(k in name for k in ("write", "delete", "remove", "update", "create", "put"))
        return self.exec or self.network or destructive or self.fs_scope_is_broad

    def has_capability(self, cap: str) -> bool:
        return {
            "network": self.network,
            "exec": self.exec,
            "fs": self.has_fs,
            "secret": False,  # secrets are a server-level concern
        }.get(cap, False)


@dataclass
class Server:
    """An MCP server, its tools, and its fleet-level governance controls."""

    name: str
    command: str = ""
    args: list[str] = field(default_factory=list)
    transport: str = "stdio"
    auth: str = "none"                       # none | apikey | token | oauth
    approved: bool = True                    # registered in the approved fleet
    secret_manager: bool = False             # secrets sourced from a vault
    egress_allowlist: list[str] = field(default_factory=list)
    env: list[str] = field(default_factory=list)  # env var names (secret surface)
    tools: list[Tool] = field(default_factory=list)

    def tool(self, name: str | None) -> Optional[Tool]:
        if name is None:
            return None
        for t in self.tools:
            if t.name == name:
                return t
        return None

    @property
    def handles_secrets(self) -> bool:
        return bool(self.env) or self.auth in ("apikey", "token", "oauth")

    @property
    def dependency_spec(self) -> Optional[str]:
        """The package spec this server launches (first non-flag arg)."""
        for a in self.args:
            if a.startswith("-"):
                continue
            return a
        return self.command or None

    @property
    def unpinned_dependency(self) -> bool:
        """True if the server runs a floating/unpinned registry package (MCP04)."""
        spec = self.dependency_spec
        if not spec:
            return False
        low = spec.lower()
        # local scripts/paths are not registry dependencies
        if low.startswith((".", "/", "~")) or low.endswith((".js", ".py", ".mjs")):
            return False
        if "latest" in low or low.endswith("*"):
            return True
        core = spec[1:] if spec.startswith("@") else spec  # drop leading scope '@'
        return "@" not in core  # no '@version' pin

    @property
    def has_sensitive_tool(self) -> bool:
        return any(t.is_sensitive for t in self.tools)

    def has_capability(self, cap: str, tool: Optional[Tool]) -> bool:
        if cap == "secret":
            return self.handles_secrets
        if tool is not None:
            return tool.has_capability(cap)
        # server-level finding: true if any tool has the capability
        return any(t.has_capability(cap) for t in self.tools)


@dataclass
class Inventory:
    servers: list[Server] = field(default_factory=list)

    def server(self, name: str | None) -> Optional[Server]:
        if name is None:
            return None
        for s in self.servers:
            if s.name == name:
                return s
        return None

    @property
    def tool_count(self) -> int:
        return sum(len(s.tools) for s in self.servers)


@dataclass
class Finding:
    """A single raw finding emitted by an upstream scanner."""

    id: str
    category: str                      # OWASP MCP id, e.g. "MCP10:2025"
    title: str
    server: Optional[str] = None
    tool: Optional[str] = None
    severity: Severity = Severity.MEDIUM
    evidence: str = ""                 # the text the scanner matched on
    scanner: str = "unknown"
    raw: dict = field(default_factory=dict)


@dataclass
class TriageResult:
    finding: Finding
    verdict: Verdict
    reason: ReasonCode
    confidence: float
    rationale: str
    judge: str = "deterministic"       # deterministic | anthropic:<model>

    @property
    def bucket(self) -> str:
        return self.reason.funnel_bucket

    def to_dict(self) -> dict:
        return {
            "id": self.finding.id,
            "category": self.finding.category,
            "title": self.finding.title,
            "server": self.finding.server,
            "tool": self.finding.tool,
            "severity": self.finding.severity.value,
            "verdict": self.verdict.value,
            "reason": self.reason.value,
            "bucket": self.bucket,
            "confidence": round(self.confidence, 2),
            "rationale": self.rationale,
            "judge": self.judge,
        }
