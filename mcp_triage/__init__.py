"""mcp-triage — triage-and-governance layer for MCP fleets.

Not scanner #11. This sits on top of any scanner: it reasons about whether a
flagged tool is actually exploitable versus designed behavior (an LLM-assisted
false-positive reducer), and it inventories MCP servers/tools/permissions,
scores them, and recommends least-privilege scopes + egress allow-lists mapped
to the OWASP MCP Top 10.
"""

from .models import (
    Finding,
    Inventory,
    ReasonCode,
    Server,
    Severity,
    Tool,
    TriageResult,
    Verdict,
)
from .triage import TriageEngine, TriageReport

__version__ = "0.1.0"

__all__ = [
    "Finding",
    "Inventory",
    "ReasonCode",
    "Server",
    "Severity",
    "Tool",
    "TriageResult",
    "Verdict",
    "TriageEngine",
    "TriageReport",
    "__version__",
]
