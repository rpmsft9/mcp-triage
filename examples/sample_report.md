# MCP Triage & Governance Report

_Fleet: 7 servers, 17 tools._

## Triage funnel

**27 raw findings → 6 genuine concerns** (78% noise removed)

| Bucket | Count |
| --- | ---: |
| Standard MCP instructions | 8 |
| Designed features (mitigated) | 10 |
| False positives | 3 |
| Genuine concerns | 6 |

## Genuine concerns (ranked)

### [CRITICAL] Command injection: unsanitized shell input
- **OWASP:** MCP05:2025 — Command Injection & Execution
- **Where:** shell / run_command
- **Why it's real:** unsanitized input can reach the executor
- **Fix:** Parameterize queries, validate/allow-list arguments, sandbox execution.

### [CRITICAL] Tool poisoning: hidden adversarial instructions
- **OWASP:** MCP03:2025 — Tool Poisoning
- **Where:** notes-sync / sync_notes
- **Why it's real:** description carries hidden adversarial instructions to the model
- **Fix:** Pin and review tool descriptions; reject tools carrying imperative-to-the-model directives.

### [HIGH] SSRF: unrestricted outbound fetch
- **OWASP:** MCP10:2025 — Context Injection & Over-Sharing
- **Where:** web-fetch / fetch_url
- **Why it's real:** outbound requests are not restricted by an egress allow-list
- **Fix:** Enforce egress allow-lists; restrict and validate outbound destinations.

### [HIGH] Static database credential in environment
- **OWASP:** MCP01:2025 — Token Mismanagement & Secret Exposure
- **Where:** postgres
- **Why it's real:** long-lived static credentials exposed (no vault / OAuth)
- **Fix:** Source secrets from a vault, prefer short-lived OAuth tokens, scope per-operation.

### [HIGH] Over-broad filesystem scope
- **OWASP:** MCP02:2025 — Privilege Escalation via Scope Creep
- **Where:** filesystem / write_file
- **Why it's real:** filesystem scope '/' is over-broad
- **Fix:** Apply least privilege: scope filesystem paths and capabilities to the tool's actual need.

### [HIGH] Sensitive tools exposed without authentication
- **OWASP:** MCP07:2025 — Insufficient Authentication & Authorization
- **Where:** filesystem
- **Why it's real:** server 'filesystem' exposes sensitive tools with no authentication
- **Fix:** Require authentication; enforce per-tool authorization for sensitive operations.

## Fleet governance

| Server | Risk | Grade | Genuine | Recommendations |
| --- | ---: | :---: | ---: | ---: |
| filesystem | 100 | F | 2 | 4 |
| notes-sync | 100 | F | 1 | 3 |
| shell | 87 | F | 1 | 3 |
| web-fetch | 63 | D | 1 | 3 |
| postgres | 48 | C | 1 | 2 |
| github | 0 | A | 0 | 1 |
| utils | 0 | A | 0 | 1 |

### Least-privilege & policy recommendations

**filesystem**
- `MCP07:2025` **Require authentication** — 'filesystem' exposes sensitive tools with auth=none; require OAuth.
- `MCP04:2025` **Pin server dependency** — 'filesystem' runs unpinned package '@acme/mcp-filesystem'; pin to a fixed version and verify provenance.
- `MCP02:2025` **Tighten filesystem scope** — tool 'write_file' can access '/'; scope to its working directory.
- `MCP02:2025` **Tighten filesystem scope** — tool 'delete_file' can access '/'; scope to its working directory.

**notes-sync**
- `MCP09:2025` **Quarantine shadow server** — 'notes-sync' is unregistered; add to the approved registry or block it.
- `MCP07:2025` **Require authentication** — 'notes-sync' exposes sensitive tools with auth=none; require OAuth.
- `MCP10:2025` **Enforce egress allow-list** — 'notes-sync' makes outbound requests with no allow-list; restrict egress (suggested: <explicit hosts only>).

**shell**
- `MCP07:2025` **Require authentication** — 'shell' exposes sensitive tools with auth=none; require OAuth.
- `MCP04:2025` **Pin server dependency** — 'shell' runs unpinned package '@acme/mcp-shell'; pin to a fixed version and verify provenance.
- `MCP05:2025` **Sandbox / validate execution** — tool 'run_command' executes with unvalidated input; parameterize and sandbox.

**web-fetch**
- `MCP07:2025` **Require authentication** — 'web-fetch' exposes sensitive tools with auth=none; require OAuth.
- `MCP04:2025` **Pin server dependency** — 'web-fetch' runs unpinned package '@acme/mcp-web-fetch'; pin to a fixed version and verify provenance.
- `MCP10:2025` **Enforce egress allow-list** — 'web-fetch' makes outbound requests with no allow-list; restrict egress (suggested: <explicit hosts only>).

**postgres**
- `MCP01:2025` **Move secrets to a vault** — Secrets ['DB_URL'] are static; source from a secret manager and rotate.
- `MCP04:2025` **Pin server dependency** — 'postgres' runs unpinned package '@acme/mcp-postgres'; pin to a fixed version and verify provenance.

**github**
- `MCP04:2025` **Pin server dependency** — 'github' runs unpinned package '@modelcontextprotocol/server-github'; pin to a fixed version and verify provenance.

**utils**
- `MCP04:2025` **Pin server dependency** — 'utils' runs unpinned package '@acme/mcp-utils'; pin to a fixed version and verify provenance.

### Proposed egress allow-lists

```json
{
  "web-fetch": ["<deny-all: set explicit hosts>"],
  "github": ["api.github.com"],
  "notes-sync": ["<deny-all: set explicit hosts>"]
}
```
