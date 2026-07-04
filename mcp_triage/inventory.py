"""Load an MCP fleet inventory from a config file.

Accepts the standard ``mcpServers`` shape (as used by Claude Desktop / mcp.json)
and an extended form where each server may declare ``tools`` with their real
capabilities and governance controls. When capabilities aren't declared, we
infer a conservative baseline from the command and tool descriptions so the
tool still does something useful on a plain config.
"""

from __future__ import annotations

import json
from pathlib import Path

from .models import Inventory, Server, Tool

_NETWORK_HINTS = ("fetch", "http", "url", "request", "get_", "download", "browse", "search", "api")
_EXEC_HINTS = ("run", "exec", "shell", "command", "query", "sql", "eval")


def _infer_tool(raw: dict) -> Tool:
    name = raw.get("name", "")
    desc = raw.get("description", "")
    haystack = f"{name} {desc}".lower()

    network = raw.get("network")
    if network is None:
        network = any(h in haystack for h in _NETWORK_HINTS)

    exec_ = raw.get("exec")
    if exec_ is None:
        exec_ = any(h in haystack for h in _EXEC_HINTS)

    fs_scope = raw.get("fs_scope")
    if fs_scope is None and any(h in haystack for h in ("file", "read", "write", "dir", "path")):
        fs_scope = raw.get("path")  # unknown scope stays None unless declared

    return Tool(
        name=name,
        description=desc,
        network=bool(network),
        exec=bool(exec_),
        sandboxed=bool(raw.get("sandboxed", False)),
        validates_args=bool(raw.get("validates_args", False)),
        fs_scope=fs_scope,
    )


def _parse_server(name: str, raw: dict) -> Server:
    return Server(
        name=name,
        command=raw.get("command", ""),
        args=list(raw.get("args", [])),
        transport=raw.get("transport", "stdio"),
        auth=raw.get("auth", "none"),
        approved=bool(raw.get("approved", True)),
        secret_manager=bool(raw.get("secret_manager", False)),
        egress_allowlist=list(raw.get("egress_allowlist", [])),
        env=list(raw.get("env", []) if isinstance(raw.get("env"), list) else raw.get("env", {}).keys()),
        tools=[_infer_tool(t) for t in raw.get("tools", [])],
    )


def parse_inventory(data: dict) -> Inventory:
    servers_raw = data.get("mcpServers") or data.get("servers") or {}
    servers = [_parse_server(name, raw) for name, raw in servers_raw.items()]
    return Inventory(servers=servers)


def load_inventory(path: str | Path) -> Inventory:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return parse_inventory(data)
