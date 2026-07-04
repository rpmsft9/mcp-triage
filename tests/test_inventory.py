from mcp_triage.models import Inventory


def test_fleet_loads(inventory: Inventory):
    assert len(inventory.servers) == 7
    assert inventory.tool_count == 17


def test_server_lookup_and_controls(inventory: Inventory):
    gh = inventory.server("github")
    assert gh is not None
    assert gh.auth == "oauth"
    assert gh.secret_manager is True
    assert gh.egress_allowlist == ["api.github.com"]
    assert gh.approved is True


def test_shadow_server_flagged(inventory: Inventory):
    notes = inventory.server("notes-sync")
    assert notes.approved is False


def test_tool_capabilities(inventory: Inventory):
    fs = inventory.server("filesystem")
    write = fs.tool("write_file")
    read = fs.tool("read_file")
    assert write.fs_scope_is_broad is True
    assert read.fs_scope_is_broad is False
    assert fs.has_sensitive_tool is True


def test_secret_surface(inventory: Inventory):
    pg = inventory.server("postgres")
    assert pg.env == ["DB_URL"]
    assert pg.handles_secrets is True
    utils = inventory.server("utils")
    assert utils.handles_secrets is False
