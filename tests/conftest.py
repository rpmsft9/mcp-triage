import json
from pathlib import Path

import pytest

from mcp_triage.ingest import load_findings, parse_findings
from mcp_triage.inventory import load_inventory

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
CONFIG = EXAMPLES / "sample_mcp_config.json"
FINDINGS = EXAMPLES / "sample_findings.json"


@pytest.fixture
def inventory():
    return load_inventory(CONFIG)


@pytest.fixture
def findings():
    return load_findings(FINDINGS)


@pytest.fixture
def raw_findings():
    return json.loads(FINDINGS.read_text(encoding="utf-8"))["findings"]
