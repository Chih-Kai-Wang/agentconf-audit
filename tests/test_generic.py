import os
import shutil
import sys

import pytest

from agentconf_audit.loaders import load_document
from agentconf_audit.rules import run_rules

pytestmark = pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX modes only")


@pytest.mark.parametrize("mode,expected", [(0o600, None), (0o640, "LOW"), (0o644, "MEDIUM"), (0o666, "MEDIUM")])
def test_gen002_file_mode(tmp_path, mode, expected):
    target = tmp_path / "settings.json"
    shutil.copy("fixtures/good-claude-settings.json", target)
    os.chmod(target, mode)
    sev = [f.severity for f in run_rules(load_document(target)) if f.rule_id == "GEN002"]
    assert sev == ([expected] if expected else [])


def test_gen002_remediation_quotes_path(tmp_path):
    target = tmp_path / "dir with space" / "settings.json"
    target.parent.mkdir()
    shutil.copy("fixtures/good-claude-settings.json", target)
    os.chmod(target, 0o644)
    f = [f for f in run_rules(load_document(target)) if f.rule_id == "GEN002"][0]
    assert f"'{target}'" in f.remediation
