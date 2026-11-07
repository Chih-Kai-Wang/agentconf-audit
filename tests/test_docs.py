"""Documentation must not drift from the code it describes."""

import pathlib
import re

from agentconf_audit.cli import rules_markdown
from agentconf_audit.rules import all_rules

ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_rules_md_is_generated_output():
    assert (ROOT / "docs" / "RULES.md").read_text(encoding="utf-8") == rules_markdown(), \
        "run: uv run agentconf-audit rules --markdown > docs/RULES.md"


def test_readme_lists_every_rule_id():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for meta, _ in all_rules():
        assert re.search(rf"\b{meta.id}\b", readme), f"{meta.id} missing from README"
