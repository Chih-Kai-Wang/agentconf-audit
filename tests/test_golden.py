"""Every fixture has a frozen expected report. Set UPDATE_GOLDENS=1 to regenerate after an
intentional rule change; the diff in git is then the review artefact."""

import json
import os
import pathlib

import pytest

from agentconf_audit.cli import main

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = sorted(p for p in (ROOT / "fixtures").iterdir() if p.suffix in (".json", ".toml"))


@pytest.mark.parametrize("fixture", FIXTURES, ids=[p.name for p in FIXTURES])
def test_fixture_matches_golden(fixture: pathlib.Path, capsys):
    rel = fixture.relative_to(ROOT).as_posix()
    rc = main(["scan", rel, "--format", "json", "--no-timestamp", "--disable", "GEN002", "--fail-on", "never"])
    assert rc == 0
    actual = json.loads(capsys.readouterr().out)
    golden = ROOT / "fixtures" / "expected" / (fixture.stem + ".json")
    if os.environ.get("UPDATE_GOLDENS"):
        golden.write_text(json.dumps(actual, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    expected = json.loads(golden.read_text(encoding="utf-8"))
    assert actual == expected


def test_good_fixtures_have_nothing_above_info():
    for fixture in FIXTURES:
        if not fixture.stem.startswith("good-"):
            continue
        golden = json.loads((ROOT / "fixtures" / "expected" / (fixture.stem + ".json")).read_text())
        assert all(f["severity"] == "INFO" for f in golden["findings"]), fixture.name


def test_every_rule_fires_on_some_fixture():
    from agentconf_audit.rules import all_rules
    fired = set()
    for golden in (ROOT / "fixtures" / "expected").glob("*.json"):
        fired |= {f["rule_id"] for f in json.loads(golden.read_text())["findings"]}
    expected = {meta.id for meta, _ in all_rules()} - {"GEN002"}  # GEN002 is covered by test_generic.py
    assert expected <= fired, f"rules with no fixture coverage: {sorted(expected - fired)}"


def test_golden_hashes_verify():
    from agentconf_audit.report import verify_report_dict
    for golden in (ROOT / "fixtures" / "expected").glob("*.json"):
        ok, expected, actual = verify_report_dict(json.loads(golden.read_text()))
        assert ok, f"{golden.name}: {expected} != {actual}"
