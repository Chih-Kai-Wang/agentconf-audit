import json
import pathlib
import shutil

from agentconf_audit.cli import main

ROOT = pathlib.Path(__file__).resolve().parent.parent
BAD = "fixtures/bad-claude-settings.json"
GOOD = "fixtures/good-claude-settings.json"


def run(args, capsys):
    rc = main(args)
    out = capsys.readouterr()
    return rc, out.out, out.err


def test_exit_1_when_high_present(capsys):
    rc, out, _ = run(["scan", BAD, "--disable", "GEN002"], capsys)
    assert rc == 1
    assert "CC001" in out


def test_exit_0_on_clean_file(capsys):
    rc, out, _ = run(["scan", GOOD, "--disable", "GEN002"], capsys)
    assert rc == 0
    assert "HIGH 0" in out


def test_threshold_and_never(capsys):
    assert run(["scan", "fixtures/broken.json", "--disable", "GEN002"], capsys)[0] == 0  # LOW only
    assert run(["scan", "fixtures/broken.json", "--disable", "GEN002", "--fail-on", "low"], capsys)[0] == 1
    assert run(["scan", BAD, "--fail-on", "never"], capsys)[0] == 0


def test_missing_input_is_usage_error(capsys):
    rc, _, err = run(["scan", "fixtures/does-not-exist.json"], capsys)
    assert rc == 2 and "not a file" in err
    rc, _, err = run(["scan"], capsys)
    assert rc == 2 and "no input" in err


def test_directory_expansion_and_dedupe(tmp_path, capsys):
    proj = tmp_path / "proj"
    (proj / ".claude").mkdir(parents=True)
    shutil.copy(ROOT / "fixtures" / "bad-mcp.json", proj / ".mcp.json")
    shutil.copy(ROOT / GOOD, proj / ".claude" / "settings.json")
    (proj / "node_modules" / "x").mkdir(parents=True)
    shutil.copy(ROOT / "fixtures" / "bad-mcp.json", proj / "node_modules" / "x" / ".mcp.json")  # must be skipped
    rc, out, _ = run(["scan", str(proj), str(proj / ".mcp.json"), "--format", "json", "--fail-on", "never",
                      "--disable", "GEN002"], capsys)
    d = json.loads(out)
    assert sorted(i["path"].rsplit("/", 1)[-1] for i in d["inputs"]) == [".mcp.json", "settings.json"]
    assert d["summary"]["HIGH"] >= 4


def test_json_report_verifies_and_detects_tampering(tmp_path, capsys):
    report = tmp_path / "r.json"
    rc, _, _ = run(["scan", BAD, "--format", "json", "-o", str(report), "--fail-on", "never"], capsys)
    assert rc == 0 and report.exists()
    assert run(["verify", str(report)], capsys)[0] == 0
    d = json.loads(report.read_text())
    d["findings"] = d["findings"][1:]  # drop a finding, keep the old hash
    report.write_text(json.dumps(d))
    rc, out, _ = run(["verify", str(report)], capsys)
    assert rc == 3 and "FAIL" in out


def test_markdown_output_groups_by_severity(capsys):
    rc, out, _ = run(["scan", BAD, "--format", "md", "--no-timestamp", "--fail-on", "never", "--disable", "GEN002"], capsys)
    assert out.index("## HIGH") < out.index("## MEDIUM") < out.index("## LOW")
    assert "report_sha256" in out


def test_secret_values_never_appear_in_output(capsys):
    _, out, _ = run(["scan", BAD, "fixtures/bad-mcp.json", "fixtures/bad-codex.toml", "--format", "json",
                     "--fail-on", "never"], capsys)
    for literal in ("FAKEFAKEFAKEFAKE", "hunter2hunter2", "abc123def456", "FAKEsignature"):
        assert literal not in out


def test_rules_listing_contains_every_rule(capsys):
    from agentconf_audit.rules import all_rules
    _, out, _ = run(["rules"], capsys)
    for meta, _ in all_rules():
        assert meta.id in out
        assert meta.not_caught  # every rule states a blind spot
