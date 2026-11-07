"""Report serialisation. The JSON report carries `report_sha256`, a hash over the canonical
form of {inputs, findings}. `agentconf-audit verify report.json` recomputes it, so a report
quoted in a README or PR can be checked against the file that was actually produced."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from . import __version__
from .model import SEVERITIES, Report

HASH_FIELDS = ("inputs", "findings")


def canonical_body(inputs: list[dict[str, Any]], findings: list[dict[str, Any]]) -> bytes:
    body = {"inputs": inputs, "findings": findings}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def report_hash(inputs: list[dict[str, Any]], findings: list[dict[str, Any]]) -> str:
    return hashlib.sha256(canonical_body(inputs, findings)).hexdigest()


def to_json_dict(report: Report, *, timestamp: bool = True) -> dict[str, Any]:
    findings = [f.to_dict() for f in sorted(report.findings, key=lambda f: f.sort_key())]
    inputs = sorted(report.inputs, key=lambda i: i["path"])
    out: dict[str, Any] = {
        "tool": "agentconf-audit",
        "version": __version__,
        "inputs": inputs,
        "findings": findings,
        "summary": report.summary(),
        "report_sha256": report_hash(inputs, findings),
        "hash_covers": list(HASH_FIELDS),
    }
    if timestamp:
        out["generated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return out


def render_json(report: Report, *, timestamp: bool = True) -> str:
    return json.dumps(to_json_dict(report, timestamp=timestamp), indent=2, ensure_ascii=False) + "\n"


def verify_report_dict(d: dict[str, Any]) -> tuple[bool, str, str]:
    """Return (ok, expected, actual)."""
    expected = str(d.get("report_sha256", ""))
    actual = report_hash(d.get("inputs", []), d.get("findings", []))
    return expected == actual, expected, actual


def render_markdown(report: Report, *, timestamp: bool = True) -> str:
    d = to_json_dict(report, timestamp=timestamp)
    s = d["summary"]
    lines = ["# agentconf-audit report", ""]
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev in SEVERITIES:
        lines.append(f"| {sev} | {s[sev]} |")
    lines.append("")
    lines.append("## Inputs")
    lines.append("")
    lines.append("| File | Kind | SHA-256 |")
    lines.append("|---|---|---|")
    for i in d["inputs"]:
        lines.append(f"| `{i['path']}` | {i['kind']} | `{i['sha256'][:16]}…` |")
    lines.append("")
    if not d["findings"]:
        lines.append("No findings.")
    for sev in SEVERITIES:
        group = [f for f in d["findings"] if f["severity"] == sev]
        if not group:
            continue
        lines.append(f"## {sev} ({len(group)})")
        lines.append("")
        for f in group:
            loc = f["location"] or "/"
            lines.append(f"- **{f['rule_id']}** {f['title']}  ")
            lines.append(f"  `{f['file']}` at `{loc}`  ")
            lines.append(f"  evidence: `{_md_code(f['evidence'])}`  ")
            lines.append(f"  why: {f['rationale']}  ")
            lines.append(f"  fix: {f['remediation']}")
        lines.append("")
    lines.append(f"`report_sha256: {d['report_sha256']}` (covers {', '.join(d['hash_covers'])}; "
                 f"verify with `agentconf-audit verify report.json`)")
    return "\n".join(lines) + "\n"


def render_text(report: Report) -> str:
    d = to_json_dict(report, timestamp=False)
    out: list[str] = []
    for f in d["findings"]:
        loc = f["location"] or "/"
        out.append(f"[{f['severity']:6}] {f['rule_id']}  {f['title']}")
        out.append(f"         {f['file']}  {loc}")
        out.append(f"         evidence: {f['evidence']}")
        out.append(f"         fix: {f['remediation']}")
    s = d["summary"]
    out.append("")
    out.append(f"{len(d['inputs'])} file(s) scanned · " + " · ".join(f"{k} {v}" for k, v in s.items()))
    out.append(f"report_sha256 {d['report_sha256']}")
    return "\n".join(out) + "\n"


def _md_code(s: str) -> str:
    return s.replace("`", "'")
