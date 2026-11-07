"""Rules that apply to every input regardless of kind."""

from __future__ import annotations

from collections.abc import Iterator

from ..model import KIND_UNKNOWN, Document, Finding, RuleMeta
from . import rule
from ._util import finding


@rule(RuleMeta(
    id="GEN001", severity="INFO",
    title="File could not be parsed or classified",
    applies_to=("*",),
    rationale="An unparseable or unrecognised file is not audited. Silence here would be a false 'clean' result, "
              "so it is reported explicitly.",
    not_caught="Nothing inside the file is evaluated.",
))
def gen001(doc: Document) -> Iterator[Finding]:
    meta = _m("GEN001")
    if doc.parse_error:
        yield finding(meta, doc, "", doc.parse_error[:160], severity="LOW", title="File could not be parsed",
                      remediation="Fix the syntax error (`python -m json.tool FILE` or `python -c \"import tomllib,sys;tomllib.load(open(sys.argv[1],'rb'))\" FILE` shows the position); until then no rule has evaluated this file.")
    elif doc.kind == KIND_UNKNOWN:
        yield finding(meta, doc, "", "unrecognised layout",
                      title="File not recognised as an agent configuration",
                      remediation="Nothing was evaluated. Open an issue with the layout if it should be supported.")


@rule(RuleMeta(
    id="GEN002", severity="MEDIUM",
    title="Configuration file readable by other users",
    applies_to=("*",),
    rationale="Agent configs commonly hold tokens and trust decisions. Group/world-readable mode lets any "
              "local account or process read them.",
    not_caught="ACLs, container boundaries and Windows permissions are not evaluated; on Windows this rule is skipped.",
))
def gen002(doc: Document) -> Iterator[Finding]:
    if doc.mode is None or doc.parse_error:
        return
    if doc.mode & 0o077:
        yield finding(_m("GEN002"), doc, "", f"mode {doc.mode:04o}",
                      severity="MEDIUM" if doc.mode & 0o007 else "LOW",
                      title="Configuration file readable by " + ("all users" if doc.mode & 0o007 else "group"),
                      remediation=f"`chmod 600 '{doc.path}'`")


def _m(rule_id: str) -> RuleMeta:
    from . import _REGISTRY
    return _REGISTRY[rule_id][0]
