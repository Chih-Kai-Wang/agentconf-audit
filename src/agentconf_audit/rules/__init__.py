"""Rule registry. Each rule is a function decorated with @rule(RuleMeta(...)) that takes a
Document and yields Findings. Importing the submodules registers them."""

from __future__ import annotations

from collections.abc import Callable, Iterator

from ..model import Document, Finding, RuleMeta

RuleFn = Callable[[Document], Iterator[Finding]]

_REGISTRY: dict[str, tuple[RuleMeta, RuleFn]] = {}


def rule(meta: RuleMeta) -> Callable[[RuleFn], RuleFn]:
    def deco(fn: RuleFn) -> RuleFn:
        if meta.id in _REGISTRY:
            raise ValueError(f"duplicate rule id {meta.id}")
        _REGISTRY[meta.id] = (meta, fn)
        return fn
    return deco


def all_rules() -> list[tuple[RuleMeta, RuleFn]]:
    _ensure_loaded()
    return [_REGISTRY[k] for k in sorted(_REGISTRY)]


def run_rules(doc: Document) -> list[Finding]:
    findings: list[Finding] = []
    for meta, fn in all_rules():
        if doc.kind in meta.applies_to or "*" in meta.applies_to:
            for f in fn(doc):
                findings.append(f)
    findings.sort(key=lambda f: f.sort_key())
    return findings


def _ensure_loaded() -> None:
    if _REGISTRY:
        return
    from . import claude_code, codex, generic, mcp  # noqa: F401  (registration side effect)
