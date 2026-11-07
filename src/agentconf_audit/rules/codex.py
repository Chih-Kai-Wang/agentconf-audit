"""Rules for OpenAI Codex CLI/desktop config.toml."""

from __future__ import annotations

from collections.abc import Iterator

from ..model import KIND_CODEX, Document, Finding, RuleMeta
from . import rule
from ._util import finding, is_root_like, ptr, safe_url, url_is_plaintext_remote

TRUSTED_PROJECT_SOFT_LIMIT = 50


@rule(RuleMeta(
    id="CX001", severity="HIGH",
    title="Codex never asks for approval",
    applies_to=(KIND_CODEX,),
    rationale="`approval_policy = \"never\"` lets every command run without a human decision. Combined with "
              "`danger-full-access` (CX002) it is unattended arbitrary code execution.",
    not_caught="Per-profile overrides under [profiles.*] are checked; a `--ask-for-approval` CLI flag at run time is not visible here.",
))
def cx001(doc: Document) -> Iterator[Finding]:
    meta = _m("CX001")
    for base, section in _sections(doc):
        val = section.get("approval_policy")
        if val == "never":
            yield finding(meta, doc, f"{base}/approval_policy", str(val),
                          remediation="Use `on-request` or `on-failure`; reserve `never` for a disposable sandbox.")


@rule(RuleMeta(
    id="CX002", severity="HIGH",
    title="Codex sandbox disabled (danger-full-access)",
    applies_to=(KIND_CODEX,),
    rationale="`sandbox_mode = \"danger-full-access\"` removes the filesystem and network sandbox; the agent can "
              "read any file and reach any host as the user.",
    not_caught="`workspace-write` with `network_access = true` is a weaker form reported as LOW; its writable roots are not enumerated.",
))
def cx002(doc: Document) -> Iterator[Finding]:
    meta = _m("CX002")
    for base, section in _sections(doc):
        val = section.get("sandbox_mode")
        if val == "danger-full-access":
            yield finding(meta, doc, f"{base}/sandbox_mode", str(val),
                          remediation="Use `workspace-write`; grant full access per task, not globally.")
    sww = doc.data.get("sandbox_workspace_write") if isinstance(doc.data, dict) else None
    if isinstance(sww, dict) and sww.get("network_access") is True:
        yield finding(meta, doc, "/sandbox_workspace_write/network_access", "true", severity="LOW",
                      title="Codex workspace-write sandbox allows network access",
                      remediation="Disable unless the task needs egress; network lets exfiltrated data leave.")


@rule(RuleMeta(
    id="CX003", severity="HIGH",
    title="Model provider reached over plaintext HTTP",
    applies_to=(KIND_CODEX,),
    rationale="Prompts, code and credentials to `base_url`/`openai_base_url` travel unencrypted to a non-loopback host.",
    not_caught="Loopback proxies are INFO only; what they forward to, and over what, is unknown.",
))
def cx003(doc: Document) -> Iterator[Finding]:
    meta = _m("CX003")
    d = doc.data if isinstance(doc.data, dict) else {}
    targets: list[tuple[str, str]] = []
    if isinstance(d.get("openai_base_url"), str):
        targets.append(("/openai_base_url", d["openai_base_url"]))
    providers = d.get("model_providers")
    if isinstance(providers, dict):
        for name, p in providers.items():
            if isinstance(p, dict) and isinstance(p.get("base_url"), str):
                targets.append((ptr("model_providers", name, "base_url"), p["base_url"]))
    for loc, url in targets:
        res = url_is_plaintext_remote(url)
        if res is True:
            yield finding(meta, doc, loc, safe_url(url)[:140], remediation="Use https://.")
        elif res is False and url.startswith("http://"):
            yield finding(meta, doc, loc, safe_url(url)[:140], severity="INFO",
                          title="Model provider is a loopback HTTP proxy",
                          remediation="Confirm the proxy itself uses TLS upstream and is not reachable from other hosts.")


@rule(RuleMeta(
    id="CX004", severity="LOW",
    title="Broad project trust",
    applies_to=(KIND_CODEX,),
    rationale="A `trusted` project skips the trust prompt and may auto-load that directory's instructions and "
              "MCP servers. Trusting `/` or the home directory trusts every repository; a very long trusted list "
              "suggests trust is granted reflexively.",
    not_caught="Whether each trusted path still exists or what it contains is not checked.",
))
def cx004(doc: Document) -> Iterator[Finding]:
    meta = _m("CX004")
    projects = doc.data.get("projects") if isinstance(doc.data, dict) else None
    if not isinstance(projects, dict):
        return
    trusted = [p for p, v in projects.items() if isinstance(v, dict) and v.get("trust_level") == "trusted"]
    for p in trusted:
        if is_root_like(p):
            yield finding(meta, doc, ptr("projects", p, "trust_level"), "trusted", severity="HIGH",
                          title=f"Root-like path `{p}` marked trusted",
                          remediation="Remove the entry; trust individual project directories.")
    if len(trusted) > TRUSTED_PROJECT_SOFT_LIMIT:
        yield finding(meta, doc, "/projects", f"{len(trusted)} trusted projects",
                      title=f"{len(trusted)} projects marked trusted",
                      remediation="Prune entries for directories you no longer use.")


@rule(RuleMeta(
    id="CX005", severity="INFO",
    title="Codex hook executes a shell command",
    applies_to=(KIND_CODEX,),
    rationale="Hooks run on lifecycle events with the user's privileges and belong to the trust boundary. "
              "Codex records a trusted hash per hook; a hook without one has not been approved.",
    not_caught="The hook script's contents are not read.",
))
def cx005(doc: Document) -> Iterator[Finding]:
    meta = _m("CX005")
    hooks = doc.data.get("hooks") if isinstance(doc.data, dict) else None
    if not isinstance(hooks, dict):
        return
    state = hooks.get("state") if isinstance(hooks.get("state"), dict) else {}
    hashed = {k.split(":", 1)[-1] for k in state}  # "<path>:<event>:<i>:<j>"
    for event, matchers in hooks.items():
        if event == "state" or not isinstance(matchers, list):
            continue
        for i, m in enumerate(matchers):
            inner = m.get("hooks") if isinstance(m, dict) else None
            if not isinstance(inner, list):
                continue
            for j, h in enumerate(inner):
                if not isinstance(h, dict) or h.get("type") != "command":
                    continue
                cmd = str(h.get("command", ""))
                key = f"{event.lower()}:{i}:{j}"
                if key in hashed:
                    yield finding(meta, doc, ptr("hooks", event, i, "hooks", j, "command"), cmd[:120],
                                  remediation="Approved (trusted hash recorded). Re-review if the script changes.")
                else:
                    yield finding(meta, doc, ptr("hooks", event, i, "hooks", j, "command"), cmd[:120], severity="LOW",
                                  title=f"Codex hook on `{event}` has no recorded trusted hash",
                                  remediation="Review the script; Codex will prompt to trust it on next run.")


def _sections(doc: Document) -> Iterator[tuple[str, dict]]:
    d = doc.data if isinstance(doc.data, dict) else {}
    yield "", d
    profiles = d.get("profiles")
    if isinstance(profiles, dict):
        for name, p in profiles.items():
            if isinstance(p, dict):
                yield ptr("profiles", name), p


def _m(rule_id: str) -> RuleMeta:
    from . import _REGISTRY
    return _REGISTRY[rule_id][0]
