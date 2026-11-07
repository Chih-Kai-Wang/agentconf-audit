"""Rules for MCP server declarations, wherever they appear (Claude Desktop, .mcp.json, ~/.claude.json,
Cursor/Windsurf mcp.json, Codex config.toml [mcp_servers])."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from ..model import (KIND_CLAUDE_DESKTOP, KIND_CLAUDE_JSON, KIND_CLAUDE_SETTINGS, KIND_CODEX,
                     KIND_MCP_JSON, Document, Finding, RuleMeta)
from ..redact import is_placeholder, is_secret_key, match_secret_value, redact
from . import rule
from ._util import (COMMON_RUNTIMES, find_server_maps, finding, in_temp_dir, is_root_like,
                    pipe_to_shell, ptr, safe_url, unpinned_package, url_is_plaintext_remote)

MCP_KINDS = (KIND_CLAUDE_DESKTOP, KIND_CLAUDE_JSON, KIND_CLAUDE_SETTINGS, KIND_MCP_JSON, KIND_CODEX)


def _servers(doc: Document) -> Iterator[tuple[str, str, dict[str, Any]]]:
    """Yield (pointer, name, server) for enabled servers."""
    for base, servers in find_server_maps(doc):
        for name, srv in servers.items():
            if not isinstance(srv, dict):
                continue
            if srv.get("enabled") is False or srv.get("disabled") is True:
                continue
            yield base + ptr(name), str(name), srv


def _args(srv: dict[str, Any]) -> list[str]:
    a = srv.get("args")
    return [str(x) for x in a] if isinstance(a, list) else []


@rule(RuleMeta(
    id="MCP001", severity="MEDIUM",
    title="MCP server runs an unpinned package from a registry",
    applies_to=MCP_KINDS,
    rationale="`npx -y pkg`, `pkg@latest` or `uvx pkg` resolves and executes whatever the registry serves at "
              "launch time. A compromised or typosquatted release runs with your privileges on next start.",
    not_caught="A pinned version is still only as safe as that release; integrity (lockfile/hash) is not verified.",
))
def mcp001(doc: Document) -> Iterator[Finding]:
    for base, name, srv in _servers(doc):
        cmd = srv.get("command")
        if not isinstance(cmd, str):
            continue
        pkg = unpinned_package(cmd, _args(srv))
        if pkg:
            yield finding(_m("MCP001"), doc, f"{base}/args", f"{cmd} {' '.join(_args(srv))}"[:140],
                          title=f"MCP server `{name}` runs unpinned package `{pkg}`",
                          remediation=f"Pin an exact version (e.g. `{pkg.split('@latest')[0]}@X.Y.Z`) or install once and point `command` at the binary.")


@rule(RuleMeta(
    id="MCP002", severity="HIGH",
    title="Credential embedded in MCP server configuration",
    applies_to=MCP_KINDS,
    rationale="Secrets in `env`, `args`, `headers` or the URL of a server are stored in plaintext and shared "
              "with every process that can read the file.",
    not_caught="Secrets in files the server reads itself (`.env`, keychains) are out of scope. Any value containing `$VAR`/`${VAR}` "
               "is treated as an indirection and skipped; only the listed credential formats and secret-like key names are recognised.",
))
def mcp002(doc: Document) -> Iterator[Finding]:
    meta = _m("MCP002")
    for base, name, srv in _servers(doc):
        env = srv.get("env") if isinstance(srv.get("env"), dict) else {}
        headers = srv.get("headers") if isinstance(srv.get("headers"), dict) else {}
        for section, mapping in (("env", env), ("headers", headers)):
            for k, v in mapping.items():
                if not isinstance(v, str) or is_placeholder(v):
                    continue
                fmt = match_secret_value(v)
                if fmt or (is_secret_key(str(k)) and len(v) >= 8):
                    yield finding(meta, doc, base + ptr(section, k), f"{k}={redact(v)}",
                                  title=f"Credential embedded in MCP server `{name}` ({fmt or 'secret-like key name'})",
                                  remediation="Reference an environment variable (`${VAR}`) or a secret manager instead of the literal value.")
        for i, a in enumerate(_args(srv)):
            fmt = match_secret_value(a)
            if fmt:
                yield finding(meta, doc, f"{base}/args/{i}", redact(a),
                              title=f"Credential passed as argument to MCP server `{name}` ({fmt})",
                              remediation="Arguments are visible in the process list; pass secrets via the environment.")
        url = srv.get("url")
        if isinstance(url, str) and (match_secret_value(url) or any(
                is_secret_key(part.split("=")[0]) for part in url.split("?")[-1].split("&") if "=" in part)):
            yield finding(meta, doc, f"{base}/url", safe_url(url)[:140],
                          title=f"Credential in URL of MCP server `{name}`",
                          remediation="Move the token to a header sourced from the environment.")


@rule(RuleMeta(
    id="MCP003", severity="HIGH",
    title="Remote MCP server reached over plaintext HTTP",
    applies_to=MCP_KINDS,
    rationale="Tool calls and results (often including file contents) cross the network unencrypted and can be "
              "read or modified in transit; a modified tool result is a prompt-injection vector.",
    not_caught="Loopback `http://127.0.0.1` is reported as INFO only; what the local proxy forwards to is unknown.",
))
def mcp003(doc: Document) -> Iterator[Finding]:
    meta = _m("MCP003")
    for base, name, srv in _servers(doc):
        url = srv.get("url")
        if not isinstance(url, str):
            continue
        res = url_is_plaintext_remote(url)
        if res is True:
            yield finding(meta, doc, f"{base}/url", safe_url(url)[:140],
                          title=f"MCP server `{name}` uses plaintext HTTP to a remote host",
                          remediation="Use https:// (or wss://).")
        elif res is False and url.startswith(("http://", "ws://")):
            yield finding(meta, doc, f"{base}/url", safe_url(url)[:140], severity="INFO",
                          title=f"MCP server `{name}` uses plaintext HTTP to loopback",
                          remediation="Fine for a local process; confirm nothing else on the machine can bind that port.")


@rule(RuleMeta(
    id="MCP004", severity="HIGH",
    title="MCP server command downloads and executes remote code",
    applies_to=MCP_KINDS,
    rationale="`curl … | sh` style launchers fetch arbitrary code on every start with no pinning or integrity check.",
    not_caught="Installers invoked indirectly by a script file are not detected.",
))
def mcp004(doc: Document) -> Iterator[Finding]:
    for base, name, srv in _servers(doc):
        line = " ".join([str(srv.get("command", ""))] + _args(srv))
        if pipe_to_shell(line):
            yield finding(_m("MCP004"), doc, f"{base}/command", line[:140],
                          title=f"MCP server `{name}` pipes a download into a shell",
                          remediation="Install the server once, verify it, and launch the installed binary.")


@rule(RuleMeta(
    id="MCP005", severity="LOW",
    title="MCP server command resolved through PATH or launched from a temporary directory",
    applies_to=MCP_KINDS,
    rationale="A bare command name is resolved by PATH at launch; a writable earlier PATH entry or a temp "
              "directory lets another process substitute the binary.",
    not_caught="PATH contents and directory permissions are not inspected; common runtimes (`node`, `python3`, `npx`, …) are deliberately exempt, so a hijacked `node` is not reported. A hygiene signal, not proof of exposure.",
))
def mcp005(doc: Document) -> Iterator[Finding]:
    meta = _m("MCP005")
    for base, name, srv in _servers(doc):
        cmd = srv.get("command")
        if not isinstance(cmd, str) or not cmd:
            continue
        if in_temp_dir(cmd):
            yield finding(meta, doc, f"{base}/command", cmd[:140], severity="MEDIUM",
                          title=f"MCP server `{name}` launched from a temporary directory",
                          remediation="Install the server under a user- or system-owned directory.")
        elif "/" not in cmd and "\\" not in cmd and cmd not in COMMON_RUNTIMES:
            yield finding(meta, doc, f"{base}/command", cmd,
                          title=f"MCP server `{name}` command `{cmd}` resolved via PATH",
                          remediation="Use the absolute path of the binary.")


@rule(RuleMeta(
    id="MCP006", severity="MEDIUM",
    title="MCP server granted whole-filesystem or home-directory scope",
    applies_to=MCP_KINDS,
    rationale="Filesystem-style servers take allowed roots as arguments; `/`, `~` or the home directory exposes "
              "every credential and repository on the machine to the model.",
    not_caught="Scope passed through environment variables or a server-specific config file is not read.",
))
def mcp006(doc: Document) -> Iterator[Finding]:
    for base, name, srv in _servers(doc):
        for i, a in enumerate(_args(srv)):
            if is_root_like(a):
                yield finding(_m("MCP006"), doc, f"{base}/args/{i}", a,
                              title=f"MCP server `{name}` scoped to `{a}`",
                              remediation="Pass the specific project directories instead.")


def _m(rule_id: str) -> RuleMeta:
    from . import _REGISTRY
    return _REGISTRY[rule_id][0]
