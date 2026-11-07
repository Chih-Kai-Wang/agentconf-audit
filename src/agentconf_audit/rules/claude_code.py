"""Rules for Claude Code settings.json and Claude Desktop claude_desktop_config.json."""

from __future__ import annotations

import re
from collections.abc import Iterator

from ..model import KIND_CLAUDE_DESKTOP, KIND_CLAUDE_SETTINGS, Document, Finding, RuleMeta
from ..redact import redact
from . import rule
from ._util import finding, is_root_like, pipe_to_shell, ptr, shell_tokens, unpinned_package

# Commands whose allow-listing hands the agent arbitrary code execution or destructive power.
INTERPRETERS = {"sh", "bash", "zsh", "fish", "python", "python3", "node", "deno", "bun", "ruby",
                "perl", "php", "npx", "uvx", "pipx", "eval", "exec", "osascript", "xargs"}
NETWORK = {"curl", "wget", "nc", "ncat", "ssh", "scp", "rsync"}
DESTRUCTIVE = {"sudo", "su", "rm", "dd", "mkfs", "chmod", "chown", "launchctl", "diskutil"}

_BASH_RE = re.compile(r"^Bash(?:\((.*)\))?$")


def _bash_patterns(doc: Document) -> Iterator[tuple[str, str]]:
    perms = doc.data.get("permissions") if isinstance(doc.data, dict) else None
    if not isinstance(perms, dict):
        return
    allow = perms.get("allow")
    if not isinstance(allow, list):
        return
    for i, entry in enumerate(allow):
        if not isinstance(entry, str):
            continue
        m = _BASH_RE.match(entry.strip())
        if m:
            yield f"/permissions/allow/{i}", (m.group(1) if m.group(1) is not None else "")


@rule(RuleMeta(
    id="CC001", severity="HIGH",
    title="Bash allow-listed without restriction",
    applies_to=(KIND_CLAUDE_SETTINGS,),
    rationale="`Bash`, `Bash(*)` or `Bash(*:*)` in permissions.allow lets the agent run any shell command "
              "without a prompt. Prompt injection in any file the agent reads becomes code execution.",
    not_caught="Equivalent effects reached through defaultMode or a permissive hook are reported by CC003/CC004, not here.",
))
def cc001(doc: Document) -> Iterator[Finding]:
    for ptr, pat in _bash_patterns(doc):
        inner = pat.strip()
        if inner in ("", "*", "*:*", ":*"):
            yield finding(_m("CC001"), doc, ptr, f"Bash({inner})",
                          remediation="Allow specific commands, e.g. `Bash(git status:*)`, `Bash(npm test)`.")


@rule(RuleMeta(
    id="CC002", severity="MEDIUM",
    title="Bash allow-list entry grants arbitrary code execution or destructive power",
    applies_to=(KIND_CLAUDE_SETTINGS,),
    rationale="A prefix rule for an interpreter (`python3 *`), a downloader (`curl *`), a privilege tool "
              "(`sudo *`) or a leading wildcard (`*foo*`) is equivalent to unrestricted execution.",
    not_caught="Only the first token is classified. `Bash(git *)` is not flagged even though git hooks and "
               "aliases can run code; wrapper scripts with innocent names are not inspected.",
))
def cc002(doc: Document) -> Iterator[Finding]:
    meta = _m("CC002")
    for ptr, pat in _bash_patterns(doc):
        inner = pat.strip()
        if inner in ("", "*", "*:*", ":*"):
            continue  # CC001
        if inner.startswith("*"):
            yield finding(meta, doc, ptr, f"Bash({inner})", title="Bash allow-list entry starts with a wildcard",
                          remediation="Anchor the pattern to a command name; a leading `*` matches any command.")
            continue
        toks = shell_tokens(inner.split(":*")[0])
        if not toks:
            continue
        cmd = toks[0].rsplit("/", 1)[-1]
        has_wild = inner.endswith("*") or ":*" in inner
        if cmd in DESTRUCTIVE:
            yield finding(meta, doc, ptr, f"Bash({inner})", severity="HIGH",
                          title=f"Bash allow-list grants `{cmd}`",
                          remediation=f"Remove `{cmd}` from the allow list; approve such commands interactively.")
        elif cmd in INTERPRETERS and has_wild:
            yield finding(meta, doc, ptr, f"Bash({inner})",
                          title=f"Bash allow-list grants arbitrary `{cmd}` execution",
                          remediation=f"Allow only the exact scripts you run, e.g. `Bash({cmd} scripts/build.py)`.")
        elif cmd in NETWORK and has_wild:
            yield finding(meta, doc, ptr, f"Bash({inner})",
                          title=f"Bash allow-list grants unrestricted `{cmd}` (network egress)",
                          remediation="Restrict to known hosts or approve network commands interactively.")


@rule(RuleMeta(
    id="CC003", severity="HIGH",
    title="Permission prompts bypassed by default",
    applies_to=(KIND_CLAUDE_SETTINGS, KIND_CLAUDE_DESKTOP),
    rationale="`permissions.defaultMode` of `bypassPermissions`/`dontAsk`, `skipDangerousModePermissionPrompt`, "
              "or the Desktop bypass opt-in removes the human from every tool call.",
    not_caught="Bypass enabled per-invocation on the command line (`--dangerously-skip-permissions`) leaves no trace in config. "
               "The Desktop keys `bypassPermissionsOptInByAccount`/`bypassPermissionsGateByAccount` are undocumented; their meaning is inferred from the names.",
))
def cc003(doc: Document) -> Iterator[Finding]:
    meta = _m("CC003")
    d = doc.data if isinstance(doc.data, dict) else {}
    perms = d.get("permissions") if isinstance(d.get("permissions"), dict) else {}
    mode = perms.get("defaultMode")
    if mode in ("bypassPermissions", "dontAsk"):
        yield finding(meta, doc, "/permissions/defaultMode", str(mode),
                      remediation="Use `default` or `acceptEdits`; enable bypass only for a sandboxed run.")
    elif mode == "acceptEdits":
        yield finding(meta, doc, "/permissions/defaultMode", str(mode), severity="LOW",
                      title="File edits auto-accepted by default",
                      remediation="Acceptable for trusted repositories; review the diff before committing.")
    if d.get("skipDangerousModePermissionPrompt") is True:
        yield finding(meta, doc, "/skipDangerousModePermissionPrompt", "true",
                      remediation="Remove the key so dangerous mode always confirms.")
    prefs = d.get("preferences") if isinstance(d.get("preferences"), dict) else {}
    for key in ("bypassPermissionsOptInByAccount", "bypassPermissionsGateByAccount"):
        acc = prefs.get(key)
        if isinstance(acc, dict):
            for account, val in acc.items():
                if val is True:
                    yield finding(meta, doc, ptr("preferences", key, account), "true", severity="MEDIUM",
                                  title="Desktop bypass-permissions mode opted in for an account",
                                  remediation="Leave opted-in only while you need it; sessions in this mode act without confirmation.")


@rule(RuleMeta(
    id="CC004", severity="INFO",
    title="Lifecycle hook executes a shell command",
    applies_to=(KIND_CLAUDE_SETTINGS,),
    rationale="Hooks run on every matching tool call with the user's privileges. Their scripts are part of the "
              "trust boundary and should be reviewed like code.",
    not_caught="The hook script's contents are not read. Only the command line is inspected for pipe-to-shell "
               "and unpinned package execution.",
))
def cc004(doc: Document) -> Iterator[Finding]:
    meta = _m("CC004")
    hooks = doc.data.get("hooks") if isinstance(doc.data, dict) else None
    if not isinstance(hooks, dict):
        return
    for event, matchers in hooks.items():
        if not isinstance(matchers, list):
            continue
        for i, m in enumerate(matchers):
            inner = m.get("hooks") if isinstance(m, dict) else None
            if not isinstance(inner, list):
                continue
            for j, h in enumerate(inner):
                if not isinstance(h, dict) or h.get("type") != "command":
                    continue
                cmd = str(h.get("command", ""))
                loc = ptr("hooks", event, i, "hooks", j, "command")
                if pipe_to_shell(cmd):
                    yield finding(meta, doc, loc, cmd[:120], severity="HIGH",
                                  title="Hook downloads and executes remote code",
                                  remediation="Vendor the script into the repository and run it from a fixed path.")
                    continue
                toks = shell_tokens(cmd)
                pkg = unpinned_package(toks[0], toks[1:]) if toks else None
                if pkg:
                    yield finding(meta, doc, loc, cmd[:120], severity="MEDIUM",
                                  title=f"Hook runs unpinned package `{pkg}` on every {event}",
                                  remediation="Pin an exact version or install the tool once and call the binary.")
                    continue
                yield finding(meta, doc, loc, cmd[:120],
                              remediation=f"Review the script run on `{event}`; keep it in version control.")


@rule(RuleMeta(
    id="CC005", severity="HIGH",
    title="Credential stored in settings env",
    applies_to=(KIND_CLAUDE_SETTINGS,),
    rationale="`env` values are injected into every tool process and are easy to leak via `settings.json` "
              "backups, dotfile repositories and screenshots.",
    not_caught="Secrets passed through a helper (`apiKeyHelper`) or the OS keychain are the right pattern and are not inspected. "
               "Any value containing `$VAR` or `${VAR}` is treated as an indirection, so a literal secret that happens to contain `$word` is skipped.",
))
def cc005(doc: Document) -> Iterator[Finding]:
    from ..redact import is_placeholder, is_secret_key, match_secret_value
    meta = _m("CC005")
    env = doc.data.get("env") if isinstance(doc.data, dict) else None
    if not isinstance(env, dict):
        return
    for k, v in env.items():
        if not isinstance(v, str) or is_placeholder(v):
            continue
        fmt = match_secret_value(v)
        if fmt or (is_secret_key(k) and len(v) >= 8):
            yield finding(meta, doc, ptr("env", k), f"{k}={redact(v)}",
                          title=f"Credential stored in settings env ({fmt or 'secret-like key name'})",
                          remediation="Move the value to the OS keychain or an `apiKeyHelper`; reference it as `${VAR}`.")


@rule(RuleMeta(
    id="CC006", severity="MEDIUM",
    title="Project MCP servers auto-approved",
    applies_to=(KIND_CLAUDE_SETTINGS,),
    rationale="`enableAllProjectMcpServers: true` starts every server declared in a repository's `.mcp.json` "
              "without asking. Cloning a malicious repository then runs its servers.",
    not_caught="Servers approved individually under `enabledMcpjsonServers` are not evaluated for trust.",
))
def cc006(doc: Document) -> Iterator[Finding]:
    d = doc.data if isinstance(doc.data, dict) else {}
    if d.get("enableAllProjectMcpServers") is True:
        yield finding(_m("CC006"), doc, "/enableAllProjectMcpServers", "true",
                      remediation="Set to false and approve project servers one by one.")


@rule(RuleMeta(
    id="CC007", severity="MEDIUM",
    title="Additional directory grants whole-filesystem or home access",
    applies_to=(KIND_CLAUDE_SETTINGS,),
    rationale="`permissions.additionalDirectories` widens the agent's file scope; `/` or the home directory "
              "defeats project isolation (SSH keys, browser profiles, other repositories).",
    not_caught="Symlinks inside an allowed directory that point outside it are not followed.",
))
def cc007(doc: Document) -> Iterator[Finding]:
    perms = doc.data.get("permissions") if isinstance(doc.data, dict) else None
    dirs = perms.get("additionalDirectories") if isinstance(perms, dict) else None
    if not isinstance(dirs, list):
        return
    for i, dpath in enumerate(dirs):
        if isinstance(dpath, str) and is_root_like(dpath):
            yield finding(_m("CC007"), doc, f"/permissions/additionalDirectories/{i}", dpath,
                          remediation="List only the specific directories the task needs.")


@rule(RuleMeta(
    id="CC008", severity="LOW",
    title="Sandbox disabled",
    applies_to=(KIND_CLAUDE_SETTINGS,),
    rationale="With `sandbox.enabled: false`, shell commands run with the full privileges of the user "
              "instead of inside the OS sandbox, so a permission mistake has no second barrier.",
    not_caught="Whether the sandbox is available on this platform/version is not checked; the key may be a no-op.",
))
def cc008(doc: Document) -> Iterator[Finding]:
    sb = doc.data.get("sandbox") if isinstance(doc.data, dict) else None
    if isinstance(sb, dict) and sb.get("enabled") is False:
        yield finding(_m("CC008"), doc, "/sandbox/enabled", "false",
                      remediation="Enable the sandbox and add explicit exceptions where a tool needs them.")


def _m(rule_id: str) -> RuleMeta:
    from . import _REGISTRY
    return _REGISTRY[rule_id][0]
