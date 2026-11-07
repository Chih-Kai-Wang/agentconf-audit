"""Helpers shared by rule modules."""

from __future__ import annotations

import os
import re
import shlex
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..model import Document, Finding, RuleMeta


def finding(meta: RuleMeta, doc: Document, location: str, evidence: str, *,
            severity: str | None = None, title: str | None = None,
            rationale: str | None = None, remediation: str) -> Finding:
    return Finding(
        rule_id=meta.id,
        severity=severity or meta.severity,
        title=title or meta.title,
        file=doc.path,
        location=location,
        evidence=evidence,
        rationale=rationale or meta.rationale,
        remediation=remediation,
    )


def walk(obj: Any, path: str = "") -> Iterator[tuple[str, Any]]:
    """Depth-first walk yielding (json-pointer, value) for every node."""
    yield path, obj
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk(v, f"{path}/{_esc(str(k))}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk(v, f"{path}/{i}")


def _esc(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def ptr(*parts: object) -> str:
    """Build a JSON pointer from raw key/index parts, escaping `~` and `/` per RFC 6901."""
    return "".join(f"/{_esc(str(p))}" for p in parts)


def find_server_maps(doc: Document) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield (pointer, servers-dict) for every mcpServers / mcp_servers mapping in the document."""
    for ptr, node in walk(doc.data):
        if isinstance(node, dict):
            for key in ("mcpServers", "mcp_servers"):
                servers = node.get(key)
                if isinstance(servers, dict):
                    yield f"{ptr}/{key}", servers


def safe_url(url: str) -> str:
    """URL for display: query string and userinfo removed, since both commonly carry credentials."""
    try:
        p = urlsplit(url)
    except ValueError:
        return "<unparseable url>"
    host = p.hostname or ""
    if p.port:
        host += f":{p.port}"
    shown = f"{p.scheme}://{host}{p.path}" if p.scheme else url.split("?")[0]
    if p.query:
        shown += "?<query redacted>"
    return shown


LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]", "0:0:0:0:0:0:0:1"}


def url_is_plaintext_remote(url: str) -> bool | None:
    """True for http:// to a non-loopback host, False for https or loopback, None if not a URL."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme not in ("http", "https", "ws", "wss"):
        return None
    if parts.scheme in ("https", "wss"):
        return False
    host = (parts.hostname or "").lower()
    return host not in LOOPBACK_HOSTS and not host.startswith("127.")


PACKAGE_RUNNERS = {"npx", "uvx", "bunx", "pipx", "dlx"}  # "pnpm dlx" / "yarn dlx" handled via tokens

# Runtimes and runners that are conventionally resolved via PATH; flagging them is noise.
COMMON_RUNTIMES = PACKAGE_RUNNERS | {"pnpm", "yarn", "node", "deno", "bun", "python", "python3", "uv",
                                      "docker", "podman", "sh", "bash", "zsh", "cmd", "powershell", "pwsh"}


def unpinned_package(command: str, args: list[str]) -> str | None:
    """If the command runs a package straight from a registry without an exact version,
    return the package spec. Pinning = '@1.2.3' (npm) or '==1.2.3' / '@1.2.3' (uvx)."""
    tokens = [os.path.basename(str(command))] + [str(a) for a in args]
    if not tokens:
        return None
    runner = tokens[0]
    if runner in ("pnpm", "yarn") and len(tokens) > 1 and tokens[1] == "dlx":
        tokens = tokens[1:]
        runner = "dlx"
    if runner not in PACKAGE_RUNNERS:
        return None
    for tok in tokens[1:]:
        if tok.startswith("-"):
            continue
        if runner in ("uvx", "pipx"):
            if re.search(r"(==|@)\d", tok):
                return None
            return tok
        # npm-style: name[@version], scoped @scope/name[@version]
        m = re.match(r"^(@[^/]+/[^@]+|[^@]+)(?:@(.+))?$", tok)
        if not m:
            return tok
        version = m.group(2)
        if version is None or version in ("latest", "next", "canary") or not re.match(r"^\d+\.\d+\.\d+", version):
            return tok
        return None
    return None


PIPE_TO_SHELL_RE = re.compile(r"\b(curl|wget|iwr|Invoke-WebRequest)\b[^|;&]*\|\s*(sudo\s+)?(sh|bash|zsh|python3?|node|pwsh|powershell)\b", re.I)


def pipe_to_shell(text: str) -> bool:
    return bool(PIPE_TO_SHELL_RE.search(text))


def is_root_like(p: str) -> bool:
    """Path that grants the whole filesystem or the whole home directory."""
    s = str(p).strip().rstrip("/") or "/"
    home = str(Path.home()).rstrip("/")
    if s in ("/", "~", "$HOME", "${HOME}", "%USERPROFILE%"):
        return True
    if re.fullmatch(r"[A-Za-z]:\\?", s):
        return True
    if s == home or s == os.path.dirname(home):
        return True
    # A user's home directory on any platform, even when it is not this machine's HOME.
    if re.fullmatch(r"/(Users|home)(/[^/]+)?", s) or re.fullmatch(r"[A-Za-z]:\\Users(\\[^\\]+)?", s):
        return True
    return False


TEMP_DIR_RE = re.compile(r"^(/tmp|/var/tmp|/private/tmp|/dev/shm|/Users/Shared|C:\\Windows\\Temp|C:\\Temp)(/|\\|$)", re.I)


def in_temp_dir(cmd: str) -> bool:
    return bool(TEMP_DIR_RE.match(str(cmd)))


def shell_tokens(cmd: str) -> list[str]:
    try:
        return shlex.split(cmd, posix=True)
    except ValueError:
        return cmd.split()
