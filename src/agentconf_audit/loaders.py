"""Load configuration files and classify them into document kinds. Read-only."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import tomllib
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

from .model import (
    KIND_CLAUDE_DESKTOP,
    KIND_CLAUDE_JSON,
    KIND_CLAUDE_SETTINGS,
    KIND_CODEX,
    KIND_MCP_JSON,
    KIND_UNKNOWN,
    Document,
)


def classify(path: Path, data: Any) -> str:
    name = path.name
    if name == "config.toml" or path.suffix == ".toml":
        if isinstance(data, dict) and (
            "approval_policy" in data or "sandbox_mode" in data or "mcp_servers" in data
            or "model_providers" in data or "projects" in data
        ):
            return KIND_CODEX
        return KIND_UNKNOWN
    if not isinstance(data, dict):
        return KIND_UNKNOWN
    if name == "claude_desktop_config.json":
        return KIND_CLAUDE_DESKTOP
    if name == ".claude.json":
        return KIND_CLAUDE_JSON
    if name.startswith("settings") and name.endswith(".json") and (
        "permissions" in data or "hooks" in data or "env" in data or "sandbox" in data
    ):
        return KIND_CLAUDE_SETTINGS
    if "mcpServers" in data or "mcp_servers" in data:
        return KIND_MCP_JSON
    if "permissions" in data or "hooks" in data:
        return KIND_CLAUDE_SETTINGS
    return KIND_UNKNOWN


def load_document(path: Path) -> Document:
    raw = path.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    mode: int | None = None
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:
        mode = None
    data: Any = None
    err: str | None = None
    try:
        if path.suffix == ".toml":
            data = tomllib.loads(raw.decode("utf-8"))
        else:
            data = json.loads(raw.decode("utf-8-sig"))
    except (ValueError, UnicodeDecodeError) as e:  # json.JSONDecodeError and TOMLDecodeError are ValueErrors
        err = f"{type(e).__name__}: {e}"
    kind = KIND_UNKNOWN if err else classify(path, data)
    return Document(path=str(path), kind=kind, data=data, sha256=sha, size=len(raw), mode=mode, parse_error=err)


def default_locations() -> list[Path]:
    """Well-known per-user config locations on this platform. Only existing files are returned."""
    home = Path.home()
    candidates: list[Path] = [
        home / ".claude" / "settings.json",
        home / ".claude" / "settings.local.json",
        home / ".claude.json",
        home / ".codex" / "config.toml",
        home / ".cursor" / "mcp.json",
        home / ".codeium" / "windsurf" / "mcp_config.json",
    ]
    if sys.platform == "darwin":
        candidates.append(home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json")
    elif sys.platform.startswith("win"):
        appdata = os.environ.get("APPDATA")
        if appdata:
            candidates.append(Path(appdata) / "Claude" / "claude_desktop_config.json")
    else:
        candidates.append(home / ".config" / "Claude" / "claude_desktop_config.json")
    cwd = Path.cwd()
    candidates += [cwd / ".mcp.json", cwd / ".claude" / "settings.json", cwd / ".claude" / "settings.local.json"]
    seen: set[Path] = set()
    out: list[Path] = []
    for c in candidates:
        try:
            r = c.resolve()
        except OSError:
            continue
        if r in seen or not c.is_file():
            continue
        seen.add(r)
        out.append(c)
    return out


def expand_paths(paths: Iterable[str]) -> Iterator[Path]:
    """Files are yielded as-is; directories are walked for known config file names."""
    names = {"settings.json", "settings.local.json", ".mcp.json", "mcp.json", "mcp_config.json",
             "claude_desktop_config.json", ".claude.json", "config.toml"}
    for p in paths:
        path = Path(p).expanduser()
        if path.is_dir():
            for root, dirs, files in os.walk(path):
                dirs[:] = [d for d in dirs if d not in {"node_modules", ".git", ".venv", "__pycache__"}]
                for f in sorted(files):
                    if f in names:
                        yield Path(root) / f
        else:
            yield path
