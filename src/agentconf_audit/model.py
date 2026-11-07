"""Core data types shared by loaders, rules and reports."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITIES: tuple[str, ...] = ("HIGH", "MEDIUM", "LOW", "INFO")
SEVERITY_RANK: dict[str, int] = {s: i for i, s in enumerate(SEVERITIES)}

# Document kinds the loader can recognise. A rule declares which kinds it applies to.
KIND_CLAUDE_SETTINGS = "claude-code-settings"   # ~/.claude/settings.json, .claude/settings*.json
KIND_CLAUDE_JSON = "claude-code-state"          # ~/.claude.json (top-level + per-project mcpServers)
KIND_CLAUDE_DESKTOP = "claude-desktop-config"   # claude_desktop_config.json
KIND_MCP_JSON = "mcp-servers-json"              # .mcp.json, cursor/windsurf mcp.json, any {"mcpServers": ...}
KIND_CODEX = "codex-config"                     # ~/.codex/config.toml
KIND_UNKNOWN = "unknown"
ALL_KINDS: tuple[str, ...] = (
    KIND_CLAUDE_SETTINGS,
    KIND_CLAUDE_JSON,
    KIND_CLAUDE_DESKTOP,
    KIND_MCP_JSON,
    KIND_CODEX,
)


@dataclass
class Document:
    """One parsed configuration file."""

    path: str
    kind: str
    data: Any
    sha256: str
    size: int
    mode: int | None = None          # POSIX permission bits, None when unavailable
    parse_error: str | None = None


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    file: str
    location: str                    # JSON-pointer-like path into the document, e.g. /permissions/allow/3
    evidence: str                    # redacted excerpt of the offending value
    rationale: str
    remediation: str

    def sort_key(self) -> tuple:
        return (SEVERITY_RANK[self.severity], self.rule_id, self.file, self.location)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RuleMeta:
    id: str
    severity: str                    # default severity; a rule may emit lower severities for weaker matches
    title: str
    applies_to: tuple[str, ...]
    rationale: str
    not_caught: str                  # honest statement of what this rule does NOT detect

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["applies_to"] = list(self.applies_to)
        return d


@dataclass
class Report:
    inputs: list[dict[str, Any]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def summary(self) -> dict[str, int]:
        counts = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            counts[f.severity] += 1
        return counts
