"""Secret detection and redaction. Redacted values keep a short hash so a reader can
confirm two reports refer to the same secret without ever seeing it."""

from __future__ import annotations

import hashlib
import re

SECRET_KEY_RE = re.compile(
    r"(api[_-]?key|secret|token|passw(or)?d|credential|private[_-]?key|auth(orization)?$|bearer)",
    re.IGNORECASE,
)

# Well-known credential formats. Each pattern is anchored to a recognisable prefix so
# ordinary strings (paths, model names) do not match.
SECRET_VALUE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("OpenAI-style key", re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}")),
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("Private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
)

# Values that are clearly placeholders or indirections, never real secrets.
PLACEHOLDER_RE = re.compile(
    r"^\s*$"                               # empty
    r"|^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$"   # ${VAR} or $VAR
    r"|^%[A-Za-z_][A-Za-z0-9_]*%$"         # %VAR% (Windows)
    r"|^<[^>]+>$"                          # <your-key>
    r"|^(your|my|insert|replace|change|todo|xxx|placeholder|example|dummy|test)[-_a-z0-9 ]*$"
    r"|^(changeme|redacted|none|null|true|false|\*+)$",
    re.IGNORECASE,
)


def is_secret_key(key: str) -> bool:
    return bool(SECRET_KEY_RE.search(key))


INDIRECTION_RE = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*\b|%[A-Za-z_][A-Za-z0-9_]*%")
AUTH_SCHEME_RE = re.compile(r"^(Bearer|Basic|Token|ApiKey)\s+", re.IGNORECASE)


def is_placeholder(value: str) -> bool:
    """True for empty values, obvious placeholders and indirections (`${VAR}`, `Bearer $TOKEN`)."""
    core = AUTH_SCHEME_RE.sub("", value.strip())
    if INDIRECTION_RE.search(core):
        return True
    return bool(PLACEHOLDER_RE.match(core))


def match_secret_value(value: str) -> str | None:
    """Return the name of the credential format matched, or None."""
    for name, pat in SECRET_VALUE_PATTERNS:
        if pat.search(value):
            return name
    return None


def redact(value: str, keep: int = 4) -> str:
    """Show a short prefix, the length and a truncated SHA-256 so the value is identifiable
    across reports but not recoverable."""
    digest = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:10]
    prefix = value[:keep] if len(value) > keep + 2 else ""
    return f"{prefix}…(len={len(value)}, sha256:{digest})"
