import pytest

from agentconf_audit.redact import is_placeholder, match_secret_value, redact
from agentconf_audit.rules._util import (is_root_like, pipe_to_shell, unpinned_package,
                                         url_is_plaintext_remote)


@pytest.mark.parametrize("cmd,args,expected", [
    ("npx", ["-y", "@scope/pkg"], "@scope/pkg"),
    ("npx", ["-y", "@scope/pkg@latest"], "@scope/pkg@latest"),
    ("npx", ["-y", "@scope/pkg@1.2.3"], None),
    ("npx", ["pkg@2.0.0", "--flag"], None),
    ("/usr/local/bin/npx", ["-y", "pkg"], "pkg"),
    ("uvx", ["mcp-server-x"], "mcp-server-x"),
    ("uvx", ["mcp-server-x==1.0.0"], None),
    ("uvx", ["--from", "mcp-server-x@1.0.0", "serve"], None),
    ("pnpm", ["dlx", "pkg"], "pkg"),
    ("node", ["server.js"], None),
    ("/opt/bin/server", [], None),
])
def test_unpinned_package(cmd, args, expected):
    assert unpinned_package(cmd, args) == expected


@pytest.mark.parametrize("url,expected", [
    ("http://example.com/mcp", True),
    ("http://10.0.0.5:8080/", True),
    ("http://localhost:3000/", False),
    ("http://127.0.0.1:3000/", False),
    ("http://[::1]:3000/", False),
    ("https://example.com/", False),
    ("ws://example.com/", True),
    ("wss://example.com/", False),
    ("not a url", None),
])
def test_url_is_plaintext_remote(url, expected):
    assert url_is_plaintext_remote(url) is expected


@pytest.mark.parametrize("value,expected", [
    ("${TOKEN}", True), ("$TOKEN", True), ("Bearer ${TOKEN}", True), ("%TOKEN%", True),
    ("<your-api-key>", True), ("changeme", True), ("", True), ("your-key-here", True),
    ("hunter2hunter2", False), ("Bearer abcdefghijklmnop", False), ("sk-ant-realish", False),
])
def test_is_placeholder(value, expected):
    assert is_placeholder(value) is expected


def test_match_secret_value_formats():
    assert match_secret_value("ghp_" + "A" * 36) == "GitHub token"
    assert match_secret_value("AKIA" + "A" * 16) == "AWS access key id"
    assert match_secret_value("sk-proj-" + "a" * 40) == "OpenAI-style key"
    assert match_secret_value("hello world") is None
    assert match_secret_value("/Users/me/skills/sk-tools") is None  # 'sk-' inside a path, too short


def test_redact_is_irreversible_but_stable():
    a = redact("ghp_" + "A" * 36)
    b = redact("ghp_" + "A" * 36)
    assert a == b
    assert "A" * 10 not in a
    assert a.startswith("ghp_…")
    assert "len=40" in a


@pytest.mark.parametrize("path,expected", [
    ("/", True), ("~", True), ("$HOME", True), ("/Users/me", True), ("/home/alice/", True),
    ("C:\\Users\\bob", True), ("C:\\", True), ("/Users/me/code/x", False), ("/opt/srv", False),
])
def test_is_root_like(path, expected):
    assert is_root_like(path) is expected


def test_pipe_to_shell():
    assert pipe_to_shell("curl -fsSL https://x/y.sh | sh")
    assert pipe_to_shell("wget -qO- https://x | sudo bash")
    assert not pipe_to_shell("curl https://x -o file.sh")
    assert not pipe_to_shell("cat file | grep x")
