# agentconf-audit

**Static security audit of AI coding-agent configuration — Claude Code, Claude Desktop, MCP servers, OpenAI Codex — with evidence-attached, replayable reports.**

Zero runtime dependencies (Python ≥ 3.11 standard library). Read-only. Secrets are never printed, only a prefix, length and truncated SHA-256.

```
$ agentconf-audit scan --auto          # the author's machine, 2026-11-07, paths shortened
[HIGH  ] CX001  Codex never asks for approval
         ~/.codex/config.toml  /approval_policy
         evidence: never
[HIGH  ] CX002  Codex sandbox disabled (danger-full-access)
         ~/.codex/config.toml  /sandbox_mode
         evidence: danger-full-access
[HIGH  ] CX004  Root-like path `/` marked trusted
         ~/.codex/config.toml  /projects/~1/trust_level
         evidence: trusted
…
4 file(s) scanned · HIGH 4 · MEDIUM 10 · LOW 2 · INFO 3
report_sha256 91469cb664007c696a5ead33a6fd9e0ddd49ac9827d1c9ebc2cc702cffabc8e4
```

## Why

An AI coding agent's configuration *is* its trust boundary. Three lines of JSON decide whether a prompt injection in a README becomes code execution:

| Configuration choice | What an attacker gets |
|---|---|
| `"Bash(*)"` in the allow list, or `approval_policy = "never"` | Any command the model is talked into running, with no human in the loop |
| `npx -y some-mcp-server@latest` | Code execution on every launch by whoever controls that package name tomorrow |
| A token in `env`, or a project tree marked `trusted` at `/` | Every secret and repository on the machine, readable by the model and by anything that reads the file |

These settings are easy to turn on during a deadline and easy to forget. `agentconf-audit` reads the files, names the exact key, and says what is wrong and what it cannot see.

## Install and run

```bash
# one-off, no install
uvx --from git+https://github.com/f0909172434/agentconf-audit agentconf-audit scan --auto

# or install
uv tool install git+https://github.com/f0909172434/agentconf-audit
agentconf-audit scan --auto                      # well-known per-user locations + ./.mcp.json
agentconf-audit scan path/to/.mcp.json ~/.codex  # files or directories
agentconf-audit scan --auto --format md -o audit.md
agentconf-audit scan --auto --format json -o audit.json && agentconf-audit verify audit.json
agentconf-audit rules                            # every rule, its rationale and its blind spot
```

Exit codes: `0` nothing at or above `--fail-on` (default `high`), `1` findings at or above it, `2` usage or I/O error, `3` report hash does not verify. That makes it a CI gate:

```yaml
- run: uvx --from git+https://github.com/f0909172434/agentconf-audit agentconf-audit scan .mcp.json .claude/settings.json --fail-on medium
```

## What it checks

21 rules. Full text with rationale and the explicit *not caught* statement for each is in [docs/RULES.md](docs/RULES.md) (generated from the code; a test fails if it drifts).

| ID | Default | Finding |
|---|---|---|
| CC001 | HIGH | `Bash` allow-listed without restriction |
| CC002 | MEDIUM | Bash allow-list entry grants an interpreter, downloader, `sudo`, or starts with `*` (`sudo`/`rm`/`dd` → HIGH) |
| CC003 | HIGH | `defaultMode: bypassPermissions`/`dontAsk`, `skipDangerousModePermissionPrompt`, Desktop bypass opt-in |
| CC004 | INFO | Lifecycle hook runs a shell command (pipe-to-shell → HIGH, unpinned `npx` → MEDIUM) |
| CC005 | HIGH | Credential literal in `settings.env` |
| CC006 | MEDIUM | `enableAllProjectMcpServers: true` |
| CC007 | MEDIUM | `additionalDirectories` includes `/` or a home directory |
| CC008 | LOW | `sandbox.enabled: false` |
| MCP001 | MEDIUM | Server runs an unpinned registry package (`npx -y pkg`, `@latest`, bare `uvx pkg`) |
| MCP002 | HIGH | Credential literal in a server's `env`, `headers`, `args` or URL |
| MCP003 | HIGH | Remote server over plaintext `http://` (loopback → INFO) |
| MCP004 | HIGH | Server command pipes a download into a shell |
| MCP005 | LOW | Server binary resolved via PATH (temp directory → MEDIUM) |
| MCP006 | MEDIUM | Server scoped to `/`, `~` or a home directory |
| CX001 | HIGH | Codex `approval_policy = "never"` (also per profile) |
| CX002 | HIGH | Codex `sandbox_mode = "danger-full-access"` (`workspace-write` + network → LOW) |
| CX003 | HIGH | Model provider `base_url` over plaintext HTTP (loopback → INFO) |
| CX004 | LOW | Root-like path marked `trusted` (→ HIGH); more than 50 trusted projects |
| CX005 | INFO | Codex hook command; no recorded `trusted_hash` → LOW |
| GEN001 | INFO | File unparseable or unrecognised — reported so silence never means "clean" |
| GEN002 | MEDIUM | Config file group/world-readable (POSIX only) |

Recognised inputs: `~/.claude/settings.json` and project `.claude/settings*.json`, `~/.claude.json`, `claude_desktop_config.json`, any `.mcp.json` / `mcp.json` / `mcp_config.json` with `mcpServers`, and `~/.codex/config.toml`.

## Evidence and replay

- Every finding carries the file, a JSON-pointer location (RFC 6901 escaping), a redacted excerpt, a rationale and a fix.
- The JSON report carries `report_sha256`, a hash over the canonical `{inputs, findings}` body. `agentconf-audit verify report.json` recomputes it, so a report quoted in a pull request can be checked against the file that produced it. Inputs are listed with their own SHA-256.
- `fixtures/` holds synthetic good and bad configurations for every format; `fixtures/expected/` holds the frozen report for each. A rule change must change a golden, and the diff is the review artefact (`UPDATE_GOLDENS=1 uv run pytest` regenerates).
- Tests assert that every rule fires on at least one fixture, that the `good-*` fixtures produce nothing above INFO, and that no secret literal from any fixture appears anywhere in any output format.

## What it does not do

- **It does not read scripts.** Hook scripts, wrapper binaries and MCP server code are not opened; only the command lines in the config are classified.
- **It does not inspect running servers.** Tool descriptions (the main prompt-injection surface in MCP) require connecting to the server and are out of scope.
- **It does not know your threat model.** `approval_policy = "never"` inside a disposable VM is fine; the tool reports it anyway and leaves the judgement to you. Use `--disable` or `--fail-on` to encode your policy.
- **Coverage is three ecosystems.** Cursor/Windsurf `mcp.json` files are handled only for their `mcpServers` block; Gemini CLI, Cline, Aider and others are not recognised and are reported under GEN001 rather than silently skipped.
- **Loopback is trusted.** `http://127.0.0.1` proxies are INFO; what they forward to, and over what, is unknown.
- **PATH hygiene is heuristic.** Common runtimes (`node`, `python3`, `npx`, …) are exempt from MCP005 to keep noise down, so a hijacked `node` is not reported.
- **No independent validation yet.** The rules come from reading the three projects' documentation and real configurations on one machine, not from an audit standard. Treat a clean run as "none of these 21 patterns", not as "secure".

## Development

```bash
uv sync --group dev
uv run pytest -q                      # 71 tests, < 1 s
uv run agentconf-audit rules --markdown > docs/RULES.md
```

Layout: `src/agentconf_audit/rules/*.py` (one module per ecosystem, each rule a decorated function with `RuleMeta` carrying its rationale and `not_caught`), `loaders.py` (classification), `redact.py` (secret formats and redaction), `report.py` (JSON/Markdown/text + hash).

---

## 繁體中文

**AI coding agent 設定檔的靜態安全稽核工具**，支援 Claude Code、Claude Desktop、MCP server 宣告與 OpenAI Codex。純 Python 標準庫、唯讀、祕密值永不輸出（只顯示前綴、長度與截斷的 SHA-256）。

- **為什麼**：agent 的設定檔就是它的信任邊界。`Bash(*)`、`approval_policy = "never"`、`npx -y pkg@latest`、把 `/` 標成 trusted，任何一項都能讓 README 裡的一段 prompt injection 變成程式碼執行或整台機器的祕密外洩。
- **做什麼**：21 條規則，每條都附理由（why）、修法（fix）與明確的「抓不到什麼」（not caught）。輸出 text / Markdown / JSON；JSON 報告帶 `report_sha256`，`agentconf-audit verify` 可重算驗證。
- **怎麼用**：`agentconf-audit scan --auto` 掃本機常見位置；`--fail-on medium` 當 CI gate；`agentconf-audit rules` 列出全部規則。
- **不做什麼**：不讀 hook 腳本內容、不連線到 MCP server 檢查 tool description、不替你判斷威脅模型、尚無獨立驗證。乾淨的結果代表「沒有這 21 種模式」，不代表安全。

## License

MIT
