# Changelog

All notable changes to this project are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

V1 hardening: no new vulnerability classes or components — correctness,
failure handling, and documentation truthfulness only.

### Fixed

- Supply-chain CLI crashed on `pip-audit` failures (`PipAuditFailed`,
  `TimeoutExpired`); now degrades to `{"error": ...}` like a missing
  `pip-audit` does, with regression tests.
- Proxy raised a bare `KeyError` (no audit record, no metric) when the
  policy allowed a tool with no registered executor; now denied fail-closed
  as `MCP-SENT-001` (least privilege), with regression tests.
- Dry-run denials were counted in `policy_denials_total` though nothing was
  blocked; now recorded in the audit log and `tool_calls_total` only, with a
  regression test.
- Proxy replay aborted the entire replay on one malformed audit-log line;
  now skips it with a stderr warning and replays the rest, with a regression
  test.
- `mcp-sentinel-proxy run --metrics-port` parsed as `str` while the stdio
  parser expects `int`; now `int` on both, with a regression test.
- `classify_license` fast-path typo (`"unlicense d"`); corrected to
  `"unlicensed"`.
- `SqlInjectionRule` and `SinkRule` docstrings contradicted the code
  (parameterized-form handling; nonexistent `is_sanitized` hook); rewritten
  to describe actual behavior.

### Changed

- Replaced `CLAUDE.md` with `AGENTS.md` (rewritten to describe the current
  implementation); added `docs/supply_chain.md`; fixed stale references
  (`THREAT_MODEL.md` proxy intro, `docs/architecture.md` pointers, policy
  `[""]`/dry-run semantics in `docs/policy.md`).
- CI: `upload-sarif@v3` → `v4`, `pip` caching, `pip`/`setuptools` upgraded
  before the supply-chain gate, per-job timeouts. The gate is never silenced
  with an advisory allowlist.
- Removed the unused `httpx` dev dependency.

## [0.1.0] - 2026-08-03

Initial release. All five sub-projects feature-complete.

### Added

- **Vulnerable target** (`src/vulnerable_target/`): a deliberately vulnerable 4-tool MCP server (command
  injection, SQL injection, path traversal, SSRF) plus a scripted, deterministic agent used to demonstrate
  prompt-injection-to-tool-call chaining without requiring a live LLM.
- **Scanner** (`src/scanner/`, `src/taxonomy/`): real interprocedural taint analysis (source → cross-file
  propagation → sink), structural rules (excessive tool permissions, missing rate-limiting/auth,
  prompt-injection-prone tool descriptions), terminal/JSON/SARIF output. Nine vulnerability classes mapped to
  STRIDE, OWASP Top 10, OWASP LLM Top 10, and MITRE ATT&CK in `THREAT_MODEL.md`.
- **Supply chain** (`src/supply_chain/`): hand-rolled CycloneDX 1.5 SBOM generation, `pip-audit`-backed
  dependency vulnerability scanning, license classification (permissive/copyleft/unknown) with
  word-boundary matching.
- **Runtime guardrail proxy** (`src/proxy/`): fail-closed YAML policy-as-code, per-tool containment (host
  allowlist, path-prefix allowlist, readonly-SQL heuristic) keyed off argument values, output-side
  prompt-injection detection, sliding-window rate limiting, structured JSONL audit logging, Prometheus
  `/metrics` + HTML `/dashboard`, dry-run mode, and a replay mode that re-evaluates captured traffic against
  an updated policy using real historical timestamps, without re-executing any tool. Ships as a real stdio
  MCP server (`mcp-sentinel-proxy run`) in front of the vulnerable target's four tools, with a default policy
  protecting all four.
- **CI/CD** (`.github/workflows/ci.yml`): lint (`ruff`), typecheck (`mypy`), test (`pytest`), a
  scanner-self-scan job (SARIF uploaded to GitHub code scanning, merge gate on `--fail-on critical`), a
  supply-chain job (`--fail-on-vulnerabilities`), and secret scanning (`gitleaks`).
- 169 tests across all five sub-projects, including real subprocess integration tests against the live
  `mcp-sentinel-proxy` server and a before/after demo that runs `THREAT_MODEL.md`'s flagship
  prompt-injection-to-exfiltration attack tree against the real proxy process.

### Fixed

(Found via adversarial self-review during development, each with a regression test — see `WRITEUP.md`'s
"Lessons learned" for the full story on each.)

- Path-prefix containment used a literal string prefix (`str.startswith()`), letting
  `"sandbox/files-evil/"` bypass an allowlist of `"sandbox/files"`; now segment-aware.
- Host-allowlist containment gated on `"://" in value`, letting protocol-relative URLs
  (`"//evil.com/x"`) skip SSRF containment entirely; now checks `urlparse(value).hostname` unconditionally.
- The `/dashboard` HTML view interpolated tool names (attacker-influenced strings in a general deployment)
  without escaping — a stored-XSS bug; now HTML-escaped.
- The dependency vulnerability audit resolved `pip-audit` via `PATH`, which can silently target a different
  Python environment than the one running MCP Sentinel; now invoked as `sys.executable -m pip_audit`.
- `default_policy.yaml`'s `read_file` entry (`allow_path_prefixes: ["sandbox/files"]`) denied every
  legitimate call, not just traversal attempts — the tool's own `SANDBOX_ROOT` already anchors its `path`
  argument at that directory, so a legitimate argument never carried that string prefix. Fixed to
  `allow_path_prefixes: [""]`, which activates the proxy's unconditional `..`-traversal block without
  imposing an unmatchable prefix restriction.
- Eight `mypy` findings across `taxonomy`, `supply_chain`, and `proxy` (an LSP-violating comparison-operator
  override, an `importlib.metadata` protocol misuse, a reused loop variable spanning two incompatible types,
  and an `Optional`-returning `max()` key).
