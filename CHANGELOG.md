# Changelog

All notable changes to this project are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
- Eight `mypy` findings across `taxonomy`, `supply_chain`, and `proxy` (an LSP-violating comparison-operator
  override, an `importlib.metadata` protocol misuse, a reused loop variable spanning two incompatible types,
  and an `Optional`-returning `max()` key).
