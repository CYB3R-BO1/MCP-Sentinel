# AGENTS.md

Guidance for coding agents working in this repository. (Replaces the former
`CLAUDE.md`; preserved content was rewritten to describe the current
implementation, obsolete passages removed.)

## What this is

MCP Sentinel: a security scanner and runtime guardrail platform for Model
Context Protocol (MCP) servers and tool-calling AI agents. Five sub-projects:

1. **`src/vulnerable_target/`** — a deliberately vulnerable multi-tool MCP
   server + scripted agent, used as the fixture the other components are
   tested against. Not a real product; it's the "victim" for demos.
2. **`src/scanner/` + `src/taxonomy/`** — a static AST-based security scanner
   (real interprocedural taint analysis, not regex).
3. **`src/supply_chain/`** — SBOM generation, dependency vulnerability
   scanning (via `pip-audit`), and license classification.
4. **`src/proxy/`** — a runtime guardrail proxy: YAML policy-as-code
   enforcement, prompt-injection detection on tool output, rate limiting,
   structured audit logging, Prometheus metrics + HTML dashboard, dry-run and
   replay modes, all in front of `vulnerable_target`'s tools.
5. **`.github/workflows/ci.yml`** — GitHub Actions: lint (`ruff`), typecheck
   (`mypy`), `pytest`, a scanner-on-self job (SARIF uploaded to code
   scanning, merge gate on `--fail-on critical`), a supply-chain job
   (`--fail-on-vulnerabilities`), and secret scanning (`gitleaks`).

Master design doc: `docs/superpowers/specs/2026-08-02-mcp-sentinel-design.md`.
Threat model with a STRIDE/OWASP/OWASP-LLM/MITRE-ATT&CK table (one row per
vulnerability class, mapped to the scanner rule that detects it, where
applicable): `THREAT_MODEL.md`.

## Commands

```bash
# Install (editable, with dev + supply-chain + proxy extras)
pip install -e ".[dev,supply-chain,proxy]"

# Run all tests
pytest

# Run a single test file / test
pytest tests/scanner/test_engine_interprocedural.py
pytest tests/scanner/test_engine_interprocedural.py::test_name_of_test -v

# Lint
ruff check .

# Type check
mypy src --ignore-missing-imports

# Run the static scanner against a target directory
mcp-sentinel-scan <path> --format terminal|json|sarif [--output FILE] [--fail-on SEVERITY]

# Run supply-chain checks (SBOM + license check + pip-audit)
mcp-sentinel-supply-chain [--requirements FILE] [--format terminal|json] [--skip-vuln-scan] \
    [--fail-on-vulnerabilities] [--fail-on-copyleft]

# Run the guardrail proxy as a stdio MCP server (spawn it the same way vulnerable_target/server.py is spawned)
mcp-sentinel-proxy run [--policy FILE] [--audit-log FILE] [--metrics-port PORT]

# Replay a captured audit log against a (possibly updated) policy without executing any tool
mcp-sentinel-proxy replay --audit-log FILE --policy FILE [--format terminal|json] [--fail-on-change]
```

Exit codes for all three CLIs: `0` = clean, `1` =
findings/fail-on threshold triggered, `2` = usage/input error.

## Architecture

### Scanner (`src/scanner/`)

Two independent analysis passes are combined in `scan.py::run_scan(root) ->
list[Finding]`, then sorted and formatted:

- **Sink rules** (`rules/*.py`, subclass `SinkRule` from `rules/base.py`) —
  one rule per sink category (command injection, SQL injection, path
  traversal, SSRF). Each declares which calls are "sinks" and which argument
  (or, for path traversal, the *receiver* of a method call like
  `.read_text()`) must not be tainted. Note: `SqlInjectionRule` skips the
  DB-API parameterized form `execute(query, params)` entirely — a
  pathological caller splicing input into the query string itself is a
  documented false-negative trade-off (see the rule docstring).
- **Taint engine** (`taint/engine.py::analyze_project`) — does the actual
  interprocedural taint tracing: source (function parameter) → propagation
  (assignment, f-strings, path joins, cross-file calls up to `max_depth`) →
  sink (as declared by the sink rules above). Handles `with`/`async with`
  specially: `open(...)` / `urlopen(...)` calls live in
  `With.items[i].context_expr`, not the block body, and chained calls
  (`conn.execute(q).fetchall()`) require checking the *receiver* of the
  outer call, not just its args — both were real bugs found via testing, not
  obvious from a first read of `ast`.
- **Structural rules** (`structural_rules/*.py`, subclass a base in
  `structural_rules/base.py`) — pattern checks that don't need taint tracing:
  excessive tool permissions, missing rate-limiting/auth, tool descriptions
  vulnerable to prompt-injection. Note: permission manifests are commonly
  declared as `ast.AnnAssign` (`X: dict[...] = {...}`), not plain
  `ast.Assign` — rules that scan assignments must handle both.
- **`project.py::load_project`** resolves cross-file function calls by
  **name matching**, not a full import graph — a known, documented
  limitation, not an oversight.
- Findings carry a `rule_id` (e.g. `MCP-SENT-005`) that maps to a
  `TaxonomyEntry` in `src/taxonomy/registry.py`, shared with the runtime proxy
  so both components speak the same vulnerability IDs. No new `rule_id` may be
  introduced without a matching `TAXONOMY` entry — reuse the closest existing
  category instead (e.g. unregistered-tool denials map to `MCP-SENT-001`,
  least privilege; see `proxy/interceptor.py`).
- Output formatters (`output/{terminal,json_output,sarif}.py`) are pure
  functions over `list[Finding]`; SARIF targets 2.1.0 for GitHub code
  scanning.

### Supply chain (`src/supply_chain/`)

- `sbom.py` — hand-rolled CycloneDX 1.5 JSON via `importlib.metadata` (not
  wrapping an external SBOM CLI, to avoid tool version-drift). Can target
  either the current environment or an exactly-pinned `requirements.txt`.
- `vuln_scan.py` — wraps `pip-audit` via `subprocess` invoked as
  `sys.executable -m pip_audit` (never via `PATH`, which can resolve to a
  different Python environment); `summarize_pip_audit_payload` is a pure
  function (unit-tested against canned JSON, no live network in tests)
  separate from the subprocess-invoking `run_dependency_audit`.
- `license_check.py` — classifies each installed distribution as
  permissive/copyleft/unknown. Uses **word-boundary regex**, not substring
  matching (short keywords like `mit`, `isc`, `mpl` are substrings of
  ordinary English words — `limitation`, `discussed`, `example` — and some
  packages dump full license text into the `License` metadata field).
  Prefers trove `Classifier` entries over the free-text `License` field when
  both exist. If you touch this file, keep the regression test in
  `tests/supply_chain/test_license_check.py`
  (`test_short_keywords_do_not_false_positive_...`) passing.
- `report.py` combines all three into one report; `cli.py` exposes
  `--fail-on-vulnerabilities` / `--fail-on-copyleft` gates for CI use.
  `report.py` degrades *all* audit failures (`PipAuditNotAvailable`,
  `PipAuditFailed`, `subprocess.TimeoutExpired`) to `{"error": ...}`,
  never crashing the CLI — keep both regression tests in
  `tests/supply_chain/test_report.py` passing. Scope boundary (see
  `docs/supply_chain.md`): SBOM + vuln-scan honor `--requirements`, but
  `check_licenses()` always scans the current environment — run inside a
  clean venv containing only the target's dependencies.
- `docs/supply_chain.md` is the per-subsystem deep dive for this component.

### Vulnerable target (`src/vulnerable_target/`)

A fixture MCP server, not a real product. `permissions.py` declares each
tool's intended scope (`TOOL_PERMISSIONS`) deliberately wider than the tool
needs — this over-scoping is itself one of the things the scanner's
structural rules detect. `tools/*.py` each contain one intentionally
vulnerable tool function (command injection, SQL injection, path traversal,
SSRF). `agent.py` is a scripted, deterministic agent (not a live LLM) that
naively obeys `SYSTEM:`-style instructions embedded in tool output, used to
demonstrate prompt-injection chaining. `scenarios/*.py` define reusable attack
scenarios (`Scenario` dataclass); `benign.py` fetches the sensitive endpoint
but without a planted directive, so it proves "one intended call, no
chaining" (see its header comment). Built on `mcp.server.MCPServer` (the API
this installed `mcp` SDK version actually exposes — not
`mcp.server.fastmcp.FastMCP`, which doesn't exist here). Some `run_command`
tests are skipped on Windows
(`@pytest.mark.skipif(sys.platform.startswith("win"), ...)`).

### Runtime guardrail proxy (`src/proxy/`)

`interceptor.py::ProxyEngine.handle_tool_call` is the single choke point every
tool call passes through: resolve the tool's policy → rate limit → generic
argument containment (host allowlist, path-prefix allowlist, readonly-SQL
heuristic — all keyed off argument *values*, not hardcoded argument names, so
it's not tied to `vulnerable_target`'s four tools specifically) → execute the
real tool → scan output with `injection_detector.py` → audit-log
(`audit_log.py`, JSONL) + Prometheus-record (`metrics.py`) the final decision.
`policy.dry_run` never withholds real output/execution — it only stops a
denial from suppressing the result, so the proxy can run in report-only mode
before being trusted to block. Dry-run denials are recorded in the audit log
and `tool_calls_total{allowed="False"}` but deliberately *not* in
`policy_denials_total` (they are would-block observations, not real blocks).
`policy.py` loads YAML via pydantic and is **fail-closed**: a missing file,
bad YAML, or a schema error all fall back to the maximally restrictive default
policy, never to "allow everything" — use `load_policy_fail_closed`, not
`load_policy`, outside tests. A policy-allowed call to a tool with no
registered executor is denied fail-closed as `MCP-SENT-001` (least privilege:
request exceeds granted agency), never a `KeyError` — see the comment in
`handle_tool_call` and keep both regression tests in
`tests/proxy/test_interceptor.py` passing.

`ToolPolicy.allow_path_prefixes` has three meanings (`None` = no path check;
`[""]` = `..`-traversal check only, no prefix restriction — the empty string
is the identity prefix; `["a/b"]` = traversal check plus segment-aware prefix
restriction). See the `ToolPolicy` docstring, `docs/policy.md`, and the
`default_policy.yaml` comment. Do not redesign this schema without updating
all three.

`stdio_proxy.py` is a real stdio MCP server (`mcp-sentinel-proxy run`) that
re-registers `vulnerable_target`'s four tools and routes each call through
`ProxyEngine` before delegating to the real tool implementation in
`vulnerable_target/tools/`. This deviates from the original design doc (which
sketched hand-rolling JSON-RPC passthrough to a spawned child server) in
favor of calling the real tool functions in-process — still a distinct
process with real enforcement, just without re-implementing MCP's wire
protocol a second time; see the module docstring for the full rationale. A
blocked call raises `ToolBlockedError`, which the MCP SDK surfaces to the
client as `isError=True`, not a silent empty response. `--metrics-port` is
`int`-typed on both CLIs (`proxy/cli.py` forwards it stringified to the
stdio parser).

Two generic containment checks had real bypasses found by an automated review
after their first commit (see git history around `fix(proxy): close three
containment-check bypasses`): the path allowlist must be segment-aware
(`_is_within_prefix`), not `str.startswith()` (`"sandbox/files-evil/"` would
otherwise pass an allowlist of `"sandbox/files"`); the host-allowlist check
must not gate on `"://" in value` (protocol-relative URLs like `"//evil.com/x"`
still resolve a real hostname under `urlparse` and would otherwise skip SSRF
containment entirely). Keep both regression tests in
`tests/proxy/test_interceptor.py` passing if you touch `_check_containment`.

`replay.py::replay_audit_log` re-evaluates a captured JSONL audit log's access
decisions against a new policy, using each record's *actual recorded
timestamp* for rate-limit replay (not "all at once") and the exact same
`evaluate_access()` function `ProxyEngine` calls live — factored out
specifically so replay can't silently drift from live behavior. It does not
replay injection detection, since the audit log doesn't store raw tool output.
Malformed lines are skipped with a stderr warning, never aborting the replay
(keep `test_replay_skips_malformed_lines_instead_of_aborting` passing).
`changed` compares `allowed` only; dry-run is a deployment mode, not part of
the allow/deny diff (see the function docstring).

`vulnerable_target/agent.py::run_scenario` takes optional `command`/`args`
(default: unchanged, spawns `vulnerable_target.server`) so the same
scripted-agent scenarios can be pointed at `proxy.stdio_proxy` instead — this
is how `tests/proxy/test_protected_mode_demo.py` re-runs THREAT_MODEL.md's
flagship attack tree in "protected mode." That test found the real chain-break
point is *earlier* than the obvious guess: the injection detector flags
`fetch_url`'s own tainted output before the agent ever sees the embedded
directive, so the naive follow-up `read_file` call never happens at all — see
the "Protected mode" subsection under the attack tree in `THREAT_MODEL.md`.

### CI/CD (`.github/workflows/ci.yml`)

Six jobs, all on `ubuntu-latest`: `lint`, `typecheck`, `test`,
`scanner-self-scan`, `supply-chain`, `secret-scan`.
`scanner-self-scan` runs `mcp-sentinel-scan` against `src/scanner`, `src/proxy`,
`src/supply_chain`, and `src/taxonomy` — deliberately **not**
`src/vulnerable_target`, which is a test fixture that is supposed to contain
the vulnerability classes `tests/scanner` asserts against; gating a merge on
findings there would be nonsensical. That self-scan surfaces a few known,
reviewed findings that are not bugs: the three CLI entry points
(`scanner/cli.py`, `supply_chain/cli.py`, `proxy/cli.py`) take an
operator-supplied `--output`/`--policy`/`--audit-log` path and read/write it
directly — the taint engine has no concept of "this is a local CLI flag the
invoking operator controls," not a remote MCP tool-call argument, so it
correctly (from a pure data-flow view) flags a path-traversal sink; and one
MEDIUM finding in `stdio_proxy.py` where the structural rate-limit check
can't see that rate limiting is actually enforced one file away in
`interceptor.py` — a real instance of the scanner's documented name-matching
(not full import graph) limitation. Because of those known findings, the job
doesn't fail the build on HIGH severity — it fails only on
`--fail-on critical` (SQL/command injection have zero legitimate reason to
appear in Sentinel's own code) — while still uploading full SARIF results
(including the known HIGHs) to GitHub code scanning so they stay visible on
every PR diff. The `supply-chain` job upgrades `pip`/`setuptools` before
gating on `--fail-on-vulnerabilities` so the gate reflects project
dependencies, not a stale runner bootstrap — never silence it with an
advisory allowlist (see `docs/supply_chain.md`).

## Working conventions for this repo

- No new high-level planning doc per sub-project unless the architecture
  materially changes — the master design doc in `docs/superpowers/specs/`
  already covers cross-cutting decisions (Python 3.10+, `src/` layout, stdlib
  `ast` over an external SAST framework, hand-rolled SBOM/CycloneDX, scripted
  agent over live LLM).
- TDD: write the test, confirm it fails for the right reason, implement,
  confirm it passes, commit.
- Commit incrementally as each piece is verified working — don't batch
  unrelated changes.
- **Never `git push`** — commits are made locally only; the repo owner pushes
  to GitHub themselves.
- Before trusting an external tool's output format (`pip-audit`, the `mcp`
  SDK, etc.), verify the real installed version's actual behavior/schema
  rather than assuming from docs — this has caught real discrepancies before
  (see `mcp.server.MCPServer` vs. `FastMCP` above).
- Avoid churn that does not materially improve correctness, maintainability,
  or explainability. Don't refactor working code merely to look cleaner; keep
  diffs small with a concrete reason per change.
