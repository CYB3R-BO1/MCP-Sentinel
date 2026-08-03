# Architecture

MCP Sentinel is five independently runnable components that share one data model (the taxonomy) and one
test fixture (the vulnerable target). This doc explains how they connect; see [`scanner.md`](scanner.md) and
[`proxy.md`](proxy.md) for a deep dive on the two components with real analysis logic.

## The shared spine: `src/taxonomy/`

Every vulnerability class MCP Sentinel knows about — whether caught by the static scanner or the runtime
proxy — has one `TaxonomyEntry` in `src/taxonomy/registry.py`, keyed by a stable `rule_id` (`MCP-SENT-001`
through `MCP-SENT-009`). Each entry carries the STRIDE category, OWASP Top 10 mapping (where a classic
web-app category applies), OWASP LLM/Agentic Top 10 mapping, a MITRE ATT&CK technique (where a real one
applies), and a default `Severity`. Findings from the scanner and denials from the proxy both carry a
`rule_id` that resolves to the same entry — so "what does `MCP-SENT-003` mean" has exactly one answer
anywhere in the codebase. `THREAT_MODEL.md` is the human-readable rendering of this table, with a row per
class and a "Detected by" / "Blocked by" column.

## Sub-project 1: the vulnerable target (`src/vulnerable_target/`)

Not a real product — the fixture everything else is built and evaluated against. Four tools, one
vulnerability class each: `read_file` (path traversal), `query_db` (SQL injection via string interpolation),
`run_command` (shell injection via `shell=True`), `fetch_url` (SSRF, no host allowlist). `permissions.py`
declares each tool's scope deliberately wider than the tool needs — a fifth vulnerability class (excessive
agency) that the *structural* rules catch, not the taint engine. `agent.py` is a scripted, deterministic
agent (reads a `Scenario` describing what "the model" decides to call) rather than a live LLM — reproducible
in CI, no API key required. `scenarios/prompt_injection_chaining.py` is the flagship end-to-end scenario used
in the README demo and `THREAT_MODEL.md`'s attack tree.

## Sub-project 2: the scanner (`src/scanner/`)

Two independent analysis passes, combined in `scan.py::run_scan`: an interprocedural taint engine
(`taint/engine.py`) for the four data-flow vulnerability classes, and structural rules
(`structural_rules/*.py`) for the two classes that don't need taint tracing. See [`scanner.md`](scanner.md).

## Sub-project 3: supply chain (`src/supply_chain/`)

Three checks combined by `report.py`: an SBOM (`sbom.py`, hand-rolled CycloneDX 1.5 JSON via
`importlib.metadata` — not wrapping an external SBOM CLI, to avoid tool version-drift), a dependency
vulnerability scan (`vuln_scan.py`, wraps `pip-audit` via `subprocess`), and license classification
(`license_check.py`, word-boundary regex, trove classifiers preferred over free-text `License` fields).

**Deliberate scope boundary**: all three checks reflect the *current Python environment's* installed
distributions, not a resolved dependency graph for an arbitrary target's `requirements.txt` you don't have
installed. License metadata and audit data aren't available without installing a package, so accurately
checking a target MCP server's supply chain would require installing its dependencies into an isolated
environment first — out of scope here. In practice this means: run `mcp-sentinel-supply-chain` inside the
environment you actually care about (a clean venv with only that project's dependencies installed), not
inside a general-purpose dev environment that also has unrelated tooling installed — otherwise the report
(and a `--fail-on-vulnerabilities` CI gate) reflects that unrelated tooling too. This is a real thing we hit
while building the CI workflow — see the `supply-chain` job discussion in [`../CLAUDE.md`](../CLAUDE.md).

## Sub-project 4: the runtime guardrail proxy (`src/proxy/`)

`interceptor.py::ProxyEngine.handle_tool_call` is the single choke point every tool call passes through. See
[`proxy.md`](proxy.md) for the full pipeline and [`policy.md`](policy.md) for the YAML schema it enforces.

## Sub-project 5: CI/CD (`.github/workflows/ci.yml`)

Six jobs: `lint`, `typecheck`, `test`, `scanner-self-scan` (SARIF uploaded to GitHub code scanning, merge
gate on `--fail-on critical`), `supply-chain` (`--fail-on-vulnerabilities`, run against a fresh install of
just this project's own extras — see the scope-boundary note above for why that matters), and `secret-scan`
(gitleaks). `scanner-self-scan` deliberately excludes `vulnerable_target/`, since it's a fixture that's
*supposed* to contain those vulnerability classes.

## A known, documented limitation: name matching, not an import graph

`scanner/project.py::load_project` resolves cross-file function calls by **matching function names**, not by
building a real import graph. If two files define a function with the same name, the taint engine can follow
a call to the wrong one. This is a real limitation, not an oversight — building a full import-resolution
graph is a meaningfully larger project (relative vs. absolute imports, re-exports, `__init__.py` aggregation,
star imports) that wasn't justified for a scanner whose primary goal is proving the taint-tracing *technique*
works interprocedurally at all. It's called out here, in code comments, and in `WRITEUP.md` rather than
silently left for someone to discover.
