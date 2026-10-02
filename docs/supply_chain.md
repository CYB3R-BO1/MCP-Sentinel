# Supply chain (`src/supply_chain/`)

Three checks combined by `report.py::generate_supply_chain_report` into one
report (the supply-chain equivalent of `scanner/scan.py` + `terminal.py`):

1. **SBOM** (`sbom.py`) — hand-rolled CycloneDX 1.5 JSON via stdlib
   `importlib.metadata`, not wrapping an external SBOM CLI (avoids tool
   version-drift). Two entry points: `generate_sbom_for_environment()` (the
   current interpreter's installed distributions) and
   `generate_sbom_for_requirements(path)` (exactly-pinned `name==version`
   lines only; anything else is skipped, not guessed).
2. **Vulnerability scan** (`vuln_scan.py`) — thin wrapper over `pip-audit`
   (PyPA's scanner, backed by OSV/PyPI advisories). Invoked as
   `sys.executable -m pip_audit`, never via `PATH`: resolving a `pip-audit`
   executable via `PATH` can find one installed for a *different* Python
   environment, silently auditing the wrong one (a real discrepancy seen on a
   multi-Python machine). `summarize_pip_audit_payload` is a pure function
   over canned JSON so tests run offline; only `run_dependency_audit` spawns
   the subprocess (timeout 300 s; exit 0 = clean, 1 = vulns found, anything
   else = `PipAuditFailed`).
3. **License classification** (`license_check.py`) — heuristic
   permissive/copyleft/unknown over installed distributions, using
   word-boundary regex (not substring matching) and preferring trove
   `Classifier` entries over the free-text `License` field. "Unknown" means
   "needs a human to check", not "definitely a problem" — it is reported
   separately from copyleft for exactly that reason, and nothing here is
   legal advice.

## Failure handling

`generate_supply_chain_report` degrades *every* audit failure mode —
`PipAuditNotAvailable` (tool not installed), `PipAuditFailed` (bad exit code,
non-JSON output), `subprocess.TimeoutExpired` — to
`{"dependency_audit": {"error": ...}}`, never crashing the CLI. The terminal
renderer prints `unavailable (<reason>)` for that case. Keep both regression
tests in `tests/supply_chain/test_report.py` passing.

## Scope boundary: which environment is actually audited

SBOM and the vulnerability scan honor `--requirements` (a pinned file audits
exactly those pins); `check_licenses()` **always scans the current
environment**. License metadata and advisory data don't exist without
installing a package, so faithfully auditing a *different* project's supply
chain means installing its dependencies into an isolated environment first —
out of scope for this tool. Concretely: **run
`mcp-sentinel-supply-chain` inside the environment you want audited** (a
clean venv containing only the target's dependencies), not inside a
general-purpose dev environment — otherwise the report, and a
`--fail-on-vulnerabilities` gate, reflects unrelated tooling too.

## CI gate integrity

The `supply-chain` CI job upgrades `pip`/`setuptools` before gating on
`--fail-on-vulnerabilities`, so the gate reflects project dependencies, not a
stale runner bootstrap. Never silence this gate with an advisory allowlist:
fix or isolate the environment instead. An explicit advisory exception is
only acceptable with a documented, unavoidable reason, narrowly scoped to
specific advisory IDs.
