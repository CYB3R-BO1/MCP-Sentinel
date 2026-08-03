# Contributing to MCP Sentinel

Thanks for considering a contribution. This project follows a fairly strict test-first workflow — the
sections below explain what that means in practice.

## Setup

```bash
git clone https://github.com/CYB3R-BO1/AppSec-Project-1.git
cd AppSec-Project-1
pip install -e ".[dev,supply-chain,proxy]"
```

## Before you open a PR

```bash
pytest                                # all tests must pass
ruff check .                          # lint must be clean
mypy src --ignore-missing-imports     # typecheck must be clean
```

All three run in CI (`.github/workflows/ci.yml`) and are required to merge, along with a scanner self-scan
(fails only on CRITICAL findings — see the note in that workflow file for why) and a supply-chain check.

## Workflow

- **Test-driven development.** Write the test, watch it fail for the right reason, implement, watch it pass,
  then commit. This isn't a style preference here — several real bugs in this codebase (see `WRITEUP.md`'s
  "Lessons learned") were caught specifically because a test was written against the intended behavior
  *before* the implementation existed, not fitted to whatever the code happened to do.
- **Commit incrementally.** One logical change per commit, each one green (tests pass, lint clean) before the
  next. Don't batch unrelated changes into one commit.
- **No new planning docs per change** unless the architecture materially changes. The master design doc
  (`docs/superpowers/specs/2026-08-02-mcp-sentinel-design.md`) and `CLAUDE.md` already cover cross-cutting
  decisions; update those in place rather than adding a new doc that will drift out of sync.
- **Verify third-party API surfaces directly** rather than assuming from documentation, especially for the
  `mcp` SDK, `pip-audit`'s JSON schema, and `prometheus_client`'s sample-naming — this project has hit real,
  non-obvious discrepancies between docs and actual installed behavior more than once (see `CLAUDE.md`).

## Where things live

See [`docs/architecture.md`](docs/architecture.md) for how the five sub-projects fit together, and
[`docs/scanner.md`](docs/scanner.md) / [`docs/proxy.md`](docs/proxy.md) for the two components with real
analysis logic. `CLAUDE.md` is the single source of truth for architectural conventions — if you're unsure
where something belongs, check there first.

## Adding a new vulnerability class

1. Add a `TaxonomyEntry` to `src/taxonomy/registry.py` with a new `rule_id` (`MCP-SENT-0NN`), mapped to
   STRIDE / OWASP / OWASP-LLM / MITRE ATT&CK where applicable.
2. Add a row to `THREAT_MODEL.md`'s table.
3. If it's statically detectable: add a `SinkRule` (data-flow) or a structural rule
   (`src/scanner/structural_rules/`), with tests in `tests/scanner/`.
4. If it's runtime-only (a decision-loop behavior, not a data-flow pattern): extend `src/proxy/` instead, with
   tests in `tests/proxy/`.
5. If you added a genuinely new vulnerable pattern to `vulnerable_target` to demonstrate it, add a
   corresponding `tests/vulnerable_target/` test proving the exploit works against the fixture.

## Reporting security issues in this project itself

See [`SECURITY.md`](SECURITY.md) — and note the scope carve-out for `vulnerable_target`, which is
intentionally insecure.

## Code of conduct

Be direct, be kind, assume good faith. Disagreements about design get resolved with evidence (a failing
test, a benchmark, a cited source) rather than seniority.
