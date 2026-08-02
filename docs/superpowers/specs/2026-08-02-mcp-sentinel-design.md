# MCP Sentinel — Master Design & Decomposition

Status: approved-by-directive (owner explicitly delegated all decisions; see
"Assumptions" below). This doc is the single reference for architecture
decisions across all sub-projects. Each sub-project also gets its own
implementation plan via the writing-plans flow.

## 1. What we're building

MCP Sentinel is a security platform for Model Context Protocol (MCP) servers
and tool-calling agents, made of five components (per the owner's brief):

1. A deliberately vulnerable multi-tool MCP server + agent harness (the
   target everything else is built and evaluated against).
2. A static scanner doing real taint analysis (source → propagation → sink →
   sanitizer), not regex matching, with terminal/JSON/SARIF output.
3. Supply-chain checks (SBOM, dependency vuln scan, license check).
4. A runtime guardrail proxy enforcing YAML policy-as-code, detecting
   injection in tool output, rate-limiting, audit logging, metrics.
5. CI/CD integration wiring the scanner's SARIF into GitHub Actions as a
   merge gate, plus baseline SAST/secret scanning on Sentinel's own code.

## 2. Why decompose instead of one big build

This is five largely independent subsystems plus a full docs/release
package. Building it as a single undifferentiated effort risks an untestable
monolith. Instead each component becomes its own sub-project with its own
implementation plan, built and merged in sequence, in this order:

1. **sub-project-1**: repo scaffold + `THREAT_MODEL.md` skeleton +
   vulnerable target (component 1). Everything downstream is scanned
   against or protects this.
2. **sub-project-2**: static taint-analysis scanner (component 2), run
   against the vulnerable target, `THREAT_MODEL.md` filled in with concrete
   finding→STRIDE/OWASP/ATT&CK mappings.
3. **sub-project-3**: supply-chain checks (component 3).
4. **sub-project-4**: runtime guardrail proxy + metrics (component 4),
   protected-mode demo against the same vulnerable target.
5. **sub-project-5**: CI/CD integration + doc/release polish (component 5 +
   deliverables list).

Each sub-project is independently testable and shippable; later ones import
the taxonomy/types defined in earlier ones but not vice versa.

## 3. Cross-cutting architecture decisions (apply to all sub-projects)

These are decisions made unilaterally per the owner's explicit instruction
not to be interrupted with questions. Each is logged with its rationale so
it can be revisited later if wrong.

- **Language: Python 3.10+, single language across all components.**
  Rationale: the official MCP SDK is first-class in Python; Python's `ast`
  module gives us a real parser/CFG substrate for the taint engine without
  hand-rolling one; FastAPI covers both the proxy and the dashboard; one
  language keeps the repo maintainable for a small/solo OSS project.
  TypeScript was the alternative — rejected only because splitting the
  taint engine's target language from the implementation language would
  double the parsing surface for no benefit at this scope.
- **Repo layout: single monorepo**, one Python package per component under
  `src/`, a shared `mcp_sentinel_taxonomy` package for the STRIDE/OWASP/ATT&CK
  mapping so the scanner and proxy reference identical finding IDs.
  ```
  src/
    vulnerable_target/   # component 1
    scanner/              # component 2
    supply_chain/         # component 3
    proxy/                 # component 4
    taxonomy/              # shared finding taxonomy (used by 2 and 4)
  tests/ (mirrors src/)
  docs/
  .github/workflows/
  ```
- **Vulnerable target's "agent":** a deterministic, scriptable tool-calling
  loop (`vulnerable_target/agent.py`) that reads a scenario file describing
  what "the model" decides to call, rather than requiring a live LLM API
  key. Rationale: the constraint says no real secrets and the demo must be
  reproducible in CI/offline; a live LLM call would make the before/after
  demo flaky and require an API key the grader may not have. An optional
  adapter for a real Claude API call is added later as a stretch, gated
  behind an env var, never required for the core demo.
- **MCP transport:** stdio subprocess (the standard MCP transport), so the
  proxy sub-project can sit as a real man-in-the-middle stdio process
  between agent and server — matching how MCP actually deploys, not a
  simulated HTTP shim.
- **Scanner scope:** targets Python MCP-SDK-based servers via static AST
  analysis (own vulnerable target is the primary, always-passing test
  fixture; scanner is written generically enough to run against any
  Python MCP server, but multi-language support is explicitly out of
  scope — logged in WRITEUP.md).
- **Supply-chain tooling:** wrap established OSS tools rather than
  reimplement dependency databases: `cyclonedx-py` (SBOM), `pip-audit`
  (vuln scan against OSV/PyPI advisory data), `pip-licenses` (license
  check). Sentinel's own code here is the orchestration + unified
  JSON/terminal report + severity gate, not the vulnerability database.
- **Runtime proxy:** FastAPI app process that spawns the real MCP server as
  a subprocess and speaks stdio JSON-RPC on both sides, applying policy
  before forwarding tool calls and scanning tool results before they
  return to the agent. Exposes `/metrics` (Prometheus text format) and a
  minimal `/dashboard` HTML page reading the same in-memory counters.
- **Policy config:** YAML, loaded with `pydantic` models for validation
  (fail closed — invalid/missing policy denies by default rather than
  silently allowing).
- **Testing:** `pytest` throughout; taint engine and policy engine get unit
  tests with intentionally crafted vulnerable/safe code samples; proxy gets
  integration tests that actually spawn the vulnerable target and assert
  attacks are blocked (not mocked) — this directly satisfies the "actually
  demonstrates a blocked attack, not narrated" definition of done.
- **CI:** GitHub Actions, `ruff` + `mypy` + `pytest` + scanner-on-self (SARIF
  upload to code scanning) + `pip-audit`/`gitleaks` as baseline hygiene,
  merge gate fails on high/critical scanner findings introduced by a PR.

## 4. Non-goals (recorded now, elaborated in WRITEUP.md)

- No multi-language (JS/TS) MCP server scanning.
- No live network egress anywhere, including in the vulnerable target — the
  "SSRF-capable fetch tool" fetches against a local mock HTTP server started
  in-process/in-Docker, never the real internet.
- No distributed/multi-tenant policy sync — proxy is single-process,
  single-policy-file, matching the scope of a demo/reference platform, with
  the production-scale gap called out explicitly in WRITEUP.md.
- No eBPF or kernel-level enforcement — proxy enforcement is at the MCP
  protocol layer only, also called out as a scale gap in WRITEUP.md.

## 5. Immediate next step

Proceed to `writing-plans` for **sub-project-1**: repo scaffold,
`THREAT_MODEL.md` skeleton (STRIDE table with rows to be completed as
scanner/proxy are built), and the vulnerable target MCP server + scripted
agent harness demonstrating all five listed vulnerability classes, each
with a passing test that proves the vulnerability is real (e.g. an actual
path traversal read outside the sandbox root, an actual SSRF hit against
the local mock server from attacker-controlled content).
