# WRITEUP.md

An interview-facing cheat sheet for MCP Sentinel: why it exists, the decisions behind it, what it trades
off, and what I'd say if someone asked me to defend any part of it. If you only read one section before an
interview, read "Design decisions and tradeoffs" — that's where the actual engineering judgment lives.

## Why I built it

Model Context Protocol servers give an LLM agent a set of tools — read a file, run a query, fetch a URL,
execute a command — and then trust the model's judgment about when to call them. That's a genuinely new
trust boundary, and I wanted to understand it by building both sides of it: a deliberately vulnerable MCP
server to see the failure modes firsthand, a static scanner to catch them before deployment, and a runtime
proxy to contain them if they ship anyway. Three angles on the same problem, not three unrelated projects.

## How it was actually built

I scoped the architecture and threat model myself, then used AI (Claude Code) extensively to accelerate
implementation — writing tests first, watching them fail for the right reason, implementing, and iterating.
I reviewed every component, ran the real test suite and real tools against real targets rather than trusting
generated code at face value, and fixed real bugs that surfaced along the way (see "Lessons learned" below —
several were found by an automated code-review pass I ran deliberately after each major commit, and I
verified each one before treating it as real). That's a credible, current way to build software in 2026, and
I'd say so plainly if asked — the judgment about what to build, what to test, and whether a finding was real
was mine throughout.

## What it actually does

Five components, each independently runnable — see [`README.md`](README.md) for the full breakdown and
[`docs/`](docs/) for per-subsystem detail:

1. A deliberately vulnerable 4-tool MCP server + scripted agent (the fixture).
2. A static scanner doing real interprocedural taint analysis (not regex) plus structural checks, with
   terminal/JSON/SARIF output.
3. Supply-chain scanning: SBOM, `pip-audit`-backed vulnerability scan, license classification.
4. A runtime guardrail proxy: fail-closed YAML policy, per-tool containment, output-side prompt-injection
   detection, rate limiting, audit logging, Prometheus metrics + dashboard, dry-run and replay modes.
5. CI/CD: the scanner's own SARIF output wired into GitHub Actions as a merge gate against its own code.

## Design decisions and tradeoffs

**Scripted agent instead of a live LLM.** `vulnerable_target/agent.py` reads a `Scenario` describing what
"the model" decides to call, rather than calling a real LLM API. This makes the prompt-injection-chaining
demo deterministic and reproducible in CI with no API key required — at the cost of not proving a *real* LLM
would actually fall for the planted instruction. I think that's the right tradeoff for a security-tooling
demo (the point is proving the guardrail *works*, not re-litigating whether LLMs are gullible), but it's a
real limitation I'd name unprompted in an interview.

**Name-matching cross-file resolution instead of a full import graph.** `scanner/project.py::load_project`
resolves cross-file function calls by matching function *names*, not by resolving actual imports. Building a
real import-resolution graph (relative vs. absolute imports, re-exports, star imports, `__init__.py`
aggregation) is a meaningfully bigger project than proving interprocedural taint tracing works at all — which
was the actual goal of sub-project 2. Two files defining a same-named function would confuse it. Documented,
not hidden.

**Regex heuristics for prompt-injection and "readonly" SQL detection, not a real parser.** Both
`injection_detector.py` and the proxy's readonly-SQL containment check are pattern-based. A sufficiently
adversarial payload can evade either. I chose heuristics deliberately over, say, wiring in a real SQL parser
or a classifier model, because the point of sub-project 4 is proving the *pipeline* — resolve policy, rate
limit, contain, execute, scan output, log, meter — works end-to-end and is the single choke point every call
passes through. Swapping in a stronger detector later doesn't change that architecture at all.

**In-process tool execution instead of hand-rolled JSON-RPC passthrough.** The original design sketch had the
proxy spawn a child MCP server process and relay raw JSON-RPC. I built `stdio_proxy.py` to call the real tool
functions in-process instead — still a distinct, real stdio MCP server process with real enforcement, just
without re-implementing MCP's wire protocol a second time for no additional security value. See the module
docstring in `src/proxy/stdio_proxy.py` for the full reasoning; I'd defend this as the right call, not a
shortcut.

**Supply-chain checks reflect the current environment, not an arbitrary target's dependency graph.** License
metadata and vulnerability data aren't available without installing a package — auditing an arbitrary target
MCP server's dependencies would require installing them into an isolated environment first. Out of scope
here; the tool audits what's actually installed in the interpreter running it. This bit me directly — see
"Lessons learned."

**`--fail-on critical`, not `--fail-on high`, for the CI scanner-self-scan gate.** Running the scanner
against its own non-fixture packages surfaces a handful of real HIGH findings that are *reviewed, not bugs*:
CLI entry points take an operator-supplied `--output`/`--policy`/`--audit-log` path, and the taint engine has
no concept of "this is a local CLI flag the invoking operator controls" versus a remote MCP tool-call
argument. Building a trust-boundary-aware taint model (so the scanner can tell those apart) is future work,
not something I wanted to fake with a suppression file. The honest interim answer is a narrower gate plus
full visibility via SARIF upload to code scanning.

## Lessons learned

**Automated review found two real, confirmed security bugs after I'd already committed working code — both
different in kind from anything a first read of the code would catch.** After committing the initial
interceptor, a review found: a path allowlist using `str.startswith()` instead of segment-aware comparison
(`"sandbox/files-evil/"` would pass an allowlist of `"sandbox/files"`), and a host-allowlist check gated on
`"://" in value` that let protocol-relative URLs (`"//evil.com/x"`) skip SSRF containment even though
`urlparse` resolves a real hostname for them. Later, a second review found stored XSS in the dashboard: tool
names (attacker-influenced strings in a general deployment) were interpolated into HTML unescaped. I verified
each one was real before fixing it — not blind trust in the tool that flagged them — then fixed all three
with regression tests. The lesson: a security tool's own code needs the same adversarial review its rules
apply to everyone else, and "the tests pass" is a necessary, not sufficient, bar.

**Building the CI supply-chain gate surfaced a real bug in a different sub-project, three days after that
sub-project shipped.** Cross-checking the vulnerability audit's output against the SBOM/license passes (78
components) showed the vuln scan reporting on 370 — because `run_dependency_audit` resolved `pip-audit` via
`shutil.which`, which found an executable installed for a *different* Python environment on the machine than
the one running MCP Sentinel. Fixed by invoking `sys.executable -m pip_audit` instead, so the audit is always
scoped to the same interpreter the rest of the report reflects. The lesson: cross-checking a tool's output
against a second, independent source of truth (here, the SBOM count) caught a bug that every existing test
had missed, because every existing test mocked `subprocess.run` and never actually exercised environment
resolution.

**A real, verified API surface beats documentation every time.** `mcp.server.MCPServer` (not
`mcp.server.fastmcp.FastMCP`, which the installed SDK version doesn't even expose), `CallToolResult.is_error`
(snake_case, not the wire protocol's camelCase `isError`), and Prometheus's exact sample-naming scheme
(`_total`, `_sum`, `_count` suffixes on a single metric family) all differed from what I'd have assumed from
memory or a quick doc skim. Verifying against the actually-installed version caught all three before they
became runtime surprises.

**Re-running the flagship attack scenario against the real proxy process (not narrating it) produced a
finding I wouldn't have guessed.** I expected the chain to break at the `read_file` path-traversal step (the
proxy's per-tool containment). It actually breaks one step earlier: the injection detector flags `fetch_url`'s
own tainted output before the agent ever sees the embedded directive, so the intended follow-up `read_file`
call never fires at all. See [`THREAT_MODEL.md`](THREAT_MODEL.md#protected-mode-where-the-runtime-proxy-breaks-this-chain).
The lesson: "the guardrail should work" and "I ran the actual attack against the actual guardrail and watched
where it stopped" are different claims, and only the second one is trustworthy.

## Future work

- **Trust-boundary-aware taint sources**, so the scanner can distinguish an operator-supplied CLI argument
  from a remote MCP tool-call argument — would remove the known false positives in the self-scan.
- **A real import graph** in `project.py`, replacing name-matching cross-file resolution.
- **A stronger prompt-injection detector** than regex heuristics — an embedding-based or small-classifier
  approach, swapped in behind the same `scan_for_injection` interface without touching the rest of the
  pipeline.
- **Distributed policy sync** across multiple proxy instances (currently single-process, in-memory metrics).
- **A real-LLM adapter** for the scripted agent, gated behind an env var, so the demo can optionally prove a
  live model actually falls for the planted instruction — never required for the core CI-run demo.

## Resume bullets (draft — rewrite before using)

These are a starting point, not a final answer — never paste AI-generated resume bullets verbatim. Rewrite
in your own voice, cut anything you can't defend in detail in an interview, and adjust for the actual role
you're applying to.

- Built a static AST-based security scanner for Model Context Protocol servers implementing real
  interprocedural taint analysis (source → cross-file propagation → sink), detecting command injection, SQL
  injection, path traversal, and SSRF with full call-chain traces; outputs SARIF for GitHub code scanning.
- Designed and implemented a runtime policy-enforcement proxy for AI agent tool calls: fail-closed YAML
  policy engine, host/path/SQL containment, output-side prompt-injection detection, rate limiting, structured
  audit logging, Prometheus metrics, and a replay mode that re-evaluates historical traffic against updated
  policy without re-executing any tool.
- Mapped 9 vulnerability classes to STRIDE, OWASP Top 10, OWASP LLM Top 10, and MITRE ATT&CK in a from-scratch
  threat model, then proved the runtime guardrail breaks a full attacker-planted-instruction-to-exfiltration
  chain against the real proxy process (not a narrated diagram).
- Wired static analysis and dependency scanning into a GitHub Actions merge gate (lint, typecheck, tests,
  SARIF-based scanner self-scan, `pip-audit`, secret scanning), with a documented, deliberately narrow gate
  threshold based on reviewing the scanner's own false positives against its own codebase.
- Found and fixed real security bugs via adversarial self-review after initial implementation, including two
  containment-check bypasses (non-segment-aware path prefix matching, a protocol-relative-URL SSRF gap) and a
  stored-XSS in an internal metrics dashboard — each verified before fixing, with regression tests added.
