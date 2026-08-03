# Scanner (`src/scanner/`)

Two independent analysis passes are combined in `scan.py::run_scan(root) -> list[Finding]`, then sorted by
`(file_path, line, rule_id)` and handed to an output formatter.

## Sink rules (taint analysis)

`rules/*.py`, each a subclass of `SinkRule` (`rules/base.py`), one per sink category: command injection, SQL
injection, path traversal, SSRF. Each rule declares which calls are "sinks" and which argument — or, for path
traversal, the *receiver* of a method call like `.read_text()` — must not be tainted for the call to be safe.

The actual interprocedural tracing lives in `taint/engine.py::analyze_project`: source (a function parameter)
→ propagation (assignment, f-strings, `Path.joinpath`/`/` composition, cross-file calls up to a
`max_depth`) → sink (as declared by the rule above). Two behaviors here came from real bugs found via
testing, not from a first read of the `ast` docs:

- **`with`/`async with` blocks are special-cased.** `open(...)` / `urlopen(...)` calls inside a `with` live in
  `With.items[i].context_expr`, not the block body — a naive walk of the body misses them entirely.
- **Chained calls need the receiver checked, not just the outer call's args.** `conn.execute(q).fetchall()`
  is a call to `.fetchall()` whose *receiver* (`conn.execute(q)`) is the thing that actually matters; checking
  only the outer call's arguments (there are none) would report no finding at all.

## Structural rules

`structural_rules/*.py`, pattern checks that don't need taint tracing:

- **Excessive tool permissions** — a tool's declared scope (e.g. `fs:read:*`, `net:http:*`) is wider than
  its stated purpose.
- **Missing rate-limiting/auth** — a file registers `.tool()` endpoints with no rate-limit or auth construct
  visible anywhere in that file.
- **Tool descriptions vulnerable to prompt injection** — instruction-like phrasing in a `.tool()`-decorated
  docstring, which an agent that reads tool descriptions into its context could be steered by.

One easy-to-miss detail: permission manifests are commonly declared as `ast.AnnAssign`
(`X: dict[...] = {...}`), not plain `ast.Assign` — any rule scanning assignments has to handle both, or it
silently sees nothing.

## `project.py::load_project`

Resolves cross-file function calls by **name matching**, not a full import graph. Documented as a known
limitation in [`architecture.md`](architecture.md#a-known-documented-limitation-name-matching-not-an-import-graph),
not an oversight.

## Taxonomy and output

Findings carry a `rule_id` (e.g. `MCP-SENT-005`) that maps to a `TaxonomyEntry` in
`src/taxonomy/registry.py` — shared with the runtime proxy, so both components speak the same vulnerability
IDs. `output/{terminal,json_output,sarif}.py` are pure functions over `list[Finding]`; the SARIF formatter
targets 2.1.0, the version GitHub code scanning consumes.

## What the scanner is not

It's an AST-based data-flow scanner, not a full SAST framework: no cross-package import resolution (see
above), no path-sensitivity (it doesn't know an `if` branch makes a sink unreachable), no sanitizer
allowlisting beyond what's directly visible in the traced call chain. Its job is to prove interprocedural
taint tracing works end-to-end against a real, deliberately-vulnerable target — not to replace a mature
commercial SAST tool.
