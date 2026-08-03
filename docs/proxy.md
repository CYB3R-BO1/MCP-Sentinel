# Runtime guardrail proxy (`src/proxy/`)

## The pipeline

`interceptor.py::ProxyEngine.handle_tool_call` is the single choke point every tool call passes through:

1. **Resolve the tool's policy** from the loaded `Policy` (`policy.py`).
2. **Rate limit** — a sliding-window limiter (`rate_limiter.py::SlidingWindowRateLimiter`, backed by
   `collections.deque`, with an injectable clock for deterministic tests).
3. **Generic argument containment** (`_check_containment`) — host allowlist, path-prefix allowlist, and a
   readonly-SQL heuristic, all keyed off **argument values**, not hardcoded argument names. This is what
   makes containment reusable across arbitrary tools instead of being wired to `vulnerable_target`'s four
   specifically.
4. **Execute the real tool.**
5. **Scan the output** with `injection_detector.py::scan_for_injection` — regex-based heuristics generalizing
   `vulnerable_target`'s naive `"SYSTEM:"` trigger detection.
6. **Audit-log and Prometheus-record the final decision** — `audit_log.py` (JSONL, one record per call) and
   `metrics.py` (`ProxyMetrics`, its own `CollectorRegistry` so multiple instances/tests don't collide on
   Prometheus's global default registry).

Steps 1–3 (everything before tool execution) are factored into a standalone module-level function,
`evaluate_access()`, specifically so `replay.py` can reuse the exact same decision logic instead of
maintaining a parallel implementation that could silently drift from what the live proxy actually does.

## Two bypasses a review found after the first commit

Both are now regression-tested in `tests/proxy/test_interceptor.py`:

- **Path allowlist must be segment-aware.** A literal `str.startswith()` check lets
  `"sandbox/files-evil/secret.txt"` pass an allowlist of `"sandbox/files"` — the fix, `_is_within_prefix`,
  compares path *segments*, not raw string prefixes.
- **Host allowlist must not gate on `"://" in value`.** A protocol-relative URL like `"//evil.com/x"` has no
  `://` substring but `urlparse(value).hostname` still resolves a real hostname for it — gating the check on
  that substring let such URLs skip SSRF containment entirely. The fix: call `urlparse(value).hostname`
  unconditionally.

## `dry_run` semantics

`policy.dry_run` **never withholds real output or execution** — it only stops a would-be denial from
suppressing the result. This lets the proxy run in report-only mode (log what it *would* have blocked)
before anyone trusts it to actually enforce.

## Fail-closed policy loading

`policy.py` loads YAML via pydantic. `load_policy_fail_closed(path)` — the entry point everything outside
tests should use — never raises: a missing file, invalid YAML, or a schema error all fall back to the
maximally restrictive default `Policy()` (deny everything), never to "allow everything." `load_policy(path)`
(the raising variant) exists for tests that need to assert on the specific error.

## `stdio_proxy.py`: a real MCP server, not a passthrough shim

`mcp-sentinel-proxy run` re-registers `vulnerable_target`'s four tools as a real stdio MCP server
(`mcp.server.MCPServer`) and routes each call through `ProxyEngine` before delegating to the real tool
implementation in `vulnerable_target/tools/`. This deviates from the original design sketch (hand-rolled
JSON-RPC passthrough to a spawned child server) in favor of calling the real tool functions in-process —
still a distinct process with real enforcement, just without re-implementing MCP's wire protocol a second
time. A blocked call raises `ToolBlockedError`, which the MCP SDK surfaces to the client as `is_error=True`
on the `CallToolResult` (snake_case — the real pydantic attribute, not the wire-protocol's camelCase
`isError`), not a silently empty response.

## Observability

`app.py::create_app` exposes `/metrics` (Prometheus text format) and `/dashboard` (HTML), run via
`uvicorn.Server` on a background daemon thread inside the proxy process, sharing one in-memory `ProxyMetrics`
instance with the interceptor. The dashboard HTML-escapes tool names and the "most abused tool" label before
interpolating them — a review found the first version didn't, which was a stored-XSS bug (tool names are
untrusted, attacker-influenced strings in a general MCP deployment), fixed and regression-tested.

## Replay mode

`replay.py::replay_audit_log(audit_log_path, policy)` re-evaluates a captured JSONL audit log's access
decisions against a **new** policy, without executing any tool. It replays using each record's *actual
recorded timestamp* (not "all at once") so rate-limit replay is faithful to what really happened, and calls
the exact same `evaluate_access()` the live engine uses. It does not replay injection detection, since the
audit log doesn't store raw tool output — only the policy decision.

## What it doesn't do

No mutual TLS, no distributed policy sync across multiple proxy instances, no eBPF-level enforcement, and
containment is limited to what's visible in a tool call's argument values — see
[`../THREAT_MODEL.md`](../THREAT_MODEL.md) and the design doc's non-goals section for the full list.
