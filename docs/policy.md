# Policy schema (`src/proxy/policy.py`)

Policies are YAML, validated via pydantic (`Policy` in `policy.py`). This is the exact schema — every field
below is real, not illustrative.

```yaml
version: 1                    # int, default 1
default_action: deny          # "allow" | "deny" -- applies to any tool not listed under `tools:`
dry_run: false                # bool -- see "dry_run semantics" below
max_calls_per_minute: 60      # int -- default rate limit, used when a tool doesn't set its own

tools:
  <tool_name>:
    enabled: true                          # bool, default true
    allow_hosts: ["127.0.0.1"]             # list[str] | null -- SSRF containment
    allow_path_prefixes: [""]              # list[str] | null -- path-traversal containment (see below)
    readonly: true                         # bool, default false -- blocks write/injection-looking SQL
    max_calls_per_minute: 30               # int | null -- overrides the top-level default for this tool

injection_detection:
  enabled: true             # bool, default true
  block_on_detection: true  # bool, default true -- false means "log, don't block" (report-only)
```

## Field semantics

- **`default_action`** governs any tool with no entry under `tools:`. `resolve_tool_policy()` synthesizes an
  implicit `ToolPolicy(enabled=<default_action == "allow">)` for it — so `default_action: deny` (the
  fail-closed default) means an unlisted tool is disabled outright, not merely unrestricted.
- **`allow_hosts`** and **`allow_path_prefixes`** are `None` by default, meaning *no restriction of that
  kind* — set one only for tools where that containment type is relevant (a `fetch_url`-style tool needs
  `allow_hosts`; a `read_file`-style tool needs `allow_path_prefixes`). Leaving both unset on an `enabled:
  true` tool means the proxy enforces rate limiting and injection detection on it, but no argument
  containment.
- **`allow_path_prefixes` also gates the unconditional `..`-traversal check** — it only activates when this
  field is set (not `None`). If a tool's legitimate arguments are bare filenames relative to a fixed root the
  tool itself already anchors (as `vulnerable_target`'s `read_file` does), there's no meaningful non-trivial
  prefix to enforce — set `allow_path_prefixes: [""]` (an empty-string prefix matches every path) purely to
  activate the `..` block without imposing a real prefix restriction. This is exactly what
  `default_policy.yaml` does, after an earlier version used `["sandbox/files"]` and denied every legitimate
  call — see the comment in that file for the full story.
- **`readonly`** applies a regex heuristic (SQL comment markers, `UNION`/`DROP`/`INSERT`/`UPDATE`/`DELETE`,
  tautology patterns like `'x'='x'`) to string arguments — a heuristic, not a real SQL parser, so it can both
  over- and under-match on sufficiently adversarial input. Documented as a heuristic deliberately, not
  presented as a guarantee.
- **`max_calls_per_minute`** at the tool level overrides the policy-level default for that tool only.

## `dry_run`

`dry_run: true` **never withholds real output or execution.** It only stops a would-be denial from
suppressing the result — the call still executes, the decision is still logged and metriced as a denial, but
the caller still gets the real response. This is what makes it safe to point a new policy at production
traffic and see what it *would* block before trusting it to actually block anything.

## Fail-closed loading

Use `load_policy_fail_closed(path) -> tuple[Policy, list[str]]` outside tests, always. It never raises: a
missing file, invalid YAML, or a schema validation error all produce the same result — the maximally
restrictive default `Policy()` (`default_action="deny"`, no tools declared, so every tool is denied) plus a
human-readable warning string. There is no code path where a broken policy file causes the proxy to allow
everything.

## The real default policy

`src/proxy/default_policy.yaml` is what `mcp-sentinel-proxy run` loads if you don't pass `--policy`. See the
[README](../README.md#example-the-runtime-policy-protecting-it) for the annotated version protecting
`vulnerable_target`'s four tools.
