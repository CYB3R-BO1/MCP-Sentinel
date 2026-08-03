# Security Policy

## A note on scope

MCP Sentinel intentionally ships a vulnerable component: `src/vulnerable_target/` is a deliberately insecure
MCP server used as a test fixture (see [`THREAT_MODEL.md`](THREAT_MODEL.md)). Its command injection, SQL
injection, path traversal, SSRF, and excessive-permission issues are **known, intentional, and the entire
point** — please do not report them. If you find a vulnerability class in `vulnerable_target` that isn't
already documented in `THREAT_MODEL.md` or covered by `tests/scanner`, that's a useful finding about test
coverage, not a security report — feel free to open a normal GitHub issue for it.

Everything else — `src/scanner/`, `src/taxonomy/`, `src/supply_chain/`, `src/proxy/`, and
`.github/workflows/` — is real code that's meant to be secure, and vulnerabilities there are genuinely in
scope.

## Supported versions

This project is pre-1.0 (`0.1.0`). Only the latest commit on `master` is supported; there is no back-porting
of fixes to older tags.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting instead of opening a public issue: go to the **Security**
tab of this repository → **Report a vulnerability**. This lets us discuss and fix the issue before it's
publicly visible.

Please include:

- Which component is affected (`scanner`, `proxy`, `supply_chain`, or the CI workflow — not
  `vulnerable_target`, per the scope note above).
- Steps to reproduce, ideally as a minimal failing test case.
- What you'd expect to happen instead, and why the actual behavior is a security issue (not just a bug).

## What happens next

This is a personal/portfolio project, not a funded security product with an SLA — but genuine reports will
be reviewed and, if confirmed, fixed with a regression test and a note in `CHANGELOG.md`, following the same
process used for every other bug found during development (see `WRITEUP.md`'s "Lessons learned" section for
examples of that process in action).
