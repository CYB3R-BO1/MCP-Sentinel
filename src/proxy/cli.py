"""mcp-sentinel-proxy: run the guardrail proxy, or replay captured traffic
against an updated policy without spinning up a live MCP server."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from proxy.policy import load_policy_fail_closed
from proxy.replay import replay_audit_log, summarize_replay
from proxy.stdio_proxy import DEFAULT_POLICY_PATH
from proxy.stdio_proxy import main as stdio_proxy_main


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mcp-sentinel-proxy")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run the proxy as a stdio MCP server (the default mode).")
    run_parser.add_argument("--policy", type=str, default=str(DEFAULT_POLICY_PATH))
    run_parser.add_argument("--audit-log", type=str, default="proxy-audit.jsonl")
    run_parser.add_argument("--metrics-port", type=str, default=None)

    replay_parser = subparsers.add_parser(
        "replay", help="Re-evaluate a captured audit log against a policy without executing any tool."
    )
    replay_parser.add_argument("--audit-log", type=Path, required=True)
    replay_parser.add_argument("--policy", type=Path, required=True)
    replay_parser.add_argument("--format", choices=["terminal", "json"], default="terminal")
    replay_parser.add_argument(
        "--fail-on-change",
        action="store_true",
        help="Exit 1 if any call's decision would differ under the given policy.",
    )

    return parser


def _run_replay(args: argparse.Namespace) -> int:
    if not args.audit_log.is_file():
        print(f"error: audit log {args.audit_log} does not exist", file=sys.stderr)
        return 2

    policy, warnings = load_policy_fail_closed(args.policy)
    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)

    results = replay_audit_log(args.audit_log, policy)
    summary = summarize_replay(results)

    if args.format == "json":
        payload = {
            "summary": summary,
            "results": [
                {
                    "correlation_id": r.correlation_id,
                    "tool_name": r.tool_name,
                    "arguments": r.arguments,
                    "original_allowed": r.original_allowed,
                    "replayed_allowed": r.replayed_allowed,
                    "replayed_reason": r.replayed_reason,
                    "changed": r.changed,
                }
                for r in results
            ],
        }
        print(json.dumps(payload, indent=2))
    else:
        print(f"Replay summary: total={summary['total']} changed={summary['changed']}")
        print(f"  newly blocked: {summary['newly_blocked']}")
        print(f"  newly allowed: {summary['newly_allowed']}")
        for r in results:
            if r.changed:
                before = "allow" if r.original_allowed else "deny"
                after = "allow" if r.replayed_allowed else "deny"
                print(f"  [{r.correlation_id}] {r.tool_name}: {before} -> {after} ({r.replayed_reason})")

    if args.fail_on_change and summary["changed"] > 0:
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "run":
        run_argv = ["--policy", args.policy, "--audit-log", args.audit_log]
        if args.metrics_port is not None:
            run_argv += ["--metrics-port", args.metrics_port]
        stdio_proxy_main(run_argv)
        return 0

    return _run_replay(args)


if __name__ == "__main__":
    sys.exit(main())
