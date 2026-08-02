"""Command-line entrypoint: `python -m scanner <path> [options]`.

Exit codes:
- 0: scan completed, no finding at or above --fail-on (default: never fail).
- 1: scan completed, at least one finding at or above --fail-on severity.
- 2: the scan root doesn't exist / isn't a directory.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from scanner.output import findings_to_json, findings_to_sarif, render_terminal_report
from scanner.scan import run_scan
from taxonomy import Severity

_SEVERITY_CHOICES = [s.value for s in Severity]


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-sentinel-scan",
        description="Static taint-analysis security scanner for MCP servers.",
    )
    parser.add_argument("path", help="Directory to scan.")
    parser.add_argument(
        "--format",
        choices=("terminal", "json", "sarif"),
        default="terminal",
        help="Output format (default: terminal).",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Write the report to this file instead of stdout.",
    )
    parser.add_argument(
        "--fail-on",
        choices=_SEVERITY_CHOICES,
        default=None,
        help="Exit with status 1 if any finding is at or above this severity.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    root = Path(args.path)
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2

    findings = run_scan(root)

    if args.format == "terminal":
        report_text = render_terminal_report(findings, str(root))
    elif args.format == "json":
        report_text = json.dumps(findings_to_json(findings, str(root)), indent=2)
    else:
        report_text = json.dumps(findings_to_sarif(findings), indent=2)

    if args.output:
        Path(args.output).write_text(report_text, encoding="utf-8")
    else:
        print(report_text, end="")

    if args.fail_on is not None:
        threshold = Severity(args.fail_on)
        if any(f.severity >= threshold for f in findings):
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
