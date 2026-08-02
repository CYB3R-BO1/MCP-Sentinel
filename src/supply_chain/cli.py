"""Command-line entrypoint: `python -m supply_chain [options]`.

Exit codes:
- 0: report generated, no requested fail-on condition tripped.
- 1: a requested fail-on condition tripped (vulnerabilities and/or
  copyleft licenses found).
- 2: --requirements points at a file that doesn't exist.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from supply_chain.report import generate_supply_chain_report, render_terminal_report


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-sentinel-supply-chain",
        description="SBOM generation, dependency vulnerability scanning, and license checking.",
    )
    parser.add_argument(
        "--requirements",
        help="Audit this requirements.txt-style file instead of the local "
        "Python environment (e.g. a scanned MCP server's own dependency file).",
    )
    parser.add_argument("--format", choices=("terminal", "json"), default="terminal")
    parser.add_argument("--output", "-o", help="Write the report to this file instead of stdout.")
    parser.add_argument(
        "--skip-vuln-scan",
        action="store_true",
        help="Skip the pip-audit network call (useful offline or in restricted CI runners).",
    )
    parser.add_argument(
        "--fail-on-vulnerabilities",
        action="store_true",
        help="Exit 1 if the dependency audit finds any vulnerability.",
    )
    parser.add_argument(
        "--fail-on-copyleft",
        action="store_true",
        help="Exit 1 if any copyleft-licensed dependency is found.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    requirements_path: Path | None = None
    if args.requirements:
        requirements_path = Path(args.requirements)
        if not requirements_path.is_file():
            print(f"error: {requirements_path} is not a file", file=sys.stderr)
            return 2

    report = generate_supply_chain_report(
        requirements_path=requirements_path, skip_vuln_scan=args.skip_vuln_scan
    )

    report_text = (
        render_terminal_report(report) if args.format == "terminal" else json.dumps(report, indent=2)
    )

    if args.output:
        Path(args.output).write_text(report_text, encoding="utf-8")
    else:
        print(report_text, end="")

    exit_code = 0
    audit = report["dependency_audit"]
    if args.fail_on_vulnerabilities and audit and audit.get("total_vulnerabilities", 0) > 0:
        exit_code = 1
    if args.fail_on_copyleft and report["license_check"]["copyleft_count"] > 0:
        exit_code = 1
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
