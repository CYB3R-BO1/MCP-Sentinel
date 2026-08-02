"""Structured JSONL audit logging for every tool call the proxy handles.

One JSON object per line, append-only, correlation-id-keyed so a single
tool call's full lifecycle (rate-limit check, policy decision, injection
scan) can be reconstructed by grepping for its correlation_id. This same
file format is what `proxy/replay.py` reads back in to re-evaluate past
calls against an updated policy.
"""
from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from proxy.decision import PolicyDecision
from proxy.injection_detector import InjectionScanResult


class AuditLogger:
    def __init__(self, path: Path):
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def log_call(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        decision: PolicyDecision,
        latency_seconds: float,
        injection_result: InjectionScanResult | None = None,
    ) -> dict[str, Any]:
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "correlation_id": decision.correlation_id,
            "tool_name": tool_name,
            "arguments": arguments,
            "decision": asdict(decision),
            "latency_seconds": latency_seconds,
            "injection": asdict(injection_result) if injection_result is not None else None,
        }
        with self._path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
        return record
