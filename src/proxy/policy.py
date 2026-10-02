"""YAML policy-as-code for the runtime guardrail proxy.

Loading is fail-closed by design: a missing file, malformed YAML, or a
schema validation error must never silently fall through to "allow
everything". `load_policy_fail_closed` is the only entry point callers
should use in production paths -- it never raises, and on any error it
returns the maximally restrictive default `Policy()` (default_action="deny",
no tools declared) plus a human-readable warning describing what went wrong,
so the proxy can log the warning and keep refusing tool calls rather than
crash open.
"""
from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ValidationError


class ToolPolicy(BaseModel):
    """Per-tool containment. The `allow_path_prefixes` field has three
    meanings, and the distinction matters (see `interceptor._check_containment`):

    - `None` (default): no path check at all.
    - `[""]`: traversal-segment (`..`) check only, no prefix restriction.
      The empty string is the identity prefix -- `_is_within_prefix(x, "")`
      is always true -- so legitimate bare filenames pass while any `..`
      segment still denies. Use this when the tool resolves arguments
      relative to its own sandbox root and a real prefix would deny every
      legitimate call.
    - `["a/b", ...]`: traversal check plus segment-aware prefix restriction;
      the argument must fall under one of the listed prefixes on a real
      path-segment boundary (`files-evil` does not match `files`).
    """

    enabled: bool = True
    allow_hosts: list[str] | None = None
    allow_path_prefixes: list[str] | None = None
    readonly: bool = False
    max_calls_per_minute: int | None = None


class InjectionDetectionPolicy(BaseModel):
    enabled: bool = True
    block_on_detection: bool = True


class Policy(BaseModel):
    version: int = 1
    default_action: Literal["allow", "deny"] = "deny"
    dry_run: bool = False
    max_calls_per_minute: int = 60
    tools: dict[str, ToolPolicy] = {}
    injection_detection: InjectionDetectionPolicy = InjectionDetectionPolicy()


class PolicyError(Exception):
    """Raised by `load_policy` (but never by `load_policy_fail_closed`)."""


def load_policy(path: Path) -> Policy:
    if not path.is_file():
        raise PolicyError(f"policy file {path} does not exist")

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PolicyError(f"policy file {path} is not valid YAML: {exc}") from exc

    if raw is None:
        raise PolicyError(f"policy file {path} is empty")

    try:
        return Policy.model_validate(raw)
    except ValidationError as exc:
        raise PolicyError(f"policy file {path} failed schema validation: {exc}") from exc


def load_policy_fail_closed(path: Path) -> tuple[Policy, list[str]]:
    try:
        return load_policy(path), []
    except PolicyError as exc:
        return Policy(), [str(exc)]


def resolve_tool_policy(policy: Policy, tool_name: str) -> ToolPolicy:
    declared = policy.tools.get(tool_name)
    if declared is not None:
        return declared
    return ToolPolicy(enabled=policy.default_action == "allow")
