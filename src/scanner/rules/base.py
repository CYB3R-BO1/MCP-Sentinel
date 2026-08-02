"""Contract every taint sink rule implements. The taint engine (see
`scanner.taint.engine`) walks each function body once, and for every
`ast.Call` it finds, asks each registered `SinkRule` whether that call is a
sink this rule cares about. A rule doesn't do its own AST traversal -- it
only classifies calls the engine hands it. This keeps the expensive part
(the traversal and the taint bookkeeping) in one place and lets adding a
new sink type be a small, self-contained, independently testable class.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass

from scanner.ast_utils import call_is_dotted as _call_is_dotted
from scanner.ast_utils import render_dotted_name as _render_dotted


@dataclass(frozen=True)
class SinkArgument:
    """One expression a `SinkRule` wants the engine to taint-check.

    `description` is a short, human-readable label for this argument used
    in a finding's message and taint trace (e.g. "command string",
    "file path").
    """

    expr: ast.expr
    description: str


class SinkRule:
    """Base class for a static sink rule. Subclasses set `rule_id` and
    implement `sink_arguments`; `is_sanitized` has a sane default."""

    rule_id: str

    def sink_arguments(self, call: ast.Call) -> list[SinkArgument]:
        """Return the argument expressions this call passes to a sink this
        rule recognizes, or an empty list if `call` isn't a sink for this
        rule at all (regardless of taint)."""
        raise NotImplementedError

    def message(self, argument: SinkArgument) -> str:
        return f"Unsanitized input reaches sink via {argument.description}"


def _call_is_attribute(call: ast.Call, attr_name: str) -> bool:
    return isinstance(call.func, ast.Attribute) and call.func.attr == attr_name


def _call_is_name(call: ast.Call, name: str) -> bool:
    return isinstance(call.func, ast.Name) and call.func.id == name
