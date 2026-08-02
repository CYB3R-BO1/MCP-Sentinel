"""A lightweight, AST-based taint engine: source (function parameter) ->
propagation (assignment, string formatting, pathlib joins, helper-function
calls) -> sink (shell exec, SQL execute, filesystem path, HTTP fetch).

Scope, by design, not oversight (see WRITEUP.md for the full trade-off
discussion):

- Every parameter of every function found under the scan root is treated
  as a taint source. There is no attempt to identify "the" MCP tool
  entrypoints specifically -- a function three calls away from any
  attacker-reachable entrypoint is indistinguishable, from inside a single
  function body, from one that's never reachable at all. Treating every
  parameter as a potential source trades some false positives (a genuinely
  unreachable helper gets flagged) for avoiding false negatives (missing a
  real vulnerability because the entrypoint detector didn't recognize a
  project's specific decorator). Findings are deduplicated by (rule, file,
  line, column), so a value that's provably tainted via multiple call
  paths is still reported once.
- Interprocedural resolution is name-based (see `scanner.project`), not a
  full import graph, and is bounded by `max_depth` to keep analysis of
  recursive or deeply-chained code finite.
- Flow is statement-sequential within straight-line code, `if`, `for`,
  `while`, `with`, and `try` bodies; it does not model which branch of an
  `if` actually executes (both are analyzed), which is the conservative,
  false-negative-avoiding choice for a security scanner.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field

from scanner.findings import Finding
from scanner.project import FunctionDef, Project
from scanner.rules.base import SinkRule
from taxonomy import get_taxonomy_entry

DEFAULT_MAX_DEPTH = 6

_SANITIZER_CALL_NAMES = {
    "normpath",
    "resolve",
    "realpath",
    "relative_to",
    "is_relative_to",
    "abspath",
    "quote",
    "shlex_quote",
    "escape",
}


@dataclass
class SinkHit:
    rule_id: str
    message: str
    file_path: str
    line: int
    column: int
    trace: tuple[str, ...]


@dataclass
class _FunctionResult:
    sink_hits: list[SinkHit] = field(default_factory=list)
    return_tainted: bool = False


def _callable_name(func_expr: ast.expr) -> str | None:
    if isinstance(func_expr, ast.Name):
        return func_expr.id
    if isinstance(func_expr, ast.Attribute):
        return func_expr.attr
    return None


def _is_sanitizer_call(call: ast.Call) -> bool:
    name = _callable_name(call.func)
    return name in _SANITIZER_CALL_NAMES


def _param_names(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    args = func_node.args
    return [a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)]


def _analyze_function(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    file_path: str,
    tainted_params: set[str],
    project: Project,
    sink_rules: tuple[SinkRule, ...],
    depth: int,
    visited: frozenset[tuple[str, str]],
    trace_prefix: tuple[str, ...],
    max_depth: int,
) -> _FunctionResult:
    tainted: set[str] = set(tainted_params)
    result = _FunctionResult()

    def check_call_for_sinks(call: ast.Call) -> None:
        for rule in sink_rules:
            for argument in rule.sink_arguments(call):
                if expr_is_tainted(argument.expr):
                    trace = (
                        *trace_prefix,
                        f"-> {rule.message(argument)} ({file_path}:{call.lineno})",
                    )
                    result.sink_hits.append(
                        SinkHit(
                            rule_id=rule.rule_id,
                            message=rule.message(argument),
                            file_path=file_path,
                            line=call.lineno,
                            column=call.col_offset + 1,
                            trace=trace,
                        )
                    )

    def expr_is_tainted(expr: ast.expr | None) -> bool:
        if expr is None:
            return False
        if isinstance(expr, ast.Name):
            return expr.id in tainted
        if isinstance(expr, ast.Constant):
            return False
        if isinstance(expr, ast.JoinedStr):
            return any(
                isinstance(v, ast.FormattedValue) and expr_is_tainted(v.value)
                for v in expr.values
            )
        if isinstance(expr, ast.BinOp):
            return expr_is_tainted(expr.left) or expr_is_tainted(expr.right)
        if isinstance(expr, ast.BoolOp):
            return any(expr_is_tainted(v) for v in expr.values)
        if isinstance(expr, ast.IfExp):
            return expr_is_tainted(expr.body) or expr_is_tainted(expr.orelse)
        if isinstance(expr, ast.Attribute):
            return expr_is_tainted(expr.value)
        if isinstance(expr, ast.Subscript):
            return expr_is_tainted(expr.value)
        if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            return any(expr_is_tainted(e) for e in expr.elts)
        if isinstance(expr, ast.Call):
            return _expr_call_is_tainted(expr)
        return False

    def _expr_call_is_tainted(call: ast.Call) -> bool:
        check_call_for_sinks(call)

        # A chained call's receiver (e.g. `conn.execute(query)` inside
        # `conn.execute(query).fetchall()`) can itself be a tainted sink
        # call; evaluate it so nested sinks are found and its taintedness
        # flows into this call's result.
        receiver_tainted = (
            expr_is_tainted(call.func.value) if isinstance(call.func, ast.Attribute) else False
        )

        if _is_sanitizer_call(call) and (any(expr_is_tainted(a) for a in call.args) or receiver_tainted):
            return False

        func_name = _callable_name(call.func)
        if func_name and depth < max_depth:
            target: FunctionDef | None = project.resolve_call_target(func_name)
            if target is not None:
                target_key = (target.file_path, target.node.name)
                if target_key not in visited:
                    target_params = _param_names(target.node)
                    tainted_arg_names: set[str] = set()
                    for i, arg_expr in enumerate(call.args):
                        if i < len(target_params) and expr_is_tainted(arg_expr):
                            tainted_arg_names.add(target_params[i])
                    for kw in call.keywords:
                        if kw.arg and kw.arg in target_params and expr_is_tainted(kw.value):
                            tainted_arg_names.add(kw.arg)
                    if tainted_arg_names:
                        sub_result = _analyze_function(
                            target.node,
                            target.file_path,
                            tainted_arg_names,
                            project,
                            sink_rules,
                            depth=depth + 1,
                            visited=visited | {target_key},
                            trace_prefix=(
                                *trace_prefix,
                                f"-> calls {func_name}({', '.join(sorted(tainted_arg_names))}) "
                                f"({file_path}:{call.lineno})",
                            ),
                            max_depth=max_depth,
                        )
                        result.sink_hits.extend(sub_result.sink_hits)
                        return sub_result.return_tainted

        return (
            receiver_tainted
            or any(expr_is_tainted(a) for a in call.args)
            or any(expr_is_tainted(kw.value) for kw in call.keywords)
        )

    def walk_stmts(stmts: list[ast.stmt]) -> None:
        nonlocal result
        for stmt in stmts:
            if isinstance(stmt, ast.Assign):
                is_tainted = expr_is_tainted(stmt.value)
                for target_node in stmt.targets:
                    if isinstance(target_node, ast.Name):
                        if is_tainted:
                            tainted.add(target_node.id)
                        else:
                            tainted.discard(target_node.id)
            elif isinstance(stmt, ast.AnnAssign):
                if stmt.value is not None and isinstance(stmt.target, ast.Name):
                    if expr_is_tainted(stmt.value):
                        tainted.add(stmt.target.id)
                    else:
                        tainted.discard(stmt.target.id)
            elif isinstance(stmt, ast.AugAssign):
                if isinstance(stmt.target, ast.Name) and expr_is_tainted(stmt.value):
                    tainted.add(stmt.target.id)
            elif isinstance(stmt, ast.Return):
                if expr_is_tainted(stmt.value):
                    result.return_tainted = True
            elif isinstance(stmt, ast.Expr):
                expr_is_tainted(stmt.value)
            elif isinstance(stmt, ast.If):
                walk_stmts(stmt.body)
                walk_stmts(stmt.orelse)
            elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
                walk_stmts(stmt.body)
                walk_stmts(stmt.orelse)
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                for item in stmt.items:
                    item_tainted = expr_is_tainted(item.context_expr)
                    if isinstance(item.optional_vars, ast.Name):
                        if item_tainted:
                            tainted.add(item.optional_vars.id)
                        else:
                            tainted.discard(item.optional_vars.id)
                walk_stmts(stmt.body)
            elif isinstance(stmt, ast.Try):
                walk_stmts(stmt.body)
                for handler in stmt.handlers:
                    walk_stmts(handler.body)
                walk_stmts(stmt.orelse)
                walk_stmts(stmt.finalbody)
            # Nested FunctionDef/ClassDef bodies are analyzed independently
            # as their own top-level entrypoints by analyze_project.

    walk_stmts(func_node.body)
    return result


def analyze_project(
    project: Project,
    sink_rules: tuple[SinkRule, ...],
    max_depth: int = DEFAULT_MAX_DEPTH,
) -> list[Finding]:
    """Run every sink rule's taint analysis over every function defined
    under `project.root` and return deduplicated, sorted findings."""
    findings_by_key: dict[tuple[str, str, int, int], Finding] = {}

    for source_file in project.files:
        for node in ast.walk(source_file.tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            tainted_params = set(_param_names(node))
            if not tainted_params:
                continue
            func_key = (source_file.file_path, node.name)
            result = _analyze_function(
                node,
                source_file.file_path,
                tainted_params,
                project,
                sink_rules,
                depth=0,
                visited=frozenset({func_key}),
                trace_prefix=(
                    f"parameter(s) {sorted(tainted_params)} of {node.name}() "
                    f"({source_file.file_path}:{node.lineno})",
                ),
                max_depth=max_depth,
            )
            for hit in result.sink_hits:
                entry = get_taxonomy_entry(hit.rule_id)
                finding = Finding(
                    rule_id=hit.rule_id,
                    severity=entry.default_severity,
                    message=hit.message,
                    file_path=hit.file_path,
                    line=hit.line,
                    column=hit.column,
                    taint_trace=hit.trace,
                )
                findings_by_key.setdefault(finding.dedup_key(), finding)

    return sorted(findings_by_key.values(), key=lambda f: (f.file_path, f.line, f.rule_id))
