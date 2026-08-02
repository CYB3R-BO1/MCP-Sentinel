"""Small AST helpers shared by both sink rules (`scanner.rules`) and
structural rules (`scanner.structural_rules`)."""
from __future__ import annotations

import ast


def render_dotted_name(expr: ast.expr) -> str | None:
    """Render `foo.bar.baz` as the string "foo.bar.baz", or None if `expr`
    isn't a plain dotted-name chain (e.g. it's a call result or subscript)."""
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute):
        base = render_dotted_name(expr.value)
        if base is None:
            return None
        return f"{base}.{expr.attr}"
    return None


def call_is_dotted(call: ast.Call, dotted_suffixes: tuple[str, ...]) -> bool:
    """True if the call's callable, rendered as a dotted name (e.g.
    `urllib.request.urlopen`), ends with one of `dotted_suffixes` (e.g.
    `("request.urlopen",)`), regardless of the leading module alias."""
    rendered = render_dotted_name(call.func)
    if rendered is None:
        return False
    return any(rendered == suffix or rendered.endswith("." + suffix) for suffix in dotted_suffixes)


def decorator_dotted_name(decorator: ast.expr) -> str | None:
    """Same as `render_dotted_name`, but unwraps a decorator call first, so
    both `@tool` and `@mcp_app.tool()` render as `"tool"`/`"mcp_app.tool"`."""
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    return render_dotted_name(target)


def is_tool_decorated(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """True if `func_node` carries a decorator that looks like an MCP tool
    registration -- bare `@tool` or any `@<...>.tool(...)` chain, matching
    both this project's `@mcp_app.tool()` and common alternate SDK spellings."""
    for decorator in func_node.decorator_list:
        name = decorator_dotted_name(decorator)
        if name and (name == "tool" or name.endswith(".tool")):
            return True
    return False
