import ast

from scanner.rules.base import SinkArgument, SinkRule


class SqlInjectionRule(SinkRule):
    """Flags `<connection-or-cursor>.execute(query)` calls where `query` is
    the only argument. A second positional argument (or a `params` /
    `parameters` keyword) is treated as evidence of the DB-API parameterized
    form `execute(query, params)` and the call is skipped entirely -- a
    pathological caller could still splice input into the query string
    itself, but distinguishing that requires value-level reasoning this
    rule deliberately does not attempt (documented false-negative
    trade-off, consistent with the engine's name-matching limits)."""

    rule_id = "MCP-SENT-004"

    def sink_arguments(self, call: ast.Call) -> list[SinkArgument]:
        if not (isinstance(call.func, ast.Attribute) and call.func.attr == "execute"):
            return []
        if not call.args:
            return []
        if len(call.args) >= 2 or any(kw.arg in {"parameters", "params"} for kw in call.keywords):
            return []
        return [SinkArgument(expr=call.args[0], description="SQL query string")]

    def message(self, argument: SinkArgument) -> str:
        return (
            "Unsanitized input reaches a SQL execution sink "
            f"({argument.description}) built via string interpolation "
            "instead of a parameterized query."
        )
