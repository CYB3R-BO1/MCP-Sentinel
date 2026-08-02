import ast

from scanner.rules.base import SinkArgument, SinkRule


class SqlInjectionRule(SinkRule):
    """Flags `<connection-or-cursor>.execute(query)` calls where `query` is
    built dynamically (f-string, `%`/`.format()`/`+` concatenation) instead
    of using the DB-API parameterized form `execute(query, params)`. A
    second positional argument is treated as evidence of parameterization
    and the call is skipped, even though a truly pathological caller could
    still splice user input into the query string itself -- that residual
    case is exactly what the taint check below still catches, since the
    query argument (args[0]) is checked regardless."""

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
