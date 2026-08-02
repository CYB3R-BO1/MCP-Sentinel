import ast

from scanner.rules.base import SinkArgument, SinkRule

_PATH_METHODS = {
    "read_text",
    "read_bytes",
    "write_text",
    "write_bytes",
    "open",
    "unlink",
    "rmdir",
}


class PathTraversalRule(SinkRule):
    """Flags a filesystem read/write sink -- either the builtin `open(path)`
    or a `pathlib.Path` method like `.read_text()` -- whose path expression
    is tainted. For the `Path` method case the tainted expression is the
    *receiver* of the call (`call.func.value`, e.g. `target` in
    `target.read_text()`), not a positional argument, since the path was
    already folded into the receiver by an earlier assignment such as
    `target = SANDBOX_ROOT / path`."""

    rule_id = "MCP-SENT-003"

    def sink_arguments(self, call: ast.Call) -> list[SinkArgument]:
        if isinstance(call.func, ast.Name) and call.func.id == "open" and call.args:
            return [SinkArgument(expr=call.args[0], description="file path passed to open()")]

        if isinstance(call.func, ast.Attribute) and call.func.attr in _PATH_METHODS:
            return [
                SinkArgument(
                    expr=call.func.value,
                    description=f"path object receiving .{call.func.attr}()",
                )
            ]

        return []

    def message(self, argument: SinkArgument) -> str:
        return (
            "Unsanitized input reaches a filesystem path sink "
            f"({argument.description}); an attacker-controlled path "
            "segment (e.g. '../') can escape the intended directory."
        )
