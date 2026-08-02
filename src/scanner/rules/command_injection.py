import ast

from scanner.ast_utils import call_is_dotted
from scanner.rules.base import SinkArgument, SinkRule

_SUBPROCESS_FUNCS = (
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
)


class CommandInjectionRule(SinkRule):
    rule_id = "MCP-SENT-005"

    def sink_arguments(self, call: ast.Call) -> list[SinkArgument]:
        if _is_os_system(call) and call.args:
            return [SinkArgument(expr=call.args[0], description="command string passed to os.system")]

        if call_is_dotted(call, _SUBPROCESS_FUNCS) and _has_shell_true(call) and call.args:
            return [SinkArgument(expr=call.args[0], description="command string passed with shell=True")]

        return []

    def message(self, argument: SinkArgument) -> str:
        return (
            "Unsanitized input reaches a shell execution sink "
            f"({argument.description}); an attacker-controlled value here "
            "can inject additional shell commands."
        )


def _is_os_system(call: ast.Call) -> bool:
    return isinstance(call.func, ast.Attribute) and call.func.attr == "system"


def _has_shell_true(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False
