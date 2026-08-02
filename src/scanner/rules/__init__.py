from scanner.rules.base import SinkArgument, SinkRule
from scanner.rules.command_injection import CommandInjectionRule
from scanner.rules.path_traversal import PathTraversalRule
from scanner.rules.sql_injection import SqlInjectionRule
from scanner.rules.ssrf import SsrfRule

DEFAULT_SINK_RULES: tuple[SinkRule, ...] = (
    CommandInjectionRule(),
    SqlInjectionRule(),
    PathTraversalRule(),
    SsrfRule(),
)

__all__ = [
    "SinkArgument",
    "SinkRule",
    "CommandInjectionRule",
    "SqlInjectionRule",
    "PathTraversalRule",
    "SsrfRule",
    "DEFAULT_SINK_RULES",
]
