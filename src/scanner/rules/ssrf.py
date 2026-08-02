import ast

from scanner.rules.base import SinkArgument, SinkRule, _call_is_dotted

_HTTP_FUNCS = (
    "request.urlopen",
    "urlopen",
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.delete",
    "requests.head",
    "requests.patch",
    "requests.request",
    "httpx.get",
    "httpx.post",
    "httpx.put",
    "httpx.delete",
)


class SsrfRule(SinkRule):
    """Flags any outbound HTTP call whose URL is tainted. Unlike the other
    rules, this one does not look for a missing sanitizer in the caller --
    a static scanner cannot know whether a runtime allowlist exists
    elsewhere (that's the runtime proxy's job, see THREAT_MODEL.md class
    #2) -- it simply reports every tainted-URL fetch so a human or the CI
    gate can confirm an allowlist is enforced downstream."""

    rule_id = "MCP-SENT-002"

    def sink_arguments(self, call: ast.Call) -> list[SinkArgument]:
        if not _call_is_dotted(call, _HTTP_FUNCS):
            return []
        if call.args:
            return [SinkArgument(expr=call.args[0], description="URL passed to an HTTP fetch")]
        for kw in call.keywords:
            if kw.arg == "url":
                return [SinkArgument(expr=kw.value, description="URL passed to an HTTP fetch")]
        return []

    def message(self, argument: SinkArgument) -> str:
        return (
            "Unsanitized input reaches an outbound HTTP fetch "
            f"({argument.description}) with no host allowlist visible in "
            "this function; this is SSRF-capable."
        )
