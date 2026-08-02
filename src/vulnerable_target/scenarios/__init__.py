from dataclasses import dataclass


@dataclass(frozen=True)
class Scenario:
    name: str
    initial_tool: str
    initial_args_template: str  # "{port}" is substituted with the mock server port
