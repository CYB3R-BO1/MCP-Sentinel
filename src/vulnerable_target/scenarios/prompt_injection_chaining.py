from vulnerable_target.scenarios import Scenario

PROMPT_INJECTION_CHAINING_SCENARIO = Scenario(
    name="prompt-injection-chaining",
    initial_tool="fetch_url",
    initial_args_template="http://127.0.0.1:{port}/public/data",
)
