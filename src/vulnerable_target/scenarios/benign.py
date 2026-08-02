from vulnerable_target.scenarios import Scenario

BENIGN_SCENARIO = Scenario(
    name="benign-fetch",
    initial_tool="fetch_url",
    initial_args_template="http://127.0.0.1:{port}/internal/admin",
)
