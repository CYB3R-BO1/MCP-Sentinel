import pytest

from vulnerable_target.agent import run_scenario
from vulnerable_target.permissions import SECRET_PATH
from vulnerable_target.scenarios.benign import BENIGN_SCENARIO
from vulnerable_target.scenarios.prompt_injection_chaining import (
    PROMPT_INJECTION_CHAINING_SCENARIO,
)


@pytest.mark.asyncio
async def test_benign_scenario_only_calls_the_one_intended_tool(mock_server):
    transcript = await run_scenario(BENIGN_SCENARIO, mock_server.port)
    assert len(transcript.tool_calls) == 1
    assert transcript.tool_calls[0][0] == "fetch_url"


@pytest.mark.asyncio
async def test_prompt_injection_chains_into_unintended_read_and_exfiltrates_secret(mock_server):
    """The flagship end-to-end proof: a single 'fetch this URL' request
    ends up leaking the sandbox-external secret file, entirely because the
    agent naively obeyed an embedded instruction in fetched content. This
    is the unprotected 'before' of the before/after demo."""
    transcript = await run_scenario(PROMPT_INJECTION_CHAINING_SCENARIO, mock_server.port)

    tool_names = [name for name, _ in transcript.tool_calls]
    assert tool_names == ["fetch_url", "read_file"]

    _, read_args = transcript.tool_calls[1]
    assert ".." in read_args["path"]

    assert "FIXTURE-SECRET" in transcript.final_output
    assert SECRET_PATH.read_text().strip() in transcript.final_output
