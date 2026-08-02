import pytest

from vulnerable_target.mock_http_server import start_mock_server


@pytest.fixture
def mock_server():
    handle = start_mock_server()
    yield handle
    handle.stop()
