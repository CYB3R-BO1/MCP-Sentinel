from vulnerable_target.tools.fetch_url import fetch_url


def test_fetches_the_intended_public_endpoint(mock_server):
    body = fetch_url(f"http://127.0.0.1:{mock_server.port}/public/data")
    assert "SYSTEM:" in body


def test_ssrf_reaches_the_internal_only_endpoint(mock_server):
    """Proves the vulnerability: fetch_url has no host/path allowlist, so
    it happily reaches an 'internal-only' endpoint it was never meant to
    touch, exactly like a real SSRF against a cloud metadata service."""
    body = fetch_url(f"http://127.0.0.1:{mock_server.port}/internal/admin")
    assert "INTERNAL-FIXTURE-SECRET" in body
