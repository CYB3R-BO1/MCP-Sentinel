def test_flags_tainted_url_via_urllib(scan_source):
    findings = scan_source(
        """
import urllib.request

def fetch_url(url):
    with urllib.request.urlopen(url, timeout=5) as response:
        return response.read()
"""
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "MCP-SENT-002"


def test_flags_tainted_url_via_requests(scan_source):
    findings = scan_source(
        """
import requests

def fetch_url(url):
    return requests.get(url).text
"""
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "MCP-SENT-002"


def test_does_not_flag_hardcoded_url(scan_source):
    findings = scan_source(
        """
import requests

def fetch_status():
    return requests.get("https://api.company.internal/status").text
"""
    )
    assert findings == []
