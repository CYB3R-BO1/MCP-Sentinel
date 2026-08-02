def test_flags_fstring_query_without_params(scan_source):
    findings = scan_source(
        """
def query_db(conn, username):
    query = f"SELECT id FROM users WHERE username = '{username}'"
    return conn.execute(query).fetchall()
"""
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "MCP-SENT-004"


def test_does_not_flag_parameterized_query(scan_source):
    findings = scan_source(
        """
def query_db(conn, username):
    return conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchall()
"""
    )
    assert findings == []


def test_does_not_flag_static_query(scan_source):
    findings = scan_source(
        """
def list_all_users(conn):
    return conn.execute("SELECT id FROM users").fetchall()
"""
    )
    assert findings == []
