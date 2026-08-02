import sqlite3
import pytest
from vulnerable_target.seed_db import seed_db
from vulnerable_target.tools.query_db import query_db


@pytest.fixture
def conn():
    connection = sqlite3.connect(":memory:")
    seed_db(connection)
    yield connection
    connection.close()


def test_looks_up_a_single_known_user(conn):
    rows = query_db(conn, "alice")
    assert len(rows) == 1
    assert rows[0][1] == "alice"


def test_sql_injection_dumps_every_row(conn):
    """Proves the vulnerability: username is spliced directly into the SQL
    string, so a classic OR '1'='1' payload returns every row instead of
    the single intended user."""
    rows = query_db(conn, "nonexistent' OR '1'='1")
    assert len(rows) >= 3
    usernames = {row[1] for row in rows}
    assert "admin" in usernames
