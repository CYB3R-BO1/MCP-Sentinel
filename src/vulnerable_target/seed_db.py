import sqlite3


def seed_db(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT)"
    )
    conn.executemany(
        "INSERT INTO users (username, email) VALUES (?, ?)",
        [
            ("alice", "alice@example.test"),
            ("bob", "bob@example.test"),
            ("admin", "admin@example.test"),
        ],
    )
    conn.commit()
