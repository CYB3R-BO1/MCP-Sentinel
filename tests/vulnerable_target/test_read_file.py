from vulnerable_target.tools.read_file import read_file
from vulnerable_target.permissions import SECRET_PATH


def test_reads_a_file_inside_the_sandbox():
    content = read_file("README.txt")
    assert "sandbox root" in content


def test_path_traversal_escapes_the_sandbox():
    """Proves the vulnerability: no containment check lets '..' read the
    secret file one directory above the declared sandbox root."""
    content = read_file("../secret.txt")
    assert content == SECRET_PATH.read_text()
    assert "FIXTURE-SECRET" in content
