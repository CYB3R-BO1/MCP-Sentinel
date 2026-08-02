from vulnerable_target.permissions import TOOL_PERMISSIONS, SANDBOX_ROOT, SECRET_PATH


def test_all_four_tools_have_declared_permissions():
    assert set(TOOL_PERMISSIONS.keys()) == {
        "read_file", "fetch_url", "query_db", "run_command",
    }


def test_each_permission_declares_scopes_and_purpose():
    for name, perm in TOOL_PERMISSIONS.items():
        assert perm["scopes"], f"{name} must declare at least one scope"
        assert perm["declared_purpose"], f"{name} must declare a purpose"


def test_sandbox_and_secret_paths_exist_and_are_separated():
    assert SANDBOX_ROOT.is_dir()
    assert SECRET_PATH.is_file()
    assert SECRET_PATH.parent == SANDBOX_ROOT.parent
    assert SECRET_PATH.parent != SANDBOX_ROOT
