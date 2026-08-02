from supply_chain.sbom import generate_sbom_for_environment, generate_sbom_for_requirements


def test_environment_sbom_has_valid_cyclonedx_shape():
    bom = generate_sbom_for_environment(root_component_name="test-app", root_component_version="1.2.3")
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.5"
    assert bom["serialNumber"].startswith("urn:uuid:")
    assert bom["metadata"]["component"] == {"type": "application", "name": "test-app", "version": "1.2.3"}
    assert isinstance(bom["components"], list)
    assert len(bom["components"]) > 0


def test_environment_sbom_includes_this_projects_own_direct_dependency():
    bom = generate_sbom_for_environment()
    names = {c["name"].lower() for c in bom["components"]}
    assert "mcp" in names
    assert "pytest" in names


def test_environment_sbom_components_have_purl_and_no_duplicates():
    bom = generate_sbom_for_environment()
    seen = set()
    for component in bom["components"]:
        assert component["type"] == "library"
        assert component["purl"] == f"pkg:pypi/{component['name'].lower()}@{component['version']}"
        key = (component["name"].lower(), component["version"])
        assert key not in seen
        seen.add(key)


def test_requirements_sbom_only_includes_exactly_pinned_lines(tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text(
        "\n".join(
            [
                "# a comment",
                "requests==2.31.0",
                "flask>=2.0  # unpinned, should be skipped",
                "",
                "click==8.1.7",
                "-r other.txt",
            ]
        ),
        encoding="utf-8",
    )
    bom = generate_sbom_for_requirements(requirements, root_component_version="9.9.9")

    names_and_versions = {(c["name"], c["version"]) for c in bom["components"]}
    assert names_and_versions == {("requests", "2.31.0"), ("click", "8.1.7")}
    assert bom["metadata"]["component"]["version"] == "9.9.9"


def test_requirements_sbom_root_name_defaults_to_parent_directory_name(tmp_path):
    target_dir = tmp_path / "some-mcp-server"
    target_dir.mkdir()
    requirements = target_dir / "requirements.txt"
    requirements.write_text("httpx==0.27.0\n", encoding="utf-8")

    bom = generate_sbom_for_requirements(requirements)
    assert bom["metadata"]["component"]["name"] == "some-mcp-server"
