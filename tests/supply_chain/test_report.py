from supply_chain.report import generate_supply_chain_report, render_terminal_report


def test_generate_report_skips_vuln_scan_when_requested():
    report = generate_supply_chain_report(skip_vuln_scan=True)
    assert report["dependency_audit"] is None
    assert report["sbom"]["bomFormat"] == "CycloneDX"
    assert report["license_check"]["total_packages"] > 0


def test_generate_report_with_requirements_file_uses_requirements_sbom(tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("requests==2.31.0\n", encoding="utf-8")

    report = generate_supply_chain_report(requirements_path=requirements, skip_vuln_scan=True)
    names = {c["name"] for c in report["sbom"]["components"]}
    assert names == {"requests"}


def test_render_terminal_report_includes_all_three_sections():
    report = generate_supply_chain_report(skip_vuln_scan=True)
    text = render_terminal_report(report)
    assert "SBOM:" in text
    assert "Licenses:" in text
    assert "Dependency vulnerability audit: skipped" in text


def test_render_terminal_report_lists_copyleft_packages_when_present():
    report = {
        "sbom": {
            "components": [],
            "metadata": {"component": {"name": "x"}},
        },
        "license_check": {
            "total_packages": 1,
            "permissive_count": 0,
            "copyleft_count": 1,
            "unknown_count": 0,
            "flagged": [{"name": "gpl-pkg", "version": "1.0", "license": "GPL-3.0", "category": "copyleft"}],
            "packages": [],
        },
        "dependency_audit": None,
    }
    text = render_terminal_report(report)
    assert "gpl-pkg 1.0: GPL-3.0" in text
