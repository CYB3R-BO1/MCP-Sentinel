from supply_chain.license_check import check_licenses, classify_license


def test_classify_permissive_licenses():
    assert classify_license("MIT License") == "permissive"
    assert classify_license("BSD-3-Clause") == "permissive"
    assert classify_license("License :: OSI Approved :: Apache Software License") == "permissive"


def test_classify_copyleft_licenses():
    assert classify_license("GNU General Public License v3") == "copyleft"
    assert classify_license("GNU Lesser General Public License v2.1 (LGPLv2.1)") == "copyleft"
    assert classify_license("AGPL-3.0") == "copyleft"


def test_classify_unknown_for_blank_or_unrecognized():
    assert classify_license("") == "unknown"
    assert classify_license("UNKNOWN") == "unknown"
    assert classify_license("Some Proprietary Thing") == "unknown"


def test_copyleft_wins_when_both_keywords_present():
    assert classify_license("Dual License: MIT or GPL-3.0") == "copyleft"


def test_check_licenses_report_shape_and_counts_are_consistent():
    report = check_licenses()
    assert report["total_packages"] > 0
    assert (
        report["permissive_count"] + report["copyleft_count"] + report["unknown_count"]
        == report["total_packages"]
    )
    assert len(report["packages"]) == report["total_packages"]
    assert len(report["flagged"]) == report["copyleft_count"] + report["unknown_count"]
    for entry in report["packages"]:
        assert entry["category"] in {"permissive", "copyleft", "unknown"}


def test_check_licenses_finds_no_duplicate_name_version_pairs():
    report = check_licenses()
    keys = [(p["name"].lower(), p["version"]) for p in report["packages"]]
    assert len(keys) == len(set(keys))
