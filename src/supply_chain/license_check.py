"""Categorizes every installed distribution's declared license as
permissive, copyleft, or unknown, using stdlib `importlib.metadata` (the
`License` metadata field and any `License ::` trove classifiers) --
no dependency on an external license-scanning tool.

This is a keyword heuristic, not a legal opinion: license metadata in the
wild is inconsistently populated (some packages leave `License` blank and
rely only on classifiers, some do neither), so "unknown" is a common and
expected result, not a scanner defect. Treat "unknown" as "needs a human
to check", not "definitely a problem" -- it's reported separately from
"copyleft" for exactly that reason.
"""
from __future__ import annotations

import importlib.metadata as metadata
from typing import Any

_PERMISSIVE_KEYWORDS = (
    "mit",
    "bsd",
    "apache",
    "isc",
    "python software foundation",
    "psf",
    "unlicense",
    "0bsd",
    "zlib",
    "public domain",
)

_COPYLEFT_KEYWORDS = (
    "gpl",
    "agpl",
    "lgpl",
    "general public license",
    "mpl",
    "mozilla public license",
    "eupl",
    "osl",
    "cddl",
)


def classify_license(license_text: str) -> str:
    lowered = license_text.lower().strip()
    if not lowered or lowered in {"unknown", "none", "unlicense d"}:
        return "unknown"
    # Copyleft keywords are checked first: "GNU Lesser General Public
    # License" contains no permissive keyword, but a hypothetical dual
    # license string could contain both -- copyleft obligations are the
    # stricter concern, so they win when both match.
    if any(keyword in lowered for keyword in _COPYLEFT_KEYWORDS):
        return "copyleft"
    if any(keyword in lowered for keyword in _PERMISSIVE_KEYWORDS):
        return "permissive"
    return "unknown"


def _license_text_for(dist: metadata.Distribution) -> str:
    dist_metadata = dist.metadata
    license_field = dist_metadata.get("License") or ""
    classifiers = [c for c in dist_metadata.get_all("Classifier", []) if c.startswith("License ::")]
    return " ".join(part for part in (license_field, *classifiers) if part).strip()


def check_licenses() -> dict[str, Any]:
    """Reflects the CURRENT Python environment's installed distributions.
    There is no equivalent "check licenses for a requirements.txt I don't
    have installed" mode: license metadata isn't available without
    installing the package (unlike a pinned version number), so accurately
    checking a target MCP server's licenses would require installing its
    dependencies into an isolated environment first -- out of scope for
    this sub-project, noted in WRITEUP.md."""
    entries: list[dict[str, str]] = []
    for dist in metadata.distributions():
        name = dist.metadata["Name"]
        if not name:
            continue
        license_text = _license_text_for(dist)
        entries.append(
            {
                "name": name,
                "version": dist.version,
                "license": license_text or "UNKNOWN",
                "category": classify_license(license_text),
            }
        )

    seen: set[tuple[str, str]] = set()
    deduped: list[dict[str, str]] = []
    for entry in sorted(entries, key=lambda e: e["name"].lower()):
        key = (entry["name"].lower(), entry["version"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(entry)

    by_category = {"permissive": 0, "copyleft": 0, "unknown": 0}
    for entry in deduped:
        by_category[entry["category"]] += 1

    return {
        "total_packages": len(deduped),
        "permissive_count": by_category["permissive"],
        "copyleft_count": by_category["copyleft"],
        "unknown_count": by_category["unknown"],
        "flagged": [e for e in deduped if e["category"] in {"copyleft", "unknown"}],
        "packages": deduped,
    }
