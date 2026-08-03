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
import re
from typing import Any

# Word-boundary-wrapped: several of these keywords (mit, bsd, isc, gpl, mpl,
# osl) are short enough to appear as substrings of ordinary English words --
# "example" contains "mpl", "limitation" contains "mit", "discussed"
# contains "isc" -- and packages sometimes dump their full license *text*
# (not just an identifier) into the `License` metadata field, where such
# false substring hits are common. Matching whole words only fixed a real
# false positive found while smoke-testing this module (a plain BSD-licensed
# package was misclassified as copyleft because its license text happened
# to contain the word "example").
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


def _keyword_pattern(keyword: str) -> re.Pattern[str]:
    return re.compile(r"\b" + re.escape(keyword) + r"\b")


_PERMISSIVE_PATTERNS = [_keyword_pattern(k) for k in _PERMISSIVE_KEYWORDS]
_COPYLEFT_PATTERNS = [_keyword_pattern(k) for k in _COPYLEFT_KEYWORDS]


def classify_license(license_text: str) -> str:
    lowered = license_text.lower().strip()
    if not lowered or lowered in {"unknown", "none", "unlicense d"}:
        return "unknown"
    # Copyleft keywords are checked first: "GNU Lesser General Public
    # License" contains no permissive keyword, but a hypothetical dual
    # license string could contain both -- copyleft obligations are the
    # stricter concern, so they win when both match.
    if any(pattern.search(lowered) for pattern in _COPYLEFT_PATTERNS):
        return "copyleft"
    if any(pattern.search(lowered) for pattern in _PERMISSIVE_PATTERNS):
        return "permissive"
    return "unknown"


def _license_text_for(dist: metadata.Distribution) -> str:
    """Prefer trove classifiers (structured, short, reliable) over the
    free-text `License` metadata field: some packages put their entire
    license *body* in that field instead of a short identifier, which is
    both noisy and a source of false keyword matches."""
    dist_metadata = dist.metadata
    classifiers = [c for c in dist_metadata.get_all("Classifier", []) if c.startswith("License ::")]
    if classifiers:
        return " ".join(classifiers)
    return " ".join(dist_metadata.get_all("License") or []).strip()


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
