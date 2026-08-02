"""Shared vulnerability-class taxonomy used by both the static scanner and
the runtime guardrail proxy, so a scanner finding and a proxy policy
violation that stem from the same vulnerability class reference the same
identifiers. Mirrors the STRIDE table in THREAT_MODEL.md at the repo root;
that file is the human-readable view, this package is the machine-readable
one -- keep them in sync when either changes."""
from taxonomy.models import Severity, TaxonomyEntry
from taxonomy.registry import TAXONOMY, get_taxonomy_entry

__all__ = ["Severity", "TaxonomyEntry", "TAXONOMY", "get_taxonomy_entry"]
