"""Supply-chain hygiene checks that run alongside the static scanner:
SBOM generation, dependency vulnerability scanning, and license checking.

Unlike `vulnerable_target`, these checks legitimately contact the network
(the public OSV/PyPI vulnerability advisory databases via `pip-audit`) --
the project's "no real network egress" constraint applies to the
sandboxed demo environment, not to developer/CI tooling that needs a live
advisory feed to be meaningful, exactly like Dependabot, npm audit, or
Snyk in any real pipeline.
"""
