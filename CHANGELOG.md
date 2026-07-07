# Changelog

## Unreleased

- Added the MIT License and updated package documentation to reflect the open-source license.
- Fixed static scanner scope noise by excluding agent metadata/worktree directories such as `.claude`, `.agents`, and `.codex` by default.
- Fixed generated report Markdown so the `Compliance Matrices` heading is emitted as a proper top-level section.
- Updated the pinned `actions/checkout` workflow reference to a Node 24-compatible release SHA.
- Added package validation coverage for agent-worktree exclusion behavior and report heading formatting.

## v2.4.0 - CLI and export usability

- Added `bin/securescan`, `scripts/securescan.sh`, and `scripts/securescan.py` as the one-command CLI front door.
- Added `doctor`, `demo`, `scan`, `validate`, `export`, and `install` CLI commands.
- Added first-run scope metadata support for static scans through `--wizard`, `--yes`, `--authorized-by`, and `--scope-note`.
- Added scan summaries with finding counts, coverage, report path, and top remediation items.
- Added JSON, SARIF, HTML, and Markdown export generation under `.securescan/exports/`.
- Added a dedicated NIST AI RMF Govern/Map/Measure/Manage evidence matrix skill, template, validator gate, and static-scanner artifact.
- Added `scripts/build-overview-docx.py` to rebuild the Word overview from the canonical Markdown overview.
- Updated CI and package validation to treat the CLI and export path as release-gated package features.

## v2.3.0 - Operational static scanner

- Added `scripts/securescan-static.py` and `scripts/securescan-static.sh`.
- The static scanner now generates the full `.securescan/` artifact set without invoking Claude agents.
- CI now runs the static scanner against `examples/vulnerable-demo` and validates the generated audit.
- Package validation now compiles the scanner and runs the scanner regression path.

## v2.2.0 - Regression and release hardening

- Added canonical `VERSION`.
- Added GitHub Actions validation workflow.
- Added golden SecureScan output for the vulnerable demo fixture.
- Added `scripts/validate-demo-audit.sh` to check generated demo audits for expected vulnerability themes.
- Strengthened `coverage.json` schema validation in `scripts/validate-securescan-artifacts.sh`.
- Updated package validation to enforce version consistency, CI wiring, golden fixture health, and demo regression health.

## v2.1.0 - Enterprise hardening

- Added `scripts/install.sh`.
- Added `scripts/validate-package.sh`.
- Added `scripts/validate-securescan-artifacts.sh`.
- Added source registry with verification dates.
- Added scope, recon, coverage, and report QA templates.
- Added static-by-default authorization rules to all audit agents.
- Added manifest and coverage requirements to recon/scanner handoff.
- Clarified HIPAA current-rule vs proposed-readiness reporting.
- Added intentionally vulnerable demo fixture for smoke testing.

## v2.0.0

- Initial multi-agent SecureScan package with 5 agents and 5 skills.
