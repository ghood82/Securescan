# SecureScan v2.4 for Claude Code

SecureScan is a Claude Code security-audit toolkit. It installs a coordinated set of agents and skills that produce auditable artifacts for static application security review, API review, AI/LLM review, agentic workflow review, and HIPAA-oriented readiness checks.

This package is designed for local, authorized audits. By default it performs static/code review only. Active exploit testing, external network testing, destructive commands, dependency installation, and production-environment access require explicit user approval in the target project.

The easiest entry point is the SecureScan CLI:

```bash
bin/securescan doctor
bin/securescan demo --format all
bin/securescan scan /path/to/project --format all --yes
```

## What Is Included

### Agents

| Agent | Model | Purpose |
|---|---:|---|
| `securescan` | Opus | Full orchestrator for the 4-phase audit workflow |
| `securescan-recon` | Sonnet | Phase 1: scope, file manifest, architecture, data, auth, AI, dependencies, CI/CD |
| `securescan-scanner` | Sonnet | Phase 2: file-by-file vulnerability scan with coverage tracking |
| `securescan-analyst` | Opus | Phase 3: exploitability validation, false-positive closure, severity, STRIDE, attack chains |
| `securescan-reporter` | Opus | Phase 4: final report assembly and quality gate |

### Skills

| Skill | Content |
|---|---|
| `owasp-web-api` | OWASP Web Top 10:2025, API Security Top 10:2023, CWE hunting cues |
| `owasp-ai-agentic` | OWASP LLM Top 10:2025, Agentic Applications Top 10:2026, AI-specific checklist |
| `scan-patterns` | Static patterns and optional tool-assisted checks for app, infra, CI/CD, serverless, AI |
| `hipaa-compliance` | Current HIPAA Security Rule checks plus clearly labeled proposed-rule readiness checks |
| `nist-ai-rmf` | NIST AI RMF Govern/Map/Measure/Manage evidence matrix and status rules |
| `security-report` | Finding template, CVSS method, confidence ratings, QA gates, report templates |

### Package Assets

| Path | Purpose |
|---|---|
| `bin/securescan` | One-command CLI for doctor, demo, scan, validate, install, and export workflows |
| `scripts/securescan.sh` | Shell wrapper for the SecureScan CLI |
| `scripts/securescan.py` | Python CLI implementation and export generator |
| `scripts/build-overview-docx.py` | Rebuilds the Word overview from the canonical Markdown overview |
| `scripts/install.sh` | Safe installer for project-local or global Claude Code installation |
| `scripts/securescan-static.sh` | Dependency-free static scanner that generates SecureScan artifacts without Claude agents |
| `scripts/validate-package.sh` | Validates package structure, frontmatter, docs, scripts, and hardening requirements |
| `scripts/validate-securescan-artifacts.sh` | Validates generated `.securescan/` audit artifacts in a target project |
| `scripts/validate-demo-audit.sh` | Checks a vulnerable-demo audit for expected vulnerability themes |
| `templates/` | Scope, recon, coverage, and report-checklist templates |
| `examples/vulnerable-demo/` | Intentionally vulnerable fixture plus golden output for regression testing |
| `SOURCES.md` | Official source registry and freshness policy |
| `SECURITY.md` | Authorized-use and responsible-disclosure guidance |
| `docs/SECURESCAN-OVERVIEW.md` | Product overview, value proposition, operating modes, and FAQ |

## Quick Install

Project-local install:

```bash
bash scripts/install.sh --project /path/to/your/project
```

Global install:

```bash
bash scripts/install.sh --global
```

Dry run:

```bash
bash scripts/install.sh --project /path/to/your/project --dry-run
```

Validate this package before distributing it:

```bash
bin/securescan doctor
```

For a faster environment-only check:

```bash
bin/securescan doctor --skip-package-check
```

## Running An Audit

Recommended CLI path:

```bash
bin/securescan scan /path/to/project --format all --yes
```

This writes `.securescan/` artifacts, validates the generated artifact set, prints a severity/coverage summary, and writes JSON, SARIF, HTML, and Markdown exports under `.securescan/exports/`.

Deterministic local static scan:

```bash
bash scripts/securescan-static.sh --project /path/to/project
```

Write artifacts somewhere other than `/path/to/project/.securescan`:

```bash
bash scripts/securescan-static.sh --project /path/to/project --output /tmp/securescan-output
```

Full static audit:

```text
@securescan Run a full authorized static security audit of this codebase
```

Phase-by-phase audit:

```text
@securescan-recon Map this codebase for an authorized security audit
@securescan-scanner Scan this codebase for vulnerabilities
@securescan-analyst Validate and analyze the findings
@securescan-reporter Generate the final audit report
```

Targeted scans:

```text
@securescan-scanner Scan only the authentication code in /src/auth
@securescan-scanner Scan all AI/LLM integration code for prompt injection
@securescan-scanner Scan CI/CD pipeline files for secrets exposure
```

## Output Contract

All audit artifacts are written under `.securescan/` in the target project:

```text
.securescan/
├── 00-scope.md          # Authorization, scope, assumptions, prohibited actions
├── file-manifest.tsv    # Recon-created file list and scan priority
├── 01-recon.md          # Architecture map, entry points, data classification, risk map
├── 02-findings.md       # Raw findings grouped by framework/category
├── coverage.json        # Machine-readable scanner coverage and skipped-file reasons
├── nist-ai-rmf-evidence.md # Govern/Map/Measure/Manage evidence matrix when AI RMF is applicable
├── 03-analysis.md       # Validated findings, false positives, STRIDE, attack chains, compliance
├── 04-report.md         # Final audit-ready report
├── exports/             # Optional CLI exports: JSON, SARIF, HTML, Markdown
└── tool-runs/           # Optional outputs from approved/local tools, redacted where needed
```

Validate a completed audit:

```bash
bin/securescan validate --project /path/to/audited/project
```

Validate a SecureScan run against the included vulnerable demo:

```bash
bin/securescan validate --project /path/to/vulnerable-demo --demo
```

Run and validate the deterministic scanner against the included vulnerable demo:

```bash
bin/securescan demo --format all
```

Validate the bundled golden output fixture:

```bash
bash scripts/validate-demo-audit.sh --artifacts examples/vulnerable-demo/golden-output
```

## Enterprise Guardrails

- Static review is the default mode.
- `bin/securescan` is the recommended first-run interface.
- `securescan-static.sh` provides a deterministic artifact-generating scanner path.
- Scope is recorded before scanning in `.securescan/00-scope.md`.
- The scanner must record coverage in `.securescan/coverage.json`.
- Every skipped file or directory needs a reason.
- Confirmed findings require proof of exploitability.
- Dynamic PoCs, network probes, dependency installation, and destructive checks require explicit approval.
- HIPAA proposed-rule checks must be labeled as proposed-readiness, not current legal obligations.
- Reports must separate confirmed, likely, possible, closed, and out-of-scope items.
- Demo regression output must continue finding SQL injection, XSS, permissive CORS, missing rate limiting, fallback-key, mutable CI action, and Docker hardening themes.

## Frameworks Covered

- OWASP Top 10 Web Application Security Risks 2025
- OWASP API Security Top 10 2023
- OWASP Top 10 for LLM Applications 2025
- OWASP Top 10 for Agentic Applications 2026
- HIPAA Security Rule current safeguards plus 2025 NPRM proposed-readiness checks
- NIST AI RMF 1.0 Govern / Map / Measure / Manage evidence matrix
- STRIDE threat modeling
- CWE taxonomy
- CVSS v3.1 with contextual adjustment
- PTES-inspired static audit workflow
- NIST CSF 2.0 / SOC 2 / HITRUST alignment summaries

## Cost Notes

Costs vary by codebase size, model routing, and how many files require deep review. Treat any static estimate as a rough planning number, not a guarantee. Use phase-by-phase mode on large repositories to control scope and review coverage before continuing.

## Before Public Distribution

This package does not assert a public open-source license. Set the intended license and legal notices before distributing outside your organization.
