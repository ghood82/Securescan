# SecureScan Overview

## What SecureScan Is

SecureScan is a security-audit toolkit for Claude Code and local static analysis. It helps teams review codebases for application security, API security, AI/LLM security, agentic workflow risks, CI/CD risks, container hardening issues, dependency posture, and HIPAA-oriented readiness.

It has three operating modes:

1. **SecureScan CLI** - A one-command interface for doctor, demo, scan, validate, install, and export workflows.
2. **Claude Code agent workflow** - A multi-agent audit process that performs recon, scanning, analyst validation, and final reporting.
3. **Deterministic static scanner** - A dependency-free local scanner that generates the same `.securescan/` artifact set without invoking Claude agents.

SecureScan is static-first and authorization-first. It does not perform active exploitation, external network scanning, dependency installation, production probing, or credentialed testing unless explicitly approved.

## Value Proposition

Security reviews often fail in two ways: they are either too shallow and pattern-based, or they produce long reports with weak evidence. SecureScan is designed to sit between lightweight linting and a full manual penetration test.

It gives teams:

- **A repeatable audit workflow** - Scope, recon, raw findings, validation, coverage, and final report are produced as separate artifacts.
- **Evidence-backed findings** - Findings require file paths, line numbers, code snippets, category mapping, confidence, severity, remediation, and verification guidance.
- **Coverage accountability** - The scanner writes `coverage.json` so reviewers can see what was scanned, partially scanned, skipped, and why.
- **AI-era security coverage** - SecureScan explicitly checks LLM prompts, RAG/vector boundaries, agent tools, MCP surfaces, memory/context poisoning, and excessive agency.
- **AI risk-management evidence** - SecureScan can produce a dedicated NIST AI RMF Govern/Map/Measure/Manage evidence matrix with status, evidence links, residual risk, owner, and next action fields.
- **Healthcare readiness support** - HIPAA current-rule checks are separated from proposed-readiness checks so reports do not overstate legal obligations.
- **Operational utility** - A local static scanner can generate artifacts in CI or developer workflows even when Claude Code agents are not running.
- **Enterprise guardrails** - Scope, authorization, secret redaction, proposed-rule labeling, CI validation, and regression fixtures are built into the package.

## Who It Is For

SecureScan is useful for:

- Engineering teams preparing for a security review or customer due diligence.
- Startups that need a structured security posture report before enterprise sales.
- Healthcare SaaS teams reviewing ePHI-adjacent systems and HIPAA readiness.
- AI product teams building LLM, RAG, agent, MCP, or tool-calling workflows.
- Security engineers who want AI-assisted review artifacts with line-level evidence.
- Consultants who need a repeatable report structure and auditable workflow.

## What It Checks

SecureScan covers:

- OWASP Top 10 Web Application Security Risks 2025
- OWASP API Security Top 10 2023
- OWASP Top 10 for LLM Applications 2025
- OWASP Top 10 for Agentic Applications 2026
- NIST AI RMF 1.0 Govern / Map / Measure / Manage evidence matrix
- CWE mapping
- CVSS v3.1 scoring and contextual severity adjustment
- STRIDE threat modeling
- HIPAA Security Rule current safeguards
- HIPAA NPRM proposed-readiness checks
- CI/CD and software supply chain issues
- Docker/container hardening
- Secret handling and accidental exposure
- Static dependency posture signals

The deterministic scanner currently includes static checks for common issues such as:

- SQL injection through string-built queries
- Reflected and DOM XSS
- Permissive CORS
- Missing login rate limiting
- Stack trace exposure
- Fallback secret-like values
- Mutable GitHub Actions tags
- Docker `latest` tags
- Containers without a non-root runtime user
- Missing JavaScript lockfiles
- Unsafe Python shell execution, SQL interpolation, and YAML loading

## How The Workflow Works

SecureScan writes all audit artifacts to `.securescan/` in the target project.

| Artifact | Purpose |
|---|---|
| `00-scope.md` | Authorization, scope, assumptions, and prohibited actions |
| `file-manifest.tsv` | File inventory with risk tier and scan requirement |
| `01-recon.md` | Architecture map, entry points, data classification, auth, AI, dependency, and CI/CD inventory |
| `02-findings.md` | Raw static findings grouped by category |
| `coverage.json` | Machine-readable coverage, skipped-file reasons, patterns applied, and tool runs |
| `nist-ai-rmf-evidence.md` | NIST AI RMF Govern/Map/Measure/Manage evidence matrix when AI RMF is applicable |
| `03-analysis.md` | Validated findings, confidence, severity, false-positive review, STRIDE, attack chains, and compliance context |
| `04-report.md` | Final audit-ready report |
| `tool-runs/` | Optional local tool outputs when approved and available |

## Running SecureScan

Recommended CLI path:

```bash
bin/securescan scan /path/to/project --format all --yes
```

Interactive scope setup:

```bash
bin/securescan scan /path/to/project --wizard
```

Export an existing audit:

```bash
bin/securescan export --project /path/to/project --format all
```

Run the deterministic scanner:

```bash
bash scripts/securescan-static.sh --project /path/to/project
```

Write output somewhere else:

```bash
bash scripts/securescan-static.sh --project /path/to/project --output /tmp/securescan-output
```

Validate generated artifacts:

```bash
bin/securescan validate --project /path/to/project --phase 4
```

Run the built-in vulnerable demo regression:

```bash
bin/securescan demo --format all
```

Run the Claude Code orchestrator:

```text
@securescan Run a full authorized static security audit of this codebase
```

## What Makes It Different

SecureScan is not just a list of grep patterns. The package enforces an audit contract:

- A scope file exists before scanning.
- Recon produces a manifest before scanning.
- Coverage is machine-readable.
- Findings are separated into raw candidates and validated results.
- Reports distinguish Confirmed, Likely, Possible, False Positive, and Out-of-Scope items.
- HIPAA proposed-rule material is labeled as proposed-readiness.
- The package validates itself through CI and a golden-output vulnerable demo fixture.

## What It Is Not

SecureScan is not a replacement for:

- A qualified manual penetration test.
- Runtime DAST against an approved environment.
- Cloud account configuration review with live credentials.
- Legal advice about HIPAA or other regulatory obligations.
- A full software composition analysis platform.
- A managed vulnerability remediation program.

It is best understood as a structured, evidence-producing static audit workflow that can be used before, during, or after deeper manual security testing.

## Safety And Data Handling

SecureScan is designed for authorized local review. Reports may contain sensitive architecture details and vulnerability information, so `.securescan/` should be treated as sensitive.

By default:

- Static review is allowed.
- Active exploitation is not allowed.
- External network scanning is not allowed.
- Production probing is not allowed.
- Dependency installation/downloads are not allowed.
- Raw secrets should not be printed in reports.

## Enterprise Readiness

SecureScan includes:

- One-command CLI front door
- Safe installer with project/global modes
- Package validator
- Artifact validator
- Demo regression validator
- Pinned CI workflow
- Canonical version file
- Source registry with verification dates
- Golden output fixture
- Scope and coverage templates
- Current-rule vs proposed-readiness regulatory language

This makes the package suitable for internal security workflows, pre-sales due diligence, engineering readiness reviews, and structured AI-assisted audit preparation.

## Common Questions

### Can SecureScan run without Claude Code?

Yes. `bin/securescan scan` and `scripts/securescan-static.sh` run locally with Python 3 and write the full artifact set.

### Can SecureScan use Claude Code?

Yes. The package includes Claude Code agents and skills for deeper multi-phase analysis and reporting.

### Does SecureScan install dependencies?

No. The deterministic scanner is dependency-free. Optional tools such as Semgrep, gitleaks, Trivy, or pip-audit can be used separately when installed and approved.

### Does SecureScan send code to external services?

The deterministic scanner does not. Claude Code usage depends on how Claude Code is configured in the user's environment.

### Does SecureScan prove exploitability?

It can identify static proof paths for certain issues, but dynamic exploit testing requires explicit authorization and a suitable test environment.

### Should `.securescan/` be committed?

Usually no. Treat generated audit artifacts as sensitive. Commit them only if your organization has an intentional internal evidence-retention policy.

## Current Status

Current package version: `2.4.0`

Validated acceptance path:

```bash
bin/securescan doctor
bin/securescan demo --format all
bin/securescan export --artifacts examples/vulnerable-demo/golden-output --format all
```
