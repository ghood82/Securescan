# SecureScan Complete Guide

## Purpose

SecureScan is an authorization-first security-audit package for local code review, Claude Code-assisted audits, and repeatable evidence generation. It helps teams inspect software projects for application security, API security, AI/LLM security, agentic workflow risk, CI/CD risk, container hardening issues, dependency posture signals, and HIPAA-oriented readiness.

SecureScan is designed to produce auditable artifacts, not just console output. A normal run creates scope, recon, findings, coverage, NIST AI RMF evidence, analysis, final report, and export files that can be reviewed by engineering, security, compliance, or customer-diligence teams.

## Operating Modes

SecureScan has three operating modes:

1. SecureScan CLI: the easiest entry point for doctor, demo, scan, validate, install, and export workflows.
2. Deterministic static scanner: a local Python scanner that generates the full `.securescan/` artifact set without Claude agents.
3. Claude Code agent workflow: a deeper multi-agent audit path with recon, scanner, analyst, and reporter agents.

The CLI and deterministic scanner are static-first. They do not perform active exploitation, external network scanning, credentialed production probing, dependency installation, or destructive tests unless a user explicitly authorizes a separate workflow.

## What SecureScan Checks

SecureScan combines several security review lenses:

- OWASP Top 10 Web Application Security Risks 2025
- OWASP API Security Top 10 2023
- OWASP Top 10 for LLM Applications 2025
- OWASP Top 10 for Agentic Applications 2026
- NIST AI RMF 1.0 Govern / Map / Measure / Manage evidence matrix
- CWE taxonomy
- CVSS v3.1 scoring with contextual severity adjustment
- STRIDE threat modeling
- HIPAA Security Rule current-safeguard readiness
- HIPAA NPRM proposed-readiness checks, clearly labeled as proposed
- CI/CD and software supply chain risk
- Docker/container hardening
- Secret handling and accidental exposure
- Static dependency posture signals

## Current Static Patterns

The deterministic scanner currently looks for common evidence-backed issues including:

- SQL injection through string-built SQL or interpolated Python queries
- Reflected XSS and DOM XSS through unsafe HTML sinks
- Permissive CORS
- Missing login rate limiting
- Stack trace exposure
- Fallback secret-like values
- Mutable GitHub Actions tags
- Docker `latest` image tags
- Containers without a non-root runtime user
- Missing JavaScript lockfiles
- Unsafe Python shell execution
- Unsafe YAML loading

The static scanner is intentionally conservative. It can flag likely risk patterns and capture code evidence, but some findings still require human analyst validation or runtime testing before they should be treated as confirmed exploitable vulnerabilities.

## What Gets Generated

SecureScan writes audit artifacts into `.securescan/` by default. The output folder can be changed with `--output`.

| Artifact | Purpose |
|---|---|
| `00-scope.md` | Authorization, scope, assumptions, allowed mode, and prohibited actions |
| `file-manifest.tsv` | File inventory with type, risk tier, scan requirement, and reason |
| `01-recon.md` | Architecture, entry points, data classification, auth, AI, dependencies, CI/CD, and high-risk areas |
| `02-findings.md` | Raw static findings grouped by finding ID and category |
| `coverage.json` | Machine-readable coverage, skipped-file reasons, patterns applied, and optional tool runs |
| `nist-ai-rmf-evidence.md` | NIST AI RMF Govern/Map/Measure/Manage evidence matrix |
| `03-analysis.md` | Validated findings, false-positive review, STRIDE, attack chains, HIPAA, AI RMF summary, and coverage risk |
| `04-report.md` | Final audit-ready report |
| `exports/summary.json` | Machine-readable summary of counts, coverage, and top findings |
| `exports/findings.json` | Machine-readable findings and coverage package |
| `exports/securescan.sarif` | SARIF output for security tooling ingestion |
| `exports/report.html` | Browser-readable report |
| `exports/securescan-summary.md` | Short Markdown summary |

## How To Run It

From the SecureScan package directory:

```bash
cd /Users/garethhood/Desktop/SecureScan-Package
```

Check readiness:

```bash
bin/securescan doctor
```

Run the built-in vulnerable demo and generate all exports:

```bash
bin/securescan demo --format all
```

Run a static audit against a real project:

```bash
bin/securescan scan /path/to/project --format all --yes
```

Run with an interactive scope wizard:

```bash
bin/securescan scan /path/to/project --wizard
```

Write artifacts somewhere outside the target project:

```bash
bin/securescan scan /path/to/project --output /private/tmp/securescan-output --format all --yes
```

Validate an existing artifact set:

```bash
bin/securescan validate --project /path/to/project --phase 4
```

Export an existing artifact set:

```bash
bin/securescan export --project /path/to/project --format all
```

## How To Interpret A Scan

Start with `04-report.md` or `exports/report.html`. These are the most readable outputs.

Then review:

- `exports/summary.json` for counts, coverage, and top findings.
- `03-analysis.md` for validation details, STRIDE, attack chains, and limitations.
- `coverage.json` to confirm what was actually scanned.
- `nist-ai-rmf-evidence.md` when the project includes AI, LLM, RAG, agentic, prompt, vector, memory, or tool-calling surfaces.
- `02-findings.md` when you need raw scanner evidence before analyst filtering.

High findings should be triaged first. Likely findings should be reviewed against real data flow, framework protections, and runtime configuration before remediation is planned. Findings under generated, vendored, backup, or agent-worktree folders should be separated from application-owned code before making engineering decisions.

## NIST AI RMF Evidence Matrix

SecureScan now generates a dedicated NIST AI RMF evidence matrix at:

```text
.securescan/nist-ai-rmf-evidence.md
```

The matrix covers the four NIST AI RMF functions:

- Govern: policy, accountability, workforce roles, risk culture, stakeholder engagement, and third-party AI supply chain.
- Map: AI context, system categorization, capabilities, component risks, and potential impacts.
- Measure: metrics, trustworthy characteristics, monitoring mechanisms, and feedback on measurement quality.
- Manage: risk prioritization, treatment, benefits, third-party risk, response, recovery, and communications.

Each row uses one of these status values:

- Compliant: evidence shows the outcome is implemented and operating.
- Partial: some evidence exists, but scope, enforcement, monitoring, or ownership is incomplete.
- Gap: missing or materially insufficient evidence.
- Not Applicable: outside the authorized scope or not relevant to the system.
- Not Assessed: the scan did not have enough evidence, access, or approval to assess it.

The matrix is evidence and alignment support. It is not a certification statement. Static code review can identify AI-sensitive surfaces, technical risks, and gaps in observable controls, but governance and lifecycle rows often require policies, owner interviews, monitoring evidence, model/provider records, test results, incident history, or risk-acceptance records.

## Claude Code Agent Workflow

The package includes five Claude Code agents:

| Agent | Purpose |
|---|---|
| `securescan` | Full orchestrator for the four-phase audit workflow |
| `securescan-recon` | Scope, manifest, architecture, data, auth, AI, dependency, and CI/CD recon |
| `securescan-scanner` | File-by-file vulnerability candidate scan with coverage tracking |
| `securescan-analyst` | Exploitability validation, false-positive closure, severity, STRIDE, attack chains, HIPAA, and NIST AI RMF evidence |
| `securescan-reporter` | Final report assembly and quality gate |

Typical Claude Code prompt:

```text
@securescan Run a full authorized static security audit of this codebase
```

Targeted prompts:

```text
@securescan-scanner Scan all AI/LLM integration code for prompt injection and insecure output handling
@securescan-recon Map only API endpoints and authentication requirements
@securescan-analyst Validate findings SCAN-001 through SCAN-010
@securescan-reporter Generate the final audit report
```

## Skills Included

| Skill | Content |
|---|---|
| `owasp-web-api` | OWASP Web Top 10 2025, OWASP API Security Top 10 2023, and CWE hunting cues |
| `owasp-ai-agentic` | OWASP LLM Top 10 2025, Agentic Applications Top 10 2026, and AI-specific checklist |
| `scan-patterns` | Static patterns and optional tool-assisted checks for app, infra, CI/CD, serverless, and AI |
| `hipaa-compliance` | HIPAA Security Rule checks plus clearly labeled proposed-readiness checks |
| `nist-ai-rmf` | NIST AI RMF Govern/Map/Measure/Manage evidence matrix guidance |
| `security-report` | Finding template, CVSS method, confidence ratings, QA gates, report templates |

## Validation And Quality Gates

SecureScan validates both the package and generated audit artifacts.

Package validation checks:

- Required directories and files exist.
- Agent and skill frontmatter is valid.
- Shell and Python scripts compile.
- Source registry has verification dates.
- HIPAA proposed-readiness language is not overstated.
- CI actions are pinned.
- Golden fixture artifacts validate.
- The vulnerable demo regression still finds expected issue themes.
- CLI doctor, scan, validation, and export paths work.
- NIST AI RMF evidence matrix wiring is present.

Artifact validation checks:

- Scope, recon, findings, coverage, NIST AI RMF evidence, analysis, and report files exist.
- `coverage.json` is valid JSON with expected schema.
- NIST AI RMF evidence includes Govern, Map, Measure, and Manage rows.
- Reports include executive summary, scope, validated findings, remediation, and risk acceptance.
- Generated artifacts do not contain obvious raw secret patterns.

## Export Formats

SecureScan supports several export formats:

| Format | Use |
|---|---|
| Markdown | Human-readable project artifact and lightweight sharing |
| HTML | Browser-readable report for review |
| JSON | Automation, dashboards, and downstream processing |
| SARIF | Security tool ingestion and code-scanning workflows |

Use `--format all` when you want the full set.

## Safety Model

SecureScan is safe-by-default:

- It starts with scope and authorization.
- It defaults to static local review.
- It does not run active exploit tests by default.
- It does not probe external networks by default.
- It does not install dependencies by default.
- It does not require production credentials.
- It records secret existence and location, but should not print raw secret values.
- It treats generated audit artifacts as sensitive security evidence.

## What SecureScan Is Not

SecureScan is not a replacement for:

- A qualified manual penetration test.
- Runtime DAST against an approved environment.
- Cloud account configuration review with live credentials.
- Legal advice about HIPAA, NIST, SOC 2, HITRUST, or other obligations.
- A full software composition analysis platform.
- A managed vulnerability remediation program.
- A certification engine for NIST AI RMF.

It is best understood as a structured static audit workflow that produces evidence and gives teams a strong starting point for remediation, customer diligence, security review, and deeper manual testing.

## Recommended User Workflow

1. Run `bin/securescan doctor`.
2. Run `bin/securescan demo --format all` once to understand the output.
3. Run `bin/securescan scan /path/to/project --format all --yes`.
4. Open `04-report.md` or `exports/report.html`.
5. Check `coverage.json` for scanned, skipped, and partial areas.
6. Separate owned application code findings from generated, vendored, backup, or worktree findings.
7. Review `nist-ai-rmf-evidence.md` if AI or agentic components exist.
8. Triage High findings first.
9. Validate likely findings against real runtime flow and framework protections.
10. Create remediation tickets with owner, severity, verification test, and reassessment date.

## Example Result Interpretation

A result such as:

```text
Findings: 93 total (Critical 0, High 9, Medium 68, Low 16)
Coverage: 100.0% (2635 scanned, 0 skipped)
```

means SecureScan inspected all files it considered in scope and produced 93 static findings. It does not automatically mean all 93 are application-owned production issues. Review paths carefully. Findings under `.claude/worktrees`, generated folders, vendored dependencies, backups, or tool caches may need to be filtered out before prioritizing application remediation.

## Best Practices

- Run scans with `--output /private/tmp/...` when you do not want to write `.securescan/` into the target project.
- Treat `.securescan/` as sensitive.
- Review the file manifest before making decisions from the report.
- Re-run validation before sharing results.
- Use SARIF and JSON exports for automation.
- Use the NIST AI RMF matrix as an evidence tracker, not a compliance claim.
- Re-check official sources before formal external reports.
- Pair SecureScan output with human review for high-risk or customer-facing conclusions.

## Current Package Entry Points

| Command | Purpose |
|---|---|
| `bin/securescan doctor` | Check local package readiness |
| `bin/securescan demo --format all` | Run the bundled vulnerable demo and generate exports |
| `bin/securescan scan /path/to/project --format all --yes` | Run a real static audit |
| `bin/securescan scan /path/to/project --wizard` | Run a scan with interactive scope setup |
| `bin/securescan validate --project /path/to/project --phase 4` | Validate generated artifacts |
| `bin/securescan export --project /path/to/project --format all` | Export an existing audit |
| `bin/securescan install --project /path/to/project` | Install agents and skills into one project |
| `bin/securescan install --global` | Install agents and skills globally |
