# SecureScan v2.4 Usage Guide

## 1. First Run

Check the package and local environment:

```bash
bin/securescan doctor
```

Run the bundled demo:

```bash
bin/securescan demo --format all
```

Run a static audit with validated artifacts and exports:

```bash
bin/securescan scan /path/to/project --format all --yes
```

The CLI prints finding counts, coverage, top remediation items, the final report path, and export paths.

## 2. Install

Install SecureScan agents and skills to one project:

```bash
bin/securescan install --project /path/to/project
```

Install globally:

```bash
bin/securescan install --global
```

Validate the package:

```bash
bin/securescan doctor
```

The installer refuses to overwrite different existing files unless you pass `--force`.

The repository also includes CI at `.github/workflows/validate.yml`, which runs the package validator, CLI doctor check, golden artifact validator, vulnerable-demo regression validator, static scanner, and export validation.

## 3. Run A Full Audit

Recommended CLI path:

```bash
bin/securescan scan /path/to/project --format all --yes
```

Interactive scope setup:

```bash
bin/securescan scan /path/to/project --wizard
```

Deterministic static scan:

```bash
bash scripts/securescan-static.sh --project /path/to/project
```

This writes the full `.securescan/` artifact set without invoking Claude agents.

```text
@securescan Run a full authorized static security audit of this codebase
```

The orchestrator creates `.securescan/00-scope.md` first, then runs:

1. Recon
2. Scanner
3. Analyst
4. Reporter

## 4. Run Phase By Phase

Phase 1 - recon:

```text
@securescan-recon Map this codebase for an authorized security audit
```

Review:

```text
.securescan/00-scope.md
.securescan/file-manifest.tsv
.securescan/01-recon.md
```

Phase 2 - scanner:

```text
@securescan-scanner Scan this codebase for vulnerabilities
```

Review:

```text
.securescan/02-findings.md
.securescan/coverage.json
```

Phase 3 - analyst:

```text
@securescan-analyst Validate and analyze the findings
```

Review:

```text
.securescan/nist-ai-rmf-evidence.md
.securescan/03-analysis.md
```

Phase 4 - reporter:

```text
@securescan-reporter Generate the final audit report
```

Final deliverable:

```text
.securescan/04-report.md
```

## 5. Targeted Scans

```text
@securescan-scanner Scan only the authentication code in /src/auth and /src/middleware
@securescan-scanner Scan all AI/LLM integration code for prompt injection and insecure output handling
@securescan-scanner Scan CI/CD pipeline files in .github/workflows for secrets exposure
@securescan-recon Map only the API endpoints and their authentication requirements
@securescan-analyst Validate just findings SCAN-001 through SCAN-010
```

For targeted scans, update `.securescan/00-scope.md` so the report can distinguish reviewed, not reviewed, and intentionally out-of-scope areas.

## 6. Optional Tool-Assisted Checks

If these tools are already installed in the target environment, the scanner can use them as supporting evidence:

- `rg`
- `semgrep`
- `gitleaks`
- `trufflehog`
- `osv-scanner`
- `npm audit`
- `pip-audit`
- `trivy`
- `checkov`

Do not install tools, download dependencies, or contact external services unless the user explicitly approves that action.

## 7. Validate Generated Audit Artifacts

```bash
bin/securescan validate --project /path/to/project
```

For an in-progress audit, validate only up to a phase:

```bash
bin/securescan validate --project /path/to/project --phase 2
```

Validate the built-in vulnerable-demo golden output:

```bash
bash scripts/validate-demo-audit.sh --artifacts examples/vulnerable-demo/golden-output
```

After running SecureScan against `examples/vulnerable-demo`, validate the actual generated audit:

```bash
bash scripts/validate-demo-audit.sh --project examples/vulnerable-demo
```

Run and validate the bundled deterministic scanner:

```bash
bin/securescan demo --format all
```

Export an existing audit:

```bash
bin/securescan export --project /path/to/project --format all
```

Exports are written under `.securescan/exports/` by default:

- `summary.json`
- `findings.json`
- `securescan.sarif`
- `report.html`
- `securescan-summary.md`

## 8. Re-running Phases

```text
@securescan-scanner Continue scanning directories listed as Partial or Skipped in the coverage log
@securescan-analyst Re-analyze finding SCAN-003 after checking the middleware chain
@securescan-reporter Regenerate the report focused on HIPAA proposed-readiness gaps
```

## 9. Artifact Handling

Add `.securescan/` to the target project's `.gitignore` unless the organization intentionally commits audit artifacts for an internal evidence trail.

Never commit real secrets, raw tokens, customer data, patient data, or unredacted exploit output.
