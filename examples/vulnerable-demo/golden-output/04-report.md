# SecureScan Final Report

Target: `/Users/garethhood/Desktop/SecureScan-Package/examples/vulnerable-demo`
Date: 2026-05-15
Methodology: SecureScan deterministic static runner v2.4.0

## Executive Summary

Posture score: 1/10.

Finding counts:

- Critical: 0
- High: 1
- Medium: 3
- Low: 8
- Informational: 0

Top risks:

1. SQL Injection Through String-Built Query in `src/server.js:15`
2. Missing Login Rate Limiting in `src/server.js:27`
3. Reflected XSS In Server HTML Response in `src/server.js:40`
4. DOM XSS Through Unsafe HTML Sink in `src/client.js:4`
5. Fallback Secret-Like Value in `src/server.js:8`

## Scope

Static local review of files discovered under the target project. Runtime exploit testing, external network testing, dependency installation, and production access were out of scope.

## Coverage

Static scanner coverage: 100.0 percent coverage according to `coverage.json`.

## Validated Findings

### F-003 - SQL Injection Through String-Built Query

Severity: High
Confidence: Confirmed
Location: `src/server.js:15`
Evidence: `  const sql = "SELECT * FROM users WHERE email = '" + email + "'";`
Remediation: Use parameterized queries, prepared statements, or ORM query builders.
Verification: Add a regression test proving injection payloads are treated as data.
### F-005 - Missing Login Rate Limiting

Severity: Medium
Confidence: Likely
Location: `src/server.js:27`
Evidence: `app.post("/login", (req, res) => {`
Remediation: Add per-IP and per-account rate limiting plus alerting for repeated failures.
Verification: Add tests that repeated login attempts are throttled.
### F-006 - Reflected XSS In Server HTML Response

Severity: Medium
Confidence: Confirmed
Location: `src/server.js:40`
Evidence: `  res.send("<h1>Hello " + name + "</h1>");`
Remediation: Escape output or render through a safe template engine.
Verification: Add a test proving script tags are escaped in the response.
### F-012 - DOM XSS Through Unsafe HTML Sink

Severity: Medium
Confidence: Confirmed
Location: `src/client.js:4`
Evidence: `document.getElementById("message").innerHTML = message;`
Remediation: Use textContent or a vetted sanitizer with strict allowlists.
Verification: Add a browser/unit test showing HTML input is rendered as text.
### F-001 - Fallback Secret-Like Value

Severity: Low
Confidence: Possible
Location: `src/server.js:8`
Evidence: `const demoFallbackApiKey = process.env.DEMO_API_KEY || "DEMO_ONLY_NOT_A_SECRET";`
Remediation: Fail closed when required secrets are missing outside local fixtures.
Verification: Add startup validation that rejects missing production secrets.


## Attack Chains

Potential chains should be reviewed by a human analyst. The static runner highlights likely chain surfaces across user input, output handling, authentication, CI/CD, and container boundaries.

	## Compliance Matrices

	HIPAA: Not Assessed unless ePHI indicators are present. Proposed-rule items must be labeled proposed-readiness.

	OWASP coverage is mapped per finding using the category field in `02-findings.md` and `03-analysis.md`.

NIST AI RMF: see `nist-ai-rmf-evidence.md` for the dedicated Govern, Map, Measure, and Manage evidence matrix.

## Remediation Roadmap

0-48hr: Fix High and confirmed Medium findings.

1-2wk: Fix remaining Medium findings and add regression tests.

1-3mo: Add CI policies for dependency, secrets, container, and IaC checks.

## Testing Recommendations

Run SAST, dependency scanning, secret scanning, IaC scanning, and targeted dynamic tests with explicit approval.

## Risk Acceptance

No risks are accepted by this static runner. Deferred findings require an owner, justification, compensating controls, residual risk, and reassessment date.
