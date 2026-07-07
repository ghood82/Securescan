# SecureScan Analysis

## Validation Summary

12 raw findings were reviewed by the deterministic static runner. The runner provides static validation and marks runtime-dependent items as Likely or Possible.

## Validated Findings

### FINDING: F-001 - Fallback Secret-Like Value

Severity: Low
CVSS Base: 3.7 - CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N
Effective: Low
Confidence: Possible
Data Class: L3
OWASP: A04
CWE: CWE-798
Location: src/server.js:8

Vulnerable Code:
`const demoFallbackApiKey = process.env.DEMO_API_KEY || "DEMO_ONLY_NOT_A_SECRET";`

Proof Of Exploitability:
Static evidence: Environment-backed secret has a literal fallback; impact depends on environment use.

Attack Scenario:
An attacker who can influence the relevant input or build surface may trigger this weakness if no upstream control blocks it.

Compensating Controls:
Not proven by static runner. Manual analyst review should verify framework protections and deployment controls.

Root Cause:
Insecure default

Remediation:
Fail closed when required secrets are missing outside local fixtures.

Verification:
Add startup validation that rejects missing production secrets.

### FINDING: F-002 - Permissive CORS Configuration

Severity: Low
CVSS Base: 4.3 - CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N
Effective: Low
Confidence: Likely
Data Class: L2
OWASP: API8
CWE: CWE-942
Location: src/server.js:11

Vulnerable Code:
`app.use(cors({ origin: "*" }));`

Proof Of Exploitability:
Static evidence: CORS is permissive; impact depends on credentialed responses and sensitive endpoints.

Attack Scenario:
An attacker who can influence the relevant input or build surface may trigger this weakness if no upstream control blocks it.

Compensating Controls:
Not proven by static runner. Manual analyst review should verify framework protections and deployment controls.

Root Cause:
Insecure default

Remediation:
Restrict allowed origins per environment and avoid wildcard on sensitive APIs.

Verification:
Add an integration test that disallowed origins do not receive CORS approval.

### FINDING: F-003 - SQL Injection Through String-Built Query

Severity: High
CVSS Base: 8.1 - CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
Effective: High
Confidence: Confirmed
Data Class: L2
OWASP: A05
CWE: CWE-89
Location: src/server.js:15

Vulnerable Code:
`  const sql = "SELECT * FROM users WHERE email = '" + email + "'";`

Proof Of Exploitability:
Static evidence: SQL is built with string interpolation or concatenation; verify whether user input reaches it.

Attack Scenario:
An attacker who can influence the relevant input or build surface may trigger this weakness if no upstream control blocks it.

Compensating Controls:
Not proven by static runner. Manual analyst review should verify framework protections and deployment controls.

Root Cause:
Insufficient input validation

Remediation:
Use parameterized queries, prepared statements, or ORM query builders.

Verification:
Add a regression test proving injection payloads are treated as data.

### FINDING: F-004 - Stack Trace Exposure

Severity: Low
CVSS Base: 3.7 - CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N
Effective: Low
Confidence: Likely
Data Class: L2
OWASP: A10
CWE: CWE-209
Location: src/server.js:19

Vulnerable Code:
`      res.status(500).send(err.stack);`

Proof Of Exploitability:
Static evidence: Stack traces can disclose internals to clients.

Attack Scenario:
An attacker who can influence the relevant input or build surface may trigger this weakness if no upstream control blocks it.

Compensating Controls:
Not proven by static runner. Manual analyst review should verify framework protections and deployment controls.

Root Cause:
Mishandling exceptional conditions

Remediation:
Return generic errors to clients and log detailed errors server-side.

Verification:
Add a test that error responses do not contain stack traces.

### FINDING: F-005 - Missing Login Rate Limiting

Severity: Medium
CVSS Base: 5.3 - CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L
Effective: Medium
Confidence: Likely
Data Class: L2
OWASP: API4
CWE: CWE-770
Location: src/server.js:27

Vulnerable Code:
`app.post("/login", (req, res) => {`

Proof Of Exploitability:
Static evidence: Login endpoint has no visible rate limiter or lockout control.

Attack Scenario:
An attacker who can influence the relevant input or build surface may trigger this weakness if no upstream control blocks it.

Compensating Controls:
Not proven by static runner. Manual analyst review should verify framework protections and deployment controls.

Root Cause:
Missing security control

Remediation:
Add per-IP and per-account rate limiting plus alerting for repeated failures.

Verification:
Add tests that repeated login attempts are throttled.

### FINDING: F-006 - Reflected XSS In Server HTML Response

Severity: Medium
CVSS Base: 6.1 - CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
Effective: Medium
Confidence: Confirmed
Data Class: L1
OWASP: A05
CWE: CWE-79
Location: src/server.js:40

Vulnerable Code:
`  res.send("<h1>Hello " + name + "</h1>");`

Proof Of Exploitability:
Static evidence: Server response builds HTML with concatenated values.

Attack Scenario:
An attacker who can influence the relevant input or build surface may trigger this weakness if no upstream control blocks it.

Compensating Controls:
Not proven by static runner. Manual analyst review should verify framework protections and deployment controls.

Root Cause:
Unsafe output handling

Remediation:
Escape output or render through a safe template engine.

Verification:
Add a test proving script tags are escaped in the response.

### FINDING: F-007 - Mutable GitHub Action Tag

Severity: Low
CVSS Base: 3.7 - CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L
Effective: Low
Confidence: Likely
Data Class: L2
OWASP: A03
CWE: CWE-829
Location: .github/workflows/ci.yml:11

Vulnerable Code:
`      - uses: actions/checkout@v4`

Proof Of Exploitability:
Static evidence: Workflow uses a mutable action version tag rather than a commit SHA.

Attack Scenario:
An attacker who can influence the relevant input or build surface may trigger this weakness if no upstream control blocks it.

Compensating Controls:
Not proven by static runner. Manual analyst review should verify framework protections and deployment controls.

Root Cause:
Dependency risk

Remediation:
Pin third-party actions to full commit SHAs and review updates intentionally.

Verification:
Add CI policy that rejects action tags matching @vN.

### FINDING: F-008 - Mutable GitHub Action Tag

Severity: Low
CVSS Base: 3.7 - CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L
Effective: Low
Confidence: Likely
Data Class: L2
OWASP: A03
CWE: CWE-829
Location: .github/workflows/ci.yml:12

Vulnerable Code:
`      - uses: actions/setup-node@v4`

Proof Of Exploitability:
Static evidence: Workflow uses a mutable action version tag rather than a commit SHA.

Attack Scenario:
An attacker who can influence the relevant input or build surface may trigger this weakness if no upstream control blocks it.

Compensating Controls:
Not proven by static runner. Manual analyst review should verify framework protections and deployment controls.

Root Cause:
Dependency risk

Remediation:
Pin third-party actions to full commit SHAs and review updates intentionally.

Verification:
Add CI policy that rejects action tags matching @vN.

### FINDING: F-009 - Docker Image Uses latest Tag

Severity: Low
CVSS Base: 3.7 - CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L
Effective: Low
Confidence: Likely
Data Class: L2
OWASP: A03
CWE: CWE-1104
Location: Dockerfile:1

Vulnerable Code:
`FROM node:latest`

Proof Of Exploitability:
Static evidence: Container base image is mutable and not pinned.

Attack Scenario:
An attacker who can influence the relevant input or build surface may trigger this weakness if no upstream control blocks it.

Compensating Controls:
Not proven by static runner. Manual analyst review should verify framework protections and deployment controls.

Root Cause:
Dependency risk

Remediation:
Pin base images by version and digest.

Verification:
Add CI policy that blocks mutable base image tags.

### FINDING: F-010 - Container Does Not Configure Non-Root User

Severity: Low
CVSS Base: 3.7 - CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L
Effective: Low
Confidence: Likely
Data Class: L2
OWASP: A02
CWE: CWE-250
Location: Dockerfile:1

Vulnerable Code:
`FROM node:latest`

Proof Of Exploitability:
Static evidence: Container image does not declare a non-root runtime user.

Attack Scenario:
An attacker who can influence the relevant input or build surface may trigger this weakness if no upstream control blocks it.

Compensating Controls:
Not proven by static runner. Manual analyst review should verify framework protections and deployment controls.

Root Cause:
Insecure default

Remediation:
Create a dedicated user/group and add a USER directive.

Verification:
Add container policy checks for non-root execution.

### FINDING: F-011 - Missing JavaScript Lockfile

Severity: Low
CVSS Base: 3.7 - CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L
Effective: Low
Confidence: Possible
Data Class: L2
OWASP: A03
CWE: CWE-1104
Location: package.json:1

Vulnerable Code:
`{`

Proof Of Exploitability:
Static evidence: package.json is present without a recognized lockfile.

Attack Scenario:
An attacker who can influence the relevant input or build surface may trigger this weakness if no upstream control blocks it.

Compensating Controls:
Not proven by static runner. Manual analyst review should verify framework protections and deployment controls.

Root Cause:
Dependency risk

Remediation:
Commit a package manager lockfile and use frozen installs in CI.

Verification:
Run package manager install in lockfile/frozen mode in CI.

### FINDING: F-012 - DOM XSS Through Unsafe HTML Sink

Severity: Medium
CVSS Base: 6.1 - CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
Effective: Medium
Confidence: Confirmed
Data Class: L1
OWASP: A05
CWE: CWE-79
Location: src/client.js:4

Vulnerable Code:
`document.getElementById("message").innerHTML = message;`

Proof Of Exploitability:
Static evidence: Browser-controlled content may reach an HTML execution sink.

Attack Scenario:
An attacker who can influence the relevant input or build surface may trigger this weakness if no upstream control blocks it.

Compensating Controls:
Not proven by static runner. Manual analyst review should verify framework protections and deployment controls.

Root Cause:
Unsafe output handling

Remediation:
Use textContent or a vetted sanitizer with strict allowlists.

Verification:
Add a browser/unit test showing HTML input is rendered as text.

## False Positive Review

No False Positive findings were closed by the deterministic runner. Claude analyst review should close protected or unreachable candidates.

## STRIDE

Trust boundaries identified by the static runner include user-controlled HTTP/browser inputs, server-side processing, dependency/build pipelines, and container runtime boundaries where present.

## Attack Chain

ATTACK CHAIN: Static Input And Build Surface Exposure

Findings chained: see validated findings above.

Chain-breaking fix: prioritize parameterization, output escaping, least-privilege build/runtime configuration, and rate limiting.

## HIPAA

Not Assessed unless L4/ePHI indicators were present in recon. Proposed HIPAA items must be reported only as proposed-readiness.

## NIST AI RMF Evidence

See `nist-ai-rmf-evidence.md` for the dedicated Govern, Map, Measure, and Manage evidence matrix. Static review can seed AI security evidence, but governance and lifecycle rows require owner-provided operational evidence.

## Coverage Risk

Static file coverage is 100.0 percent based on `coverage.json`.
