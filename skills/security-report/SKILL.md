---
name: security-report
description: >
  Templates and standards for SecureScan security audit outputs. Load this skill when validating
  findings, assigning CVSS/contextual severity, writing remediation, creating risk acceptance
  entries, or assembling final reports.
version: 2.3.0
last_verified: 2026-05-06
source_urls:
  - https://www.first.org/cvss/v3.1/specification-document
---

# Security Report Standards And Templates

## Evidence Standard

Every validated finding needs:

- Exact file path and line/range
- Exact code snippet, redacted if sensitive
- Reachability/data-flow explanation
- Trust boundary
- CWE and OWASP mapping
- Data classification
- Confidence
- CVSS v3.1 base vector and score
- Contextual effective severity
- Remediation and verification steps

No file/line/code evidence means no finding.

## Validated Finding Template

```text
FINDING: F-[NNN] - [Descriptive Title]

Severity:       [Critical|High|Medium|Low|Informational]
CVSS Base:      X.X - CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_
Effective:      [Critical|High|Medium|Low|Informational] - [context adjustment]
Confidence:     [Confirmed|Likely|Possible]
Data Class:     [L4 Regulated|L3 Confidential|L2 Internal|L1 Public]
OWASP Web:      [A01-A10 or N/A]
OWASP API:      [API1-API10 or N/A]
OWASP LLM:      [LLM01-LLM10 or N/A]
OWASP Agentic:  [ASI01-ASI10 or N/A]
CWE:            CWE-XXX: [Name]
Location:       [file path:line-range]
Component:      [module/service/layer]

Description:
[Precise vulnerability statement.]

Vulnerable Code:
[3-10 lines with sensitive values redacted.]

Proof Of Exploitability:
[Confirmed: concrete static PoC, payload, curl command if approved, or walkthrough.]
[Likely: why it appears exploitable and what runtime test would confirm.]
[Possible: suspicious condition and required verification.]

Attack Scenario:
[Preconditions, attacker action, impact.]

Compensating Controls:
[Existing mitigations or "None identified".]

Root Cause:
[Taxonomy label and explanation.]

Remediation:
[Concrete framework-idiomatic fix. Include code/config where useful.]

Verification:
[Test, command, unit/integration case, or manual check that proves the fix.]
```

## Confidence Ratings

| Rating | Meaning | PoC Required |
|---|---|---|
| Confirmed | Working PoC or exploitation path can be constructed from reviewed code and approved scope | Yes |
| Likely | Dangerous reachable pattern with no visible sufficient control; runtime confirmation needed | No |
| Possible | Suspicious or environment-dependent issue; impact not proven | No |
| False Positive | Code path unreachable, protected, or not actually vulnerable | No |

## Contextual Severity Method

1. Calculate CVSS v3.1 base vector and score.
2. Adjust effective severity using application context:

| Factor | Condition | Adjustment |
|---|---|---|
| Data classification | Exposes L4 regulated/ePHI data | Elevate one level |
| Data classification | L1 public data only | Reduce one level |
| Exposure | Internet-facing without auth | Baseline or elevate if high impact |
| Exposure | Requires normal user auth | Consider reducing one level |
| Exposure | Internal-only/VPN-only | Consider reducing one level |
| Multi-tenant | Cross-tenant impact | Elevate one level |
| Compensating controls | Strong control demonstrably blocks exploit | Close or reduce |
| AI autonomy | Agent/tool can act without approval | Elevate one level |
| Supply chain | Build/deploy compromise path | Elevate if production signing/deploy is affected |

3. Cap effective severity at Critical and floor it at Informational.
4. Record the reason for every adjustment.

## Root Cause Taxonomy

| Root Cause | Definition | Systemic Fix |
|---|---|---|
| Missing security control | Protection absent | Add middleware/library/control |
| Incorrect implementation | Control exists but incomplete or bypassable | Fix implementation and add regression tests |
| Insecure default | Default config unsafe for production | Harden config and add drift checks |
| Insufficient input validation | Data trusted at boundary | Validate and normalize at boundary |
| Missing authorization | Auth exists but permission check missing | Add object/function-level authorization |
| Dependency risk | Third-party package/tool/build risk | Update, pin, replace, or add provenance controls |
| Configuration drift | Runtime differs from intended state | IaC, policy checks, drift detection |
| Unsafe AI trust boundary | AI input/output/tool result trusted | Treat AI content as untrusted and validate |
| Excessive agent autonomy | Agent has too much power | Least privilege, approval gates, audit logs |
| Incomplete observability | No logs/alerts for security events | Add audit logging and alerting |
| Architectural flaw | Structural issue beyond point patch | Redesign boundary or flow |

## Attack Chain Template

```text
ATTACK CHAIN: [Name]

Findings chained:   F-NNN -> F-NNN -> F-NNN
Combined severity:  [Critical|High|Medium|Low]

Kill chain:
  Step 1: [Exploit F-NNN to gain X]
  Step 2: [Use X to exploit F-NNN]
  Step 3: [Resulting business/security impact]

Business impact:    [Concrete impact]
Chain-breaking fix: [Single remediation that breaks the chain]
```

## Closed Finding Template

```text
CLOSED: SCAN-[NNN] - [Title]
Reason: [Framework auto-escapes | upstream validation | code path unreachable | scope excludes path | other]
Evidence: [Specific code/control proving closure]
```

## Risk Acceptance Template

```text
RISK ACCEPTANCE: Finding F-[NNN]

Finding:                [Title]
Effective Severity:     [Level]
Business Justification: [Why deferred]
Compensating Controls:  [Controls reducing risk]
Residual Risk:          [High|Medium|Low]
Owner:                  [Role]
Reassess By:            [Date or trigger]
Escalate If:            [Condition]
```

## Final Report QA Gate

Before finalizing:

- Scope and authorization are stated.
- Static/dynamic testing boundaries are clear.
- Coverage summary matches `coverage.json`.
- Every skipped area has a reason.
- Confirmed findings have PoCs or walkthroughs.
- Likely/Possible findings state required verification.
- False positives are listed with evidence.
- Current HIPAA and proposed-readiness controls are separated.
- No raw secrets or sensitive customer/patient data appear.
- Remediation is actionable and testable.
- Risk acceptance section exists even if empty.
