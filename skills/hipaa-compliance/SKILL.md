---
name: hipaa-compliance
description: >
  HIPAA Security Rule assessment reference for healthcare application security reviews.
  Load this skill when code handles electronic Protected Health Information (ePHI), when
  assessing healthcare SaaS readiness, or when building HIPAA current-rule and proposed-readiness
  matrices.
version: 2.3.0
last_verified: 2026-05-06
source_urls:
  - https://www.hhs.gov/hipaa/for-professionals/security/index.html
  - https://www.hhs.gov/hipaa/for-professionals/security/hipaa-security-rule-nprm/factsheet/index.html
---

# HIPAA Security Rule Assessment

Source status: verified against HHS pages on 2026-05-06.

Important: The 2025 HIPAA Security Rule changes are an NPRM/proposed rule unless HHS has issued a final rule after this verification date. Do not report proposed controls as current legal obligations. Label them `proposed-readiness`.

## Current-Rule Technical Safeguard Matrix

Use Compliant, Partial, Gap, Not Applicable, or Not Assessed.

| # | Requirement | HIPAA Reference | What To Check In Code | Status | Findings | Priority |
|---|---|---|---|---|---|---|
| 1 | ePHI encryption at rest | 45 CFR 164.312(a)(2)(iv) | Database, file storage, backups, key management, cloud encryption settings | | | |
| 2 | ePHI encryption in transit | 45 CFR 164.312(e)(1) | TLS enforcement, HSTS, DB TLS, service-to-service encryption | | | |
| 3 | Access control / RBAC | 45 CFR 164.312(a)(1) | API-layer authz, role checks, least privilege, tenant scoping | | | |
| 4 | Unique user identification | 45 CFR 164.312(a)(2)(i) | Unique user IDs, no shared accounts for ePHI access | | | |
| 5 | Emergency access procedure | 45 CFR 164.312(a)(2)(ii) | Break-glass workflow, approval, logging, review | | | |
| 6 | Automatic logoff | 45 CFR 164.312(a)(2)(iii) | Idle timeout, token expiry, session invalidation | | | |
| 7 | Audit controls | 45 CFR 164.312(b) | Who/what/when/where/outcome for ePHI access; tamper resistance | | | |
| 8 | Integrity controls | 45 CFR 164.312(c)(1) | Validation, change tracking, checksums, write authorization | | | |
| 9 | Person/entity authentication | 45 CFR 164.312(d) | Authentication strength, SSO, MFA if implemented/required by policy | | | |
| 10 | Transmission security | 45 CFR 164.312(e)(2) | No ePHI over HTTP, email/file transfer protections, API transport security | | | |
| 11 | Contingency backup/recovery | 45 CFR 164.308(a)(7)(ii) | Backup automation, restore tests, backup encryption, recovery procedures | | | |
| 12 | Workforce access termination | 45 CFR 164.308(a)(3)(ii)(C) | Disable users, revoke sessions/tokens, deprovision service access | | | |

## Proposed-Readiness Matrix

Use this matrix only as proposed-readiness unless source verification confirms a final rule.

| # | Proposed-Readiness Area | NPRM Signal | What To Check | Status | Findings | Priority |
|---|---|---|---|---|---|---|
| P1 | Written policies/procedures/plans | Written documentation required | Security policies, incident procedures, risk analyses in docs/IaC | | | |
| P2 | Technology asset inventory and network map | At least every 12 months and on material change | Asset inventory, data flow map, systems handling ePHI | | | |
| P3 | Specific risk analysis | Threats, vulnerabilities, likelihood, risk level | Risk register, code/IaC evidence, documented assumptions | | | |
| P4 | Workforce access change notice | Within 24 hours | HR/IdP/webhook process, admin audit trail | | | |
| P5 | 72-hour restoration procedures | Restore relevant systems/data within 72 hours | DR plan, backup restore tests, RTO/RPO evidence | | | |
| P6 | Annual compliance audit | At least every 12 months | Compliance audit process and evidence retention | | | |
| P7 | Business associate safeguard verification | Annual written verification/certification | BAA inventory, vendor security review, third-party systems | | | |
| P8 | ePHI encryption at rest and in transit | Proposed stronger requirement | Encryption defaults and exception process | | | |
| P9 | Multi-factor authentication | Required with limited exceptions | MFA enforcement, admin access, break-glass exceptions | | | |
| P10 | Vulnerability scanning and pen testing | Scanning every 6 months; pen test every 12 months | CI SAST/DAST, external test records, remediation SLA | | | |
| P11 | Network segmentation | Required | VPC/security groups, subnetting, tenant isolation, firewall rules | | | |
| P12 | Backup and recovery technical controls | Separate controls for backup/recovery | Immutable backups, separate credentials, restore verification | | | |

## Multi-Tenant ePHI Isolation Checks

- Database isolation: tenant ID scoping on every query, RLS where available, no cross-tenant joins without authorization.
- Cache isolation: tenant-scoped keys and invalidation.
- File storage isolation: tenant-prefixed paths, bucket/IAM scoping, signed URL controls.
- Queue isolation: tenant context on messages and consumers.
- Search/vector isolation: tenant collections or mandatory tenant filters at retrieval time.
- Error response isolation: no other-tenant identifiers or data in errors.
- Log isolation: tenant context included, ePHI redacted.

## ePHI Data Flow Verification

For each ePHI location, verify:

1. At rest: encrypted with cloud-managed or application-managed controls.
2. In transit: TLS 1.2+ or stronger, no HTTP fallback.
3. In processing: minimum necessary data loaded.
4. In logs: no patient names, DOB, SSN, MRN, diagnosis, insurance IDs, or raw clinical text unless explicitly approved and protected.
5. In errors: no ePHI or stack traces containing ePHI.
6. In URLs: no ePHI in query strings or path segments.
7. In browser: no ePHI in localStorage, sessionStorage, or unencrypted cookies.
8. In AI: no ePHI sent to public AI APIs without an approved compliant data path and contractual controls.

## Reporting Guidance

- Separate current-rule gaps from proposed-readiness gaps.
- Do not give legal advice. Report technical evidence and readiness posture.
- If ePHI is not present, mark HIPAA matrices Not Applicable and explain why.
- If ePHI might be present but evidence is incomplete, mark Not Assessed or Partial, not Compliant.
