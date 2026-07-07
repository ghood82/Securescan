# SecureScan Source Registry

Last verified: 2026-05-06

This file records the official sources used by SecureScan reference skills. Re-verify these sources before releasing a new package version or using the package for a formal external audit.

| Area | Source | Status In Package | Last Verified |
|---|---|---|---|
| OWASP Web Top 10 | https://owasp.org/Top10/2025/ | Current OWASP Top 10:2025 release | 2026-05-06 |
| OWASP API Security Top 10 | https://owasp.org/API-Security/editions/2023/en/0x11-t10/ | Current API Top 10:2023 reference | 2026-05-06 |
| OWASP LLM Top 10 | https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/ | Current LLM Top 10:2025 reference | 2026-05-06 |
| OWASP Agentic Applications Top 10 | https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ | Current Agentic Applications Top 10:2026 reference | 2026-05-06 |
| NIST AI RMF 1.0 | https://www.nist.gov/itl/ai-risk-management-framework | Govern, Map, Measure, Manage AI risk-management baseline | 2026-05-15 |
| NIST AI RMF Core | https://airc.nist.gov/airmf-resources/airmf/5-sec-core/ | Function/category source for the evidence matrix | 2026-05-15 |
| NIST AI RMF Playbook | https://www.nist.gov/itl/ai-risk-management-framework/nist-ai-rmf-playbook | Voluntary implementation guidance and suggested actions | 2026-05-15 |
| HIPAA Security Rule NPRM | https://www.hhs.gov/hipaa/for-professionals/security/hipaa-security-rule-nprm/factsheet/index.html | Proposed-rule readiness only; do not label as current legal obligation | 2026-05-06 |
| Current HIPAA Security Rule overview | https://www.hhs.gov/hipaa/for-professionals/security/index.html | Current Security Rule context | 2026-05-06 |
| CVSS v3.1 | https://www.first.org/cvss/v3.1/specification-document | Severity scoring reference | 2026-05-06 |

## Freshness Policy

- Re-check official sources before any formal customer-facing report.
- Treat OWASP GenAI and agentic references as fast-moving.
- Treat NIST AI RMF rows as evidence and alignment support, not certification.
- Treat HIPAA proposed-rule controls as proposed-readiness until HHS publishes a final rule.
- Record the verification date in the final audit report when a compliance matrix depends on time-sensitive sources.
