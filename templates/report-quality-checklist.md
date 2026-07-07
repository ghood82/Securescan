# SecureScan Report Quality Checklist

Use this checklist before finalizing `.securescan/04-report.md`.

- [ ] Scope and authorization are stated.
- [ ] Static vs dynamic testing limits are clear.
- [ ] Coverage summary includes scanned, partial, skipped, and skip reasons.
- [ ] Every validated finding has file, line, code evidence, CWE, OWASP category, data class, confidence, CVSS, effective severity, remediation, and verification.
- [ ] Every Confirmed finding has a proof of exploitability.
- [ ] Likely and Possible findings clearly state what runtime testing would confirm.
- [ ] False positives are closed with evidence.
- [ ] HIPAA proposed-rule items are labeled proposed-readiness.
- [ ] NIST AI RMF evidence is captured in `nist-ai-rmf-evidence.md` when AI components exist or AI RMF is requested.
- [ ] NIST AI RMF Govern, Map, Measure, and Manage rows use Compliant, Partial, Gap, Not Applicable, or Not Assessed with evidence and residual-risk notes.
- [ ] No raw secrets, patient data, customer data, or access tokens appear in the report.
- [ ] Top attack chains have a chain-breaking remediation.
- [ ] Remediation roadmap is prioritized by severity and exploitability.
- [ ] Residual risks and out-of-scope areas are explicit.
