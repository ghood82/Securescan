# SecureScan Scope And Authorization

Audit date: 2026-05-15
Auditor: SecureScan deterministic static runner v2.4.0
Target project: /Users/garethhood/Desktop/SecureScan-Package/examples/vulnerable-demo

## Authorization

- Authorized by: local user invocation
- Authorization evidence: `securescan-static` command
- Allowed mode: Static local review
- Explicitly approved active testing: No
- Explicitly approved external network testing: No
- Explicitly approved dependency installation/downloads: No
- Explicitly approved production access: No

## In Scope

- Source files, manifests, configuration, CI/CD, container, and infrastructure files discovered under the target project.

## Out Of Scope

- Runtime exploitation
- External network testing
- Dependency installation
- Production access
- Secret value disclosure

## Data Handling

- Secret-like values are redacted from code evidence where detected.
- Artifacts are written locally under this output directory.
