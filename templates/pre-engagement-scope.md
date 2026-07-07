# SecureScan Scope And Authorization

Audit date: YYYY-MM-DD
Auditor: AI-assisted SecureScan workflow
Target project: PATH_OR_REPO

## Authorization

- Authorized by: NAME_OR_ROLE
- Authorization evidence: USER_REQUEST_OR_TICKET
- Allowed mode: Static local review unless otherwise stated
- Explicitly approved active testing: No
- Explicitly approved external network testing: No
- Explicitly approved dependency installation/downloads: No
- Explicitly approved production access: No

## In Scope

- Source code in the current project
- Local configuration files, excluding secret values
- Dependency manifests and lockfiles
- CI/CD workflow files
- Infrastructure-as-code files
- AI/LLM prompts, tools, agents, MCP servers, and vector/RAG code if present

## Out Of Scope

- Third-party systems without written authorization
- Production probing unless explicitly approved
- Brute force, denial of service, destructive tests, persistence, exfiltration
- Secret value disclosure
- Customer, patient, or employee data extraction

## Data Handling

- Do not print raw secrets.
- Do not include patient/customer data in reports.
- Redact sensitive values in evidence.
- Store artifacts under `.securescan/`.

## Assumptions

- If scope is not specified, default to the current local project.
- If testing mode is not specified, default to static analysis only.
- If a file cannot be inspected, record it in coverage with a skip reason.
