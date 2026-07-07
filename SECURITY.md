# Security Policy

SecureScan is an audit-assistance package. It is not a license to test systems without permission.

## Authorized Use

Use SecureScan only on codebases, repositories, applications, and environments where you have explicit authorization.

Default mode is static local review. The agents should not perform active exploitation, external network scanning, production probing, dependency installation, destructive actions, credential use, or data exfiltration without explicit approval in the target project.

## Handling Secrets And Sensitive Data

- Do not print secret values in findings.
- Record secret locations and evidence type, not the secret itself.
- Redact tokens, passwords, patient data, customer data, private keys, and session identifiers.
- Store generated reports under `.securescan/` and treat them as sensitive.
- Avoid committing `.securescan/` unless the organization has an explicit internal evidence-retention policy.

## Reporting Issues In This Package

When reporting a flaw in SecureScan itself, include:

- Package version
- File path and line number
- Expected behavior
- Actual behavior
- Minimal reproduction steps
- Any safety impact

Do not include real secrets, patient data, customer data, or exploit payloads against third-party systems.
