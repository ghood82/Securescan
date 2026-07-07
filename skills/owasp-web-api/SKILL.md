---
name: owasp-web-api
description: >
  Reference tables for OWASP Top 10 Web Application Security Risks 2025 and OWASP API
  Security Top 10 2023. Load this skill when scanning or analyzing web application,
  API, server-side, client-side, and CI/CD security findings.
version: 2.3.0
last_verified: 2026-05-06
source_urls:
  - https://owasp.org/Top10/2025/
  - https://owasp.org/API-Security/editions/2023/en/0x11-t10/
---

# OWASP Web And API Security Frameworks

Source status: verified against official OWASP pages on 2026-05-06. Re-check `SOURCES.md` before formal external reports.

## OWASP Top 10 Web Application Security Risks 2025

| ID | Category | Key CWEs | What To Hunt |
|---|---|---|---|
| A01 | Broken Access Control | CWE-284, CWE-639, CWE-862, CWE-918 | Missing authorization, IDOR, privilege escalation, forced browsing, unsafe CORS, JWT manipulation, SSRF consolidated under access control |
| A02 | Security Misconfiguration | CWE-16, CWE-209, CWE-732 | Debug mode, verbose errors, weak headers, default creds, open storage, unnecessary features |
| A03 | Software Supply Chain Failures | CWE-1104 | Vulnerable/unpinned dependencies, mutable CI actions, typosquatting, compromised build tooling, missing integrity verification |
| A04 | Cryptographic Failures | CWE-327, CWE-328, CWE-330, CWE-321, CWE-798 | Plaintext sensitive data, weak crypto, hardcoded keys, missing TLS, weak random generation |
| A05 | Injection | CWE-79, CWE-89, CWE-78, CWE-94, CWE-117 | SQLi, XSS, command injection, code injection, SSTI, header/log injection |
| A06 | Insecure Design | CWE-522, CWE-602 | Missing abuse-case handling, no rate limits, weak business rules, no threat modeling |
| A07 | Authentication Failures | CWE-287, CWE-306, CWE-384 | Weak passwords, missing MFA where required, token/session flaws, credential stuffing exposure |
| A08 | Software And Data Integrity Failures | CWE-502, CWE-829 | Insecure deserialization, unsigned updates, untrusted code/data, missing artifact integrity |
| A09 | Security Logging And Alerting Failures | CWE-532, CWE-778 | Missing audit trails, sensitive logs, no alerting, no tamper resistance |
| A10 | Mishandling Of Exceptional Conditions | CWE-209, CWE-248, CWE-636, CWE-703, CWE-754, CWE-755 | Failing open, stack traces, inconsistent error handling, unhandled exceptions, bad rollback/cleanup |

## OWASP API Security Top 10 2023

| ID | Category | What To Hunt |
|---|---|---|
| API1 | Broken Object Level Authorization | User-controlled IDs without per-object authorization checks |
| API2 | Broken Authentication | Token validation flaws, weak auth, brute-force exposure, improper token lifetime |
| API3 | Broken Object Property Level Authorization | Excessive data exposure, mass assignment, missing field allowlists |
| API4 | Unrestricted Resource Consumption | Missing pagination caps, upload limits, rate limits, cost controls |
| API5 | Broken Function Level Authorization | Regular users reaching admin functions or privileged workflows |
| API6 | Unrestricted Access To Sensitive Business Flows | Automated abuse of signup, purchasing, exports, scraping, or other high-impact flows |
| API7 | Server-Side Request Forgery | User-supplied URLs fetched server-side without allowlist and metadata/IP protections |
| API8 | Security Misconfiguration | Weak gateway/server configs, debug endpoints, missing headers, permissive methods/CORS |
| API9 | Improper Inventory Management | Shadow APIs, stale versions, undocumented hosts/routes, deprecated endpoints still exposed |
| API10 | Unsafe Consumption Of APIs | Trusting third-party responses without validation, auth checks, schema checks, or sanitization |

## CWE Quick Reference

| CWE | Name | Detection Hint |
|---|---|---|
| CWE-79 | Cross-Site Scripting | Raw HTML sinks, unsafe templating, unescaped output |
| CWE-89 | SQL Injection | String-built SQL, f-string/template SQL, unsafe raw queries |
| CWE-78 | OS Command Injection | Shell execution with user-controlled input |
| CWE-94 | Code Injection | `eval`, dynamic functions, unsafe interpreters |
| CWE-117 | Log Injection | Unsanitized user input in structured or plain logs |
| CWE-200 | Sensitive Data Exposure | PII/PHI/secrets in responses, logs, URLs, errors |
| CWE-284 | Improper Access Control | Missing permission enforcement |
| CWE-287 | Improper Authentication | Weak or broken authentication checks |
| CWE-306 | Missing Authentication | Sensitive endpoint lacks auth |
| CWE-327 | Broken Crypto | MD5/SHA1/DES/ECB or obsolete algorithms |
| CWE-352 | CSRF | State-changing browser endpoint without CSRF protection |
| CWE-434 | Unrestricted File Upload | Missing type, size, content, or storage validation |
| CWE-502 | Insecure Deserialization | `pickle`, unsafe `yaml.load`, unsafe object deserialization |
| CWE-601 | Open Redirect | Unvalidated redirect target |
| CWE-639 | IDOR | User-controlled object reference without ownership check |
| CWE-798 | Hardcoded Credentials | Credentials or API keys in source |
| CWE-862 | Missing Authorization | Authenticated user can perform unauthorized action |
| CWE-918 | SSRF | Server-side fetch from attacker-controlled URI |

## Analyst Guidance

- Do not report a category by pattern alone. Check reachability, framework protections, and compensating controls.
- For API1/API5, trace the specific object/function authorization check, not just authentication.
- For API3, check both read exposure and write/mass-assignment paths.
- For A03, inspect lockfiles, CI action pinning, Docker base tags, package manager settings, and provenance controls.
- For A10, look at failure paths, not just happy paths.
