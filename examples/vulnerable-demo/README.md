# SecureScan Vulnerable Demo

This fixture is intentionally vulnerable. Use it only to smoke-test SecureScan behavior.

Expected scanner themes:

- SQL injection through string concatenation
- Reflected XSS through `innerHTML`
- Insecure CORS wildcard
- Missing rate limiting on login
- Hardcoded demo-only fallback value
- Mutable GitHub Action tag
- Docker `latest` tag and root execution

Validate the bundled golden output:

```bash
bash ../../scripts/validate-demo-audit.sh --artifacts golden-output
```

Run the deterministic scanner from the package root:

```bash
bash scripts/securescan-static.sh --project examples/vulnerable-demo
bash scripts/validate-demo-audit.sh --project examples/vulnerable-demo
```

Run a targeted scan after installing SecureScan:

```text
@securescan-recon Map examples/vulnerable-demo for a security audit
@securescan-scanner Scan examples/vulnerable-demo for vulnerabilities
```

Then validate the generated `.securescan/` artifacts:

```bash
bash ../../scripts/validate-demo-audit.sh --project .
```
