---
name: scan-patterns
description: >
  Static vulnerability scan patterns and optional tool-assisted checks for JavaScript/TypeScript,
  Python, web/API code, infrastructure, CI/CD, serverless, and AI/LLM integrations. Load this
  skill when performing Phase 2 file-by-file scanning.
version: 2.3.0
last_verified: 2026-05-06
---

# Vulnerability Scan Patterns

Use these patterns as hunting prompts, not final findings. The analyst must validate reachability, framework protections, exploitability, and compensating controls.

Prefer `rg` over `grep` when available. Do not print raw secret values.

## JavaScript / TypeScript

### Code And Command Injection

- `eval(`, `Function(`, string-based `setTimeout` / `setInterval`
- `child_process.exec`, `execSync`, `spawn` or `spawnSync` with `shell: true`
- Template interpretation of user-controlled strings

Example search:

```bash
rg -n "eval\\(|Function\\(|child_process|execSync|spawn\\(" -g '*.js' -g '*.ts' -g '*.tsx' .
```

### XSS And Unsafe Output

- `dangerouslySetInnerHTML`
- `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`
- Server-rendered HTML built with request/query/body values

```bash
rg -n "dangerouslySetInnerHTML|innerHTML|outerHTML|insertAdjacentHTML|document.write" -g '*.js' -g '*.jsx' -g '*.ts' -g '*.tsx' .
```

### SQL / NoSQL Injection

- Raw SQL with string concatenation or template interpolation
- `.query("SELECT` with concatenated variables
- Mongo `$where`, dynamic `$regex`, or unsanitized operator injection

```bash
rg -n "SELECT .*\\+|SELECT .*\\$\\{|\\.query\\(|\\$where|\\$regex" -g '*.js' -g '*.ts' .
```

### Auth And Session

- Missing route middleware on sensitive endpoints
- `cors()` with no explicit allowlist or `origin: "*"`
- Session cookies missing `secure`, `httpOnly`, `sameSite`
- JWT verification without algorithm allowlist or expiration handling
- State-changing browser endpoints without CSRF strategy
- Login/register/password reset without rate limiting

```bash
rg -n "cors\\(|express-session|jsonwebtoken\\.verify|csrf|rateLimit|sameSite|httpOnly|secure:" -g '*.js' -g '*.ts' .
```

### Data Exposure

- Full ORM/database objects returned to clients
- Errors sending `err.stack`, `trace`, or raw exception objects
- Logs containing secret, token, password, SSN, PHI, patient data
- Sensitive browser storage: `localStorage`, `sessionStorage`, non-httpOnly cookies

```bash
rg -n "err\\.stack|traceback|console\\.log|localStorage|sessionStorage|res\\.json\\(|res\\.send\\(" -g '*.js' -g '*.ts' -g '*.tsx' .
```

## Python

### Code / Command Injection

- `os.system`, `subprocess.*` with `shell=True`
- `eval`, `exec`, `compile`, dynamic `__import__`

```bash
rg -n "os\\.system|subprocess\\.|shell=True|eval\\(|exec\\(|compile\\(|__import__\\(" -g '*.py' .
```

### SQL Injection

- f-string or `.format()` SQL
- String concatenation in cursor execution
- SQLAlchemy `text(f"...")` or raw SQL with interpolated values

```bash
rg -n "f[\"'].*SELECT|\\.format\\(.*SELECT|cursor\\.execute\\(|text\\(f[\"']" -g '*.py' .
```

### Deserialization

- `pickle.loads`, `yaml.load` without `SafeLoader`, `jsonpickle.decode`, `marshal.loads`

```bash
rg -n "pickle\\.loads|yaml\\.load|jsonpickle\\.decode|marshal\\.loads" -g '*.py' .
```

### Web/API Controls

- FastAPI handlers missing `Depends` auth where sensitive
- Flask routes missing auth decorators
- Pydantic models using `Any` or allowing sensitive mass assignment
- `DEBUG = True`, `ALLOWED_HOSTS = ["*"]`
- SSRF through `requests.get(user_url)` or `httpx.get(user_url)`

```bash
rg -n "@app\\.|Depends\\(|login_required|DEBUG\\s*=\\s*True|ALLOWED_HOSTS|requests\\.get|httpx\\.get" -g '*.py' .
```

## Infrastructure And Configuration

### Cloud / IaC

- IAM `"Action": "*"` or `"Resource": "*"`
- Public S3/bucket policies
- `0.0.0.0/0` on non-public ports
- Databases or storage without encryption
- Missing HTTPS redirects/HSTS
- Overly broad Lambda/service roles

```bash
rg -n '"Action": "\\*"|"Resource": "\\*"|0\\.0\\.0\\.0/0|Principal": "\\*"' -g '*.json' -g '*.yaml' -g '*.yml' -g '*.tf' .
```

### Docker

- `FROM ...:latest`
- No non-root `USER`
- `COPY . .` without `.dockerignore`
- Secrets in `ENV` or `ARG`
- Unnecessary exposed ports

```bash
rg -n "FROM .*:latest|USER root|^USER |^ENV .*SECRET|^ARG .*TOKEN|EXPOSE " -g 'Dockerfile*' .
```

### CI/CD

- Mutable third-party actions such as `@v4`
- Missing or broad `permissions:`
- `pull_request_target`
- Secrets echoed to logs
- CI runs untrusted scripts with write tokens

```bash
rg -n "uses: .*@v[0-9]+|pull_request_target|permissions:|GITHUB_TOKEN|secrets\\." -g '*.yml' -g '*.yaml' .github workflows .
```

## AI / LLM / Agentic Patterns

- User input interpolated directly into prompts without delimiters
- RAG/document/web content inserted as instructions
- LLM outputs passed to HTML, SQL, shell, code execution, or privileged tools
- Tools without schemas or parameter validation
- Destructive tool calls without approval gates
- Persistent memory writes from untrusted content
- Vector retrieval without tenant/user filter
- Missing token/cost/time limits and circuit breakers

```bash
rg -n "prompt|systemPrompt|messages|tool|function_call|embedding|vector|memory|OpenAI|Anthropic|Gemini|LangChain|MCP" -g '*.js' -g '*.ts' -g '*.tsx' -g '*.py' .
```

## Optional Tool-Assisted Checks

Use these only if the tool is already installed and the scope allows the command. Do not install or download without approval.

```bash
semgrep --config=auto --json --output=.securescan/tool-runs/semgrep.json .
gitleaks detect --redact --report-format=json --report-path=.securescan/tool-runs/gitleaks.json
trufflehog filesystem . --json > .securescan/tool-runs/trufflehog.json
osv-scanner --recursive --format json --output .securescan/tool-runs/osv.json .
npm audit --json > .securescan/tool-runs/npm-audit.json
pip-audit -f json -o .securescan/tool-runs/pip-audit.json
trivy fs --format json --output .securescan/tool-runs/trivy-fs.json .
checkov -d . -o json > .securescan/tool-runs/checkov.json
```

If a tool is absent or not approved, record that in `coverage.json.tool_runs` with `status: "not-run"` and a reason.

## Coverage Rules

- Scan every `scan_required=yes` manifest file unless technically impossible.
- For binary/generated/vendor files, scan the controlling manifest/config instead and record skip reason.
- Record exact pattern families applied per file.
- Record partial files when only relevant sections were reviewed.
- Coverage gaps must flow into Analyst and Reporter residual-risk sections.
