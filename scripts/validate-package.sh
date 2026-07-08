#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${1:-$(pwd)}"
FAILURES=0

fail() {
  echo "FAIL: $*" >&2
  FAILURES=$((FAILURES + 1))
}

pass() {
  echo "PASS: $*"
}

require_file() {
  local path="$1"
  if [ -f "${ROOT_DIR}/${path}" ]; then
    pass "file exists: ${path}"
  else
    fail "missing file: ${path}"
  fi
}

require_dir() {
  local path="$1"
  if [ -d "${ROOT_DIR}/${path}" ]; then
    pass "directory exists: ${path}"
  else
    fail "missing directory: ${path}"
  fi
}

check_frontmatter_name() {
  local path="$1"
  local expected="$2"
  local full="${ROOT_DIR}/${path}"

  if [ ! -f "$full" ]; then
    fail "cannot check missing file: ${path}"
    return
  fi

  if [ "$(sed -n '1p' "$full")" != "---" ]; then
    fail "${path} missing opening YAML frontmatter"
  fi

  if ! sed -n '1,20p' "$full" | grep -Eq "^name: ${expected}$"; then
    fail "${path} frontmatter name is not '${expected}'"
  else
    pass "frontmatter name: ${path}"
  fi

  if ! sed -n '1,30p' "$full" | grep -Eq "^description:"; then
    fail "${path} missing description"
  fi
}

require_dir "agents"
require_dir "bin"
require_dir "skills"
require_dir "scripts"
require_dir "templates"
require_dir "examples/vulnerable-demo"

require_file "README.md"
require_file "USAGE-GUIDE.md"
require_file "PROJECT-HISTORY.md"
require_file "VERSION"
require_file "SOURCES.md"
require_file "SECURITY.md"
require_file "docs/ENTERPRISE-READINESS.md"
require_file "docs/SECURESCAN-OVERVIEW.md"
require_file ".github/workflows/validate.yml"
require_file "templates/pre-engagement-scope.md"
require_file "templates/recon-template.md"
require_file "templates/coverage.json"
require_file "templates/nist-ai-rmf-evidence-matrix.md"
require_file "templates/report-quality-checklist.md"
require_file "scripts/install.sh"
require_file "scripts/build-overview-docx.py"
require_file "scripts/securescan.py"
require_file "scripts/securescan.sh"
require_file "scripts/validate-package.sh"
require_file "scripts/validate-securescan-artifacts.sh"
require_file "scripts/validate-demo-audit.sh"
require_file "scripts/securescan-static.py"
require_file "scripts/securescan-static.sh"
require_file "bin/securescan"
require_file "examples/vulnerable-demo/EXPECTED-FINDINGS.md"
require_file "examples/vulnerable-demo/golden-output/00-scope.md"
require_file "examples/vulnerable-demo/golden-output/file-manifest.tsv"
require_file "examples/vulnerable-demo/golden-output/01-recon.md"
require_file "examples/vulnerable-demo/golden-output/02-findings.md"
require_file "examples/vulnerable-demo/golden-output/coverage.json"
require_file "examples/vulnerable-demo/golden-output/nist-ai-rmf-evidence.md"
require_file "examples/vulnerable-demo/golden-output/03-analysis.md"
require_file "examples/vulnerable-demo/golden-output/04-report.md"
require_file "examples/vulnerable-demo/src/server.js"
require_file "examples/vulnerable-demo/src/client.js"
require_file "examples/vulnerable-demo/package.json"
require_file "examples/vulnerable-demo/Dockerfile"

check_frontmatter_name "agents/securescan.md" "securescan"
check_frontmatter_name "agents/securescan-recon.md" "securescan-recon"
check_frontmatter_name "agents/securescan-scanner.md" "securescan-scanner"
check_frontmatter_name "agents/securescan-analyst.md" "securescan-analyst"
check_frontmatter_name "agents/securescan-reporter.md" "securescan-reporter"

check_frontmatter_name "skills/owasp-web-api/SKILL.md" "owasp-web-api"
check_frontmatter_name "skills/owasp-ai-agentic/SKILL.md" "owasp-ai-agentic"
check_frontmatter_name "skills/scan-patterns/SKILL.md" "scan-patterns"
check_frontmatter_name "skills/hipaa-compliance/SKILL.md" "hipaa-compliance"
check_frontmatter_name "skills/nist-ai-rmf/SKILL.md" "nist-ai-rmf"
check_frontmatter_name "skills/security-report/SKILL.md" "security-report"

for script in "${ROOT_DIR}"/scripts/*.sh; do
  script_rel="scripts/$(basename "$script")"
  if bash -n "$script"; then
    pass "shell syntax: ${script_rel}"
  else
    fail "shell syntax error: ${script_rel}"
  fi
done

if bash -n "${ROOT_DIR}/bin/securescan"; then
  pass "shell syntax: bin/securescan"
else
  fail "shell syntax error: bin/securescan"
fi

for python_script in "${ROOT_DIR}/scripts/securescan-static.py" "${ROOT_DIR}/scripts/securescan.py" "${ROOT_DIR}/scripts/build-overview-docx.py"; do
  script_rel="scripts/$(basename "$python_script")"
  if PYTHONDONTWRITEBYTECODE=1 python3 -m py_compile "$python_script"; then
    pass "python syntax: ${script_rel}"
  else
    fail "python syntax error: ${script_rel}"
  fi
done

PACKAGE_VERSION="$(tr -d '[:space:]' < "${ROOT_DIR}/VERSION")"
if [ -z "$PACKAGE_VERSION" ]; then
  fail "VERSION is empty"
elif grep -q "SecureScan v${PACKAGE_VERSION%.*}" "${ROOT_DIR}/README.md" && grep -q "## v${PACKAGE_VERSION}" "${ROOT_DIR}/CHANGELOG.md"; then
  pass "VERSION is documented"
else
  fail "VERSION does not match README/CHANGELOG"
fi

if grep -RInE "version: 2\\.(0|1|2)\\.0|SecureScan v2\\.(0|1|2)" "${ROOT_DIR}" \
  --exclude-dir=.git \
  --exclude=validate-package.sh \
  --exclude=CHANGELOG.md \
  --exclude=PROJECT-HISTORY.md >/dev/null 2>&1; then
  fail "package contains stale v2.0/v2.1 version references"
else
  pass "no stale package version references found"
fi

if grep -RInE 'uses: .+@v[0-9]+' "${ROOT_DIR}/.github" >/dev/null 2>&1; then
  fail "package CI uses mutable GitHub Action tags"
else
  pass "package CI actions are pinned"
fi

if grep -q "Last verified:" "${ROOT_DIR}/SOURCES.md" && grep -q "NIST AI RMF 1.0" "${ROOT_DIR}/SOURCES.md"; then
  pass "source registry has verification date"
else
  fail "SOURCES.md missing verification date or NIST AI RMF source"
fi

if grep -q "proposed-readiness" "${ROOT_DIR}/skills/hipaa-compliance/SKILL.md"; then
  pass "HIPAA skill distinguishes proposed-readiness"
else
  fail "HIPAA skill must distinguish proposed-readiness from current legal obligations"
fi

if grep -RInE 'Expected fina[l]|Mandates biannua[l]' "${ROOT_DIR}" --exclude-dir=.git --exclude=validate-package.sh >/dev/null 2>&1; then
  fail "package contains stale or overstated regulatory wording"
else
  pass "no stale HIPAA final-rule wording found"
fi

if grep -q "coverage.json" "${ROOT_DIR}/agents/securescan-scanner.md" && grep -q "file-manifest.tsv" "${ROOT_DIR}/agents/securescan-scanner.md"; then
  pass "scanner prompt references manifest and coverage contract"
else
  fail "scanner prompt must require file-manifest.tsv and coverage.json"
fi

if grep -q "nist-ai-rmf" "${ROOT_DIR}/agents/securescan-analyst.md" && \
  grep -q "nist-ai-rmf-evidence.md" "${ROOT_DIR}/agents/securescan-reporter.md" && \
  grep -q "Govern" "${ROOT_DIR}/templates/nist-ai-rmf-evidence-matrix.md" && \
  grep -q "Map" "${ROOT_DIR}/templates/nist-ai-rmf-evidence-matrix.md" && \
  grep -q "Measure" "${ROOT_DIR}/templates/nist-ai-rmf-evidence-matrix.md" && \
  grep -q "Manage" "${ROOT_DIR}/templates/nist-ai-rmf-evidence-matrix.md"; then
  pass "NIST AI RMF evidence matrix is wired into analyst and reporter workflow"
else
  fail "NIST AI RMF evidence matrix is not fully wired into workflow"
fi

if grep -q "00-scope.md" "${ROOT_DIR}/agents/securescan.md" && grep -q "authorized" "${ROOT_DIR}/agents/securescan.md"; then
  pass "orchestrator includes scope/authorization guard"
else
  fail "orchestrator missing scope/authorization guard"
fi

if grep -q "validate-demo-audit.sh" "${ROOT_DIR}/.github/workflows/validate.yml" && \
  grep -q "validate-securescan-artifacts.sh" "${ROOT_DIR}/.github/workflows/validate.yml" && \
  grep -q "securescan-static.sh" "${ROOT_DIR}/.github/workflows/validate.yml"; then
  pass "CI workflow runs package and demo validators"
else
  fail "CI workflow must run package, static scanner, and demo validators"
fi

if bash "${ROOT_DIR}/scripts/validate-securescan-artifacts.sh" --artifacts "${ROOT_DIR}/examples/vulnerable-demo/golden-output" --phase 4 >/dev/null; then
  pass "golden artifact fixture validates"
else
  fail "golden artifact fixture does not validate"
fi

if bash "${ROOT_DIR}/scripts/validate-demo-audit.sh" --artifacts "${ROOT_DIR}/examples/vulnerable-demo/golden-output" >/dev/null; then
  pass "vulnerable-demo regression validates"
else
  fail "vulnerable-demo regression does not validate"
fi

TMP_OUTPUT="$(mktemp -d "${TMPDIR:-/tmp}/securescan-static-package.XXXXXX")"
if bash "${ROOT_DIR}/scripts/securescan-static.sh" --project "${ROOT_DIR}/examples/vulnerable-demo" --output "${TMP_OUTPUT}" >/dev/null &&
  bash "${ROOT_DIR}/scripts/validate-demo-audit.sh" --artifacts "${TMP_OUTPUT}" >/dev/null; then
  pass "static scanner produces valid vulnerable-demo audit"
else
  fail "static scanner did not produce valid vulnerable-demo audit"
fi

TMP_EXCLUSION_PROJECT="$(mktemp -d "${TMPDIR:-/tmp}/securescan-exclusion-project.XXXXXX")"
mkdir -p "${TMP_EXCLUSION_PROJECT}/src" "${TMP_EXCLUSION_PROJECT}/.claude/worktrees/noisy/src"
cat > "${TMP_EXCLUSION_PROJECT}/src/app.js" <<'EOF'
const express = require('express');
const app = express();
app.get('/hello', (req, res) => res.send('ok'));
EOF
cat > "${TMP_EXCLUSION_PROJECT}/.claude/worktrees/noisy/src/noise.js" <<'EOF'
document.body.innerHTML = location.hash;
EOF
TMP_EXCLUSION_OUTPUT="$(mktemp -d "${TMPDIR:-/tmp}/securescan-exclusion-output.XXXXXX")"
if bash "${ROOT_DIR}/scripts/securescan-static.sh" --project "${TMP_EXCLUSION_PROJECT}" --output "${TMP_EXCLUSION_OUTPUT}" >/dev/null &&
  ! grep -R "\.claude/worktrees" "${TMP_EXCLUSION_OUTPUT}" >/dev/null 2>&1 &&
  grep -q "src/app.js" "${TMP_EXCLUSION_OUTPUT}/file-manifest.tsv"; then
  pass "static scanner excludes agent worktree metadata"
else
  fail "static scanner should exclude .claude/worktrees metadata from application scans"
fi

TMP_SQL_PROJECT="$(mktemp -d "${TMPDIR:-/tmp}/securescan-sql-project.XXXXXX")"
mkdir -p "${TMP_SQL_PROJECT}/src" "${TMP_SQL_PROJECT}/backend/venv_old_39/lib/python3.9/site-packages/PIL"
cat > "${TMP_SQL_PROJECT}/src/safe_queries.py" <<'EOF'
def safe_where_clause(cursor, format_query, organization_id, status):
    conditions = []
    params = []
    if organization_id:
        conditions.append("organization_id = ?")
        params.append(organization_id)
    if status:
        conditions.append("status = ?")
        params.append(status)
    where_clause = " AND ".join(conditions) if conditions else "1=1"
    cursor.execute(format_query(f"SELECT * FROM orders WHERE {where_clause}"), params)


def safe_placeholders(cursor, format_query, doc_ids):
    placeholders = ", ".join("?" for _ in doc_ids)
    cursor.execute(
        format_query(f"SELECT * FROM documents WHERE id IN ({placeholders})"),
        tuple(doc_ids),
    )
EOF
cat > "${TMP_SQL_PROJECT}/src/unsafe_query.py" <<'EOF'
def unsafe_request_query(cursor, format_query, request):
    cursor.execute(format_query(f"SELECT * FROM users WHERE email = '{request.args.get('email')}'"))
EOF
cat > "${TMP_SQL_PROJECT}/backend/venv_old_39/lib/python3.9/site-packages/PIL/ImageShow.py" <<'EOF'
import os
os.system("open " + path)
EOF
TMP_SQL_OUTPUT="$(mktemp -d "${TMPDIR:-/tmp}/securescan-sql-output.XXXXXX")"
if bash "${ROOT_DIR}/scripts/securescan-static.sh" --project "${TMP_SQL_PROJECT}" --output "${TMP_SQL_OUTPUT}" >/dev/null &&
  grep -q "src/unsafe_query.py" "${TMP_SQL_OUTPUT}/02-findings.md" &&
  ! grep -q "src/safe_queries.py" "${TMP_SQL_OUTPUT}/02-findings.md" &&
  ! grep -R "venv_old_39" "${TMP_SQL_OUTPUT}" >/dev/null 2>&1; then
  pass "static scanner distinguishes bound SQL assembly from unsafe interpolation"
else
  fail "static scanner should suppress safe bound SQL assembly, flag unsafe interpolation, and exclude stale virtualenvs"
fi

TMP_DOM_PROJECT="$(mktemp -d "${TMPDIR:-/tmp}/securescan-dom-project.XXXXXX")"
mkdir -p "${TMP_DOM_PROJECT}/src"
cat > "${TMP_DOM_PROJECT}/src/safe_dom.js" <<'EOF'
// SECURITY: Avoids innerHTML by building nodes directly.
function clearAndRenderStatic(list) {
  list.innerHTML = '';
  list.innerHTML = '<li class="empty">None</li>';
}
EOF
cat > "${TMP_DOM_PROJECT}/src/unsafe_dom.js" <<'EOF'
function renderUserHtml(target) {
  target.innerHTML = location.hash;
}
EOF
TMP_DOM_OUTPUT="$(mktemp -d "${TMPDIR:-/tmp}/securescan-dom-output.XXXXXX")"
if bash "${ROOT_DIR}/scripts/securescan-static.sh" --project "${TMP_DOM_PROJECT}" --output "${TMP_DOM_OUTPUT}" >/dev/null &&
  grep -q "src/unsafe_dom.js" "${TMP_DOM_OUTPUT}/02-findings.md" &&
  ! grep -q "src/safe_dom.js" "${TMP_DOM_OUTPUT}/02-findings.md"; then
  pass "static scanner distinguishes static DOM assignments from dynamic innerHTML"
else
  fail "static scanner should suppress static/clearing innerHTML and flag dynamic innerHTML"
fi

if bash "${ROOT_DIR}/scripts/securescan.sh" doctor --skip-package-check >/dev/null; then
  pass "CLI doctor command runs"
else
  fail "CLI doctor command failed"
fi

if bash "${ROOT_DIR}/scripts/securescan.sh" export --artifacts "${TMP_OUTPUT}" --format all --output-dir "${TMP_OUTPUT}/exports" >/dev/null &&
  [ -f "${TMP_OUTPUT}/exports/summary.json" ] &&
  [ -f "${TMP_OUTPUT}/exports/findings.json" ] &&
  [ -f "${TMP_OUTPUT}/exports/securescan.sarif" ] &&
  [ -f "${TMP_OUTPUT}/exports/report.html" ] &&
  [ -f "${TMP_OUTPUT}/exports/securescan-summary.md" ]; then
  pass "CLI export command writes summary, JSON, SARIF, HTML, and Markdown"
else
  fail "CLI export command did not write expected exports"
fi

if grep -q ".securescan/" "${ROOT_DIR}/README.md" && grep -q "scripts/install.sh" "${ROOT_DIR}/README.md" && grep -q "securescan scan" "${ROOT_DIR}/README.md"; then
  pass "README documents install and artifacts"
else
  fail "README missing install/artifact/CLI documentation"
fi

if grep -q "Value Proposition" "${ROOT_DIR}/docs/SECURESCAN-OVERVIEW.md" &&
  grep -q "What It Is Not" "${ROOT_DIR}/docs/SECURESCAN-OVERVIEW.md" &&
  grep -q "scripts/securescan-static.sh" "${ROOT_DIR}/docs/SECURESCAN-OVERVIEW.md" &&
  grep -q "securescan export" "${ROOT_DIR}/docs/SECURESCAN-OVERVIEW.md"; then
  pass "overview document covers value, limits, and operations"
else
  fail "overview document is missing required product sections"
fi

if [ "$FAILURES" -eq 0 ]; then
  echo "SecureScan package validation passed."
else
  echo "SecureScan package validation failed with ${FAILURES} issue(s)." >&2
  exit 1
fi
