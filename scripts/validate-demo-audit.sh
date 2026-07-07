#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  bash scripts/validate-demo-audit.sh --project /path/to/demo-project
  bash scripts/validate-demo-audit.sh --artifacts /path/to/securescan-artifacts

Validates that a SecureScan audit of examples/vulnerable-demo found the expected vulnerability themes.
EOF
}

PROJECT_PATH=""
ARTIFACT_PATH=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --project)
      [ "$#" -ge 2 ] || { echo "Missing value for --project" >&2; exit 2; }
      PROJECT_PATH="$2"
      shift 2
      ;;
    --artifacts)
      [ "$#" -ge 2 ] || { echo "Missing value for --artifacts" >&2; exit 2; }
      ARTIFACT_PATH="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [ -n "$PROJECT_PATH" ] && [ -n "$ARTIFACT_PATH" ]; then
  echo "Choose either --project or --artifacts, not both." >&2
  exit 2
fi

if [ -z "$PROJECT_PATH" ] && [ -z "$ARTIFACT_PATH" ]; then
  usage >&2
  exit 2
fi

if [ -n "$ARTIFACT_PATH" ]; then
  ROOT="${ARTIFACT_PATH%/}"
else
  ROOT="${PROJECT_PATH%/}/.securescan"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"${SCRIPT_DIR}/validate-securescan-artifacts.sh" --artifacts "$ROOT" --phase 4

FAILURES=0

fail() {
  echo "FAIL: $*" >&2
  FAILURES=$((FAILURES + 1))
}

pass() {
  echo "PASS: $*"
}

require_theme() {
  local name="$1"
  local pattern="$2"

  if grep -RIE "$pattern" "$ROOT" >/dev/null 2>&1; then
    pass "demo theme found: ${name}"
  else
    fail "demo theme missing: ${name}"
  fi
}

require_theme "SQL injection" 'SQL injection|SQL string concatenation|SELECT \* FROM users|req\.query\.email'
require_theme "XSS" 'XSS|innerHTML|req\.query\.name|res\.send.*Hello'
require_theme "permissive CORS" 'CORS|origin: "\*"|origin.*\*'
require_theme "missing login rate limiting" 'rate limit|rate limiting|/login'
require_theme "demo fallback key" 'DEMO_ONLY_NOT_A_SECRET|demoFallbackApiKey|fallback key'
require_theme "mutable CI action" 'actions/checkout@v4|mutable GitHub Action|mutable action'
require_theme "Docker hardening" 'node:latest|non-root|Docker latest|latest Tag'
require_theme "100 percent coverage" '"coverage_percent"[[:space:]]*:[[:space:]]*100|100 percent coverage'

if [ "$FAILURES" -eq 0 ]; then
  echo "SecureScan vulnerable-demo regression validation passed."
else
  echo "SecureScan vulnerable-demo regression validation failed with ${FAILURES} issue(s)." >&2
  exit 1
fi
