#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  bash scripts/validate-securescan-artifacts.sh --project /path/to/project [--phase 1|2|3|4]
  bash scripts/validate-securescan-artifacts.sh --artifacts /path/to/securescan-artifacts [--phase 1|2|3|4]

Validates generated SecureScan artifacts in /path/to/project/.securescan or a direct artifact directory.
EOF
}

PROJECT_PATH=""
ARTIFACT_PATH=""
PHASE="4"

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
    --phase)
      [ "$#" -ge 2 ] || { echo "Missing value for --phase" >&2; exit 2; }
      PHASE="$2"
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

case "$PHASE" in
  1|2|3|4) ;;
  *) echo "--phase must be 1, 2, 3, or 4" >&2; exit 2 ;;
esac

if [ -n "$ARTIFACT_PATH" ]; then
  ROOT="${ARTIFACT_PATH%/}"
else
  ROOT="${PROJECT_PATH%/}/.securescan"
fi
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
  if [ -f "${ROOT}/${path}" ]; then
    pass "artifact exists: ${path}"
  else
    fail "missing artifact: ${path}"
  fi
}

require_contains() {
  local path="$1"
  local pattern="$2"
  if [ -f "${ROOT}/${path}" ] && grep -Eq "$pattern" "${ROOT}/${path}"; then
    pass "${path} contains ${pattern}"
  else
    fail "${path} missing required content: ${pattern}"
  fi
}

if [ ! -d "$ROOT" ]; then
  echo "Missing .securescan directory: $ROOT" >&2
  exit 1
fi

require_file "00-scope.md"
require_contains "00-scope.md" "Authorization|Allowed mode|Out Of Scope|In Scope"

if [ "$PHASE" -ge 1 ]; then
  require_file "file-manifest.tsv"
  require_file "01-recon.md"
  require_contains "01-recon.md" "Architecture|Entry Points|Data Classification|Out Of Scope"
fi

if [ "$PHASE" -ge 2 ]; then
  require_file "02-findings.md"
  require_file "coverage.json"
  require_contains "coverage.json" '"schema_version"'
  require_contains "coverage.json" '"files_total"'
  require_contains "coverage.json" '"files_scanned"'
  if command -v python3 >/dev/null 2>&1; then
    if python3 -m json.tool "${ROOT}/coverage.json" >/dev/null; then
      pass "coverage.json is valid JSON"
    else
      fail "coverage.json is not valid JSON"
    fi
    if python3 - "${ROOT}/coverage.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as handle:
    data = json.load(handle)

errors = []

def expect(condition, message):
    if not condition:
        errors.append(message)

for key in ["schema_version", "generated_at", "project_root", "scope", "summary", "coverage", "skipped", "tool_runs"]:
    expect(key in data, f"missing top-level key: {key}")

summary = data.get("summary", {})
for key in ["files_total", "files_scanned", "files_partial", "files_skipped", "coverage_percent"]:
    expect(key in summary, f"missing summary key: {key}")

for key in ["files_total", "files_scanned", "files_partial", "files_skipped"]:
    expect(isinstance(summary.get(key), int), f"summary.{key} must be an integer")

percent = summary.get("coverage_percent")
expect(isinstance(percent, (int, float)), "summary.coverage_percent must be numeric")
if isinstance(percent, (int, float)):
    expect(0 <= percent <= 100, "summary.coverage_percent must be between 0 and 100")

coverage = data.get("coverage", [])
skipped = data.get("skipped", [])
tool_runs = data.get("tool_runs", [])
expect(isinstance(coverage, list), "coverage must be a list")
expect(isinstance(skipped, list), "skipped must be a list")
expect(isinstance(tool_runs, list), "tool_runs must be a list")

allowed_status = {"Full", "Partial", "Skipped"}
allowed_risk = {"Critical", "High", "Medium", "Low"}
seen_paths = set()

full_count = 0
partial_count = 0
skipped_count = 0

if isinstance(coverage, list):
    for index, item in enumerate(coverage):
        expect(isinstance(item, dict), f"coverage[{index}] must be an object")
        if not isinstance(item, dict):
            continue
        for key in ["path", "risk_tier", "status", "reason", "patterns_applied", "findings"]:
            expect(key in item, f"coverage[{index}] missing key: {key}")
        item_path = item.get("path")
        status = item.get("status")
        risk = item.get("risk_tier")
        expect(isinstance(item_path, str) and item_path, f"coverage[{index}].path must be a non-empty string")
        expect(item_path not in seen_paths, f"duplicate coverage path: {item_path}")
        if item_path:
            seen_paths.add(item_path)
        expect(risk in allowed_risk, f"coverage[{index}].risk_tier must be one of {sorted(allowed_risk)}")
        expect(status in allowed_status, f"coverage[{index}].status must be one of {sorted(allowed_status)}")
        expect(isinstance(item.get("reason"), str), f"coverage[{index}].reason must be a string")
        expect(isinstance(item.get("patterns_applied"), list), f"coverage[{index}].patterns_applied must be a list")
        expect(isinstance(item.get("findings"), list), f"coverage[{index}].findings must be a list")
        if status != "Full":
            expect(bool(item.get("reason")), f"coverage[{index}] with status {status} needs a reason")
        if status == "Full":
            full_count += 1
        elif status == "Partial":
            partial_count += 1
        elif status == "Skipped":
            skipped_count += 1

if isinstance(skipped, list):
    for index, item in enumerate(skipped):
        expect(isinstance(item, dict), f"skipped[{index}] must be an object")
        if not isinstance(item, dict):
            continue
        expect(isinstance(item.get("path"), str) and item.get("path"), f"skipped[{index}].path must be a non-empty string")
        expect(isinstance(item.get("reason"), str) and item.get("reason"), f"skipped[{index}].reason must be a non-empty string")
    skipped_count += len(skipped)

if isinstance(tool_runs, list):
    for index, item in enumerate(tool_runs):
        expect(isinstance(item, dict), f"tool_runs[{index}] must be an object")
        if not isinstance(item, dict):
            continue
        expect(isinstance(item.get("tool"), str) and item.get("tool"), f"tool_runs[{index}].tool must be a non-empty string")
        expect(item.get("status") in {"run", "not-run", "failed", "partial"}, f"tool_runs[{index}].status has invalid value")
        expect(isinstance(item.get("reason"), str), f"tool_runs[{index}].reason must be a string")

if isinstance(summary.get("files_scanned"), int):
    expect(summary["files_scanned"] == full_count, f"files_scanned {summary['files_scanned']} does not match Full coverage count {full_count}")
if isinstance(summary.get("files_partial"), int):
    expect(summary["files_partial"] == partial_count, f"files_partial {summary['files_partial']} does not match Partial coverage count {partial_count}")
if isinstance(summary.get("files_skipped"), int):
    expect(summary["files_skipped"] == skipped_count, f"files_skipped {summary['files_skipped']} does not match skipped count {skipped_count}")
if isinstance(summary.get("files_total"), int):
    expected_total = full_count + partial_count + skipped_count
    expect(summary["files_total"] == expected_total, f"files_total {summary['files_total']} does not match counted total {expected_total}")

if errors:
    for error in errors:
        print(error, file=sys.stderr)
    sys.exit(1)
PY
    then
      pass "coverage.json schema is valid"
    else
      fail "coverage.json schema validation failed"
    fi
  fi
fi

if [ "$PHASE" -ge 3 ]; then
  require_file "nist-ai-rmf-evidence.md"
  require_contains "nist-ai-rmf-evidence.md" "Govern"
  require_contains "nist-ai-rmf-evidence.md" "Map"
  require_contains "nist-ai-rmf-evidence.md" "Measure"
  require_contains "nist-ai-rmf-evidence.md" "Manage"
  require_contains "nist-ai-rmf-evidence.md" "Compliant|Partial|Gap|Not Applicable|Not Assessed"
  require_file "03-analysis.md"
  require_contains "03-analysis.md" "Validated|False Positive|STRIDE|Attack Chain|HIPAA|NIST AI RMF"
fi

if [ "$PHASE" -ge 4 ]; then
  require_file "04-report.md"
  require_contains "04-report.md" "Executive Summary|Scope|Validated Findings|Remediation|Risk Acceptance"
  require_contains "04-report.md" '^## Compliance Matrices$'
fi

if grep -RInE '(AKIA[0-9A-Z]{16}|BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY|ghp_[A-Za-z0-9_]{30,}|sk-[A-Za-z0-9]{20,})' "$ROOT" >/dev/null 2>&1; then
  fail "potential raw secret pattern found in .securescan artifacts"
else
  pass "no obvious raw secret patterns found"
fi

if [ "$FAILURES" -eq 0 ]; then
  echo "SecureScan artifact validation passed."
else
  echo "SecureScan artifact validation failed with ${FAILURES} issue(s)." >&2
  exit 1
fi
