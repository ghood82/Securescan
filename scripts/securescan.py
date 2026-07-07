#!/usr/bin/env python3
"""SecureScan command-line front door.

The deterministic scanner remains the artifact generator. This wrapper gives
users a smaller command surface for first-run setup, validation, demo runs, and
report exports.
"""

from __future__ import annotations

import argparse
import datetime as dt
import getpass
import html
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


VERSION = "2.4.0"
ROOT_DIR = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT_DIR / "scripts"
STATIC_SCANNER = SCRIPTS_DIR / "securescan-static.sh"
INSTALLER = SCRIPTS_DIR / "install.sh"
PACKAGE_VALIDATOR = SCRIPTS_DIR / "validate-package.sh"
ARTIFACT_VALIDATOR = SCRIPTS_DIR / "validate-securescan-artifacts.sh"
DEMO_VALIDATOR = SCRIPTS_DIR / "validate-demo-audit.sh"
DEMO_PROJECT = ROOT_DIR / "examples" / "vulnerable-demo"


SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
SARIF_LEVELS = {
    "Critical": "error",
    "High": "error",
    "Medium": "warning",
    "Low": "note",
    "Informational": "note",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="securescan",
        description="Run, validate, demo, install, and export SecureScan audits.",
    )
    parser.add_argument("--version", action="version", version=f"SecureScan CLI {VERSION}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor = subparsers.add_parser("doctor", help="Check local SecureScan package readiness.")
    doctor.add_argument(
        "--skip-package-check",
        action="store_true",
        help="Only check local tools and paths; do not run validate-package.sh.",
    )
    doctor.set_defaults(func=cmd_doctor)

    demo = subparsers.add_parser("demo", help="Run the bundled vulnerable-demo scan and validation.")
    demo.add_argument(
        "--output",
        default=None,
        help="Demo artifact directory. Defaults to a fresh /tmp/securescan-demo-* directory.",
    )
    demo.add_argument(
        "--keep",
        action="store_true",
        help="Retained for compatibility; demo artifacts are always kept and printed.",
    )
    demo.add_argument(
        "--format",
        default="summary",
        help="Comma-separated exports: summary,json,sarif,html,markdown,all. Defaults to summary.",
    )
    demo.set_defaults(func=cmd_demo)

    scan = subparsers.add_parser("scan", help="Run a static local SecureScan audit.")
    scan.add_argument("project", help="Project directory to scan.")
    scan.add_argument(
        "--output",
        default=None,
        help="Artifact directory. Defaults to PROJECT/.securescan.",
    )
    scan.add_argument(
        "--max-file-bytes",
        type=int,
        default=1_000_000,
        help="Skip files larger than this many bytes. Defaults to 1MB.",
    )
    scan.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Exit with code 10 after a successful scan when findings are produced.",
    )
    scan.add_argument(
        "--wizard",
        action="store_true",
        help="Ask scope and authorization questions before writing final scope metadata.",
    )
    scan.add_argument(
        "--yes",
        action="store_true",
        help="Accept static-local-review defaults without prompts.",
    )
    scan.add_argument(
        "--authorized-by",
        default=None,
        help="Name or team authorizing the static local review.",
    )
    scan.add_argument(
        "--scope-note",
        action="append",
        default=[],
        help="Additional scope note. May be repeated.",
    )
    scan.add_argument(
        "--format",
        default="summary",
        help="Comma-separated exports: summary,json,sarif,html,markdown,all. Defaults to summary.",
    )
    scan.set_defaults(func=cmd_scan)

    validate = subparsers.add_parser("validate", help="Validate generated SecureScan artifacts.")
    target = validate.add_mutually_exclusive_group(required=True)
    target.add_argument("--project", help="Project whose PROJECT/.securescan artifacts should be validated.")
    target.add_argument("--artifacts", help="Direct path to a .securescan artifact directory.")
    validate.add_argument("--phase", choices=["1", "2", "3", "4"], default="4")
    validate.add_argument(
        "--demo",
        action="store_true",
        help="Also validate vulnerable-demo expected finding themes.",
    )
    validate.set_defaults(func=cmd_validate)

    export = subparsers.add_parser("export", help="Export an existing SecureScan artifact set.")
    export_target = export.add_mutually_exclusive_group(required=True)
    export_target.add_argument("--project", help="Project whose PROJECT/.securescan artifacts should be exported.")
    export_target.add_argument("--artifacts", help="Direct path to a .securescan artifact directory.")
    export.add_argument(
        "--format",
        default="all",
        help="Comma-separated exports: summary,json,sarif,html,markdown,all. Defaults to all.",
    )
    export.add_argument(
        "--output-dir",
        default=None,
        help="Export directory. Defaults to ARTIFACTS/exports.",
    )
    export.set_defaults(func=cmd_export)

    install = subparsers.add_parser("install", help="Install SecureScan agents and skills.")
    install_target = install.add_mutually_exclusive_group(required=True)
    install_target.add_argument("--project", help="Install into PROJECT/.claude.")
    install_target.add_argument("--global", dest="global_install", action="store_true", help="Install into ~/.claude.")
    install.add_argument("--force", action="store_true", help="Replace existing SecureScan files if they differ.")
    install.add_argument("--dry-run", action="store_true", help="Print installer actions without writing files.")
    install.set_defaults(func=cmd_install)

    return parser.parse_args()


def run_command(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, check=check)


def artifact_dir_for(project: Path, output: str | None = None) -> Path:
    return Path(output).expanduser().resolve() if output else project / ".securescan"


def artifacts_from_args(args: argparse.Namespace) -> Path:
    if getattr(args, "artifacts", None):
        return Path(args.artifacts).expanduser().resolve()
    return Path(args.project).expanduser().resolve() / ".securescan"


def parse_formats(value: str) -> set[str]:
    requested = {part.strip().lower() for part in value.split(",") if part.strip()}
    if not requested:
        return {"summary"}
    if "all" in requested:
        return {"summary", "json", "sarif", "html", "markdown"}
    allowed = {"summary", "json", "sarif", "html", "markdown"}
    unknown = requested - allowed
    if unknown:
        raise SystemExit(f"Unknown export format(s): {', '.join(sorted(unknown))}")
    return requested


def load_coverage(artifacts: Path) -> dict[str, Any]:
    path = artifacts / "coverage.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def parse_analysis_findings(artifacts: Path) -> list[dict[str, Any]]:
    path = artifacts / "03-analysis.md"
    if not path.exists():
        return []

    text = path.read_text(encoding="utf-8", errors="replace")
    blocks = re.split(r"(?=^### FINDING: )", text, flags=re.MULTILINE)
    findings: list[dict[str, Any]] = []
    for block in blocks:
        heading = re.search(r"^### FINDING: (?P<id>\S+) - (?P<title>.+)$", block, re.MULTILINE)
        if not heading:
            continue
        location = field_value(block, "Location")
        file_path, line = parse_location(location)
        findings.append(
            {
                "id": heading.group("id"),
                "title": heading.group("title").strip(),
                "severity": field_value(block, "Severity") or "Informational",
                "confidence": field_value(block, "Confidence") or "Unknown",
                "owasp": field_value(block, "OWASP") or "Unmapped",
                "cwe": field_value(block, "CWE") or "Unmapped",
                "location": location,
                "file": file_path,
                "line": line,
                "evidence": fenced_value(block, "Vulnerable Code"),
                "remediation": paragraph_value(block, "Remediation"),
                "verification": paragraph_value(block, "Verification"),
            }
        )
    findings.sort(key=lambda item: (SEVERITY_ORDER.get(str(item["severity"]), 9), str(item["id"])))
    return findings


def field_value(text: str, name: str) -> str:
    match = re.search(rf"^{re.escape(name)}:\s*(.+)$", text, flags=re.MULTILINE)
    return match.group(1).strip() if match else ""


def fenced_value(text: str, heading: str) -> str:
    match = re.search(rf"^{re.escape(heading)}:\n`(.+?)`", text, flags=re.MULTILINE | re.DOTALL)
    return match.group(1).strip() if match else ""


def paragraph_value(text: str, heading: str) -> str:
    match = re.search(rf"^{re.escape(heading)}:\n(.+?)(?:\n\n[A-Z][A-Za-z ]+?:|\Z)", text, re.DOTALL | re.MULTILINE)
    if not match:
        return ""
    return match.group(1).strip()


def parse_location(location: str) -> tuple[str, int]:
    if not location:
        return "", 1
    match = re.match(r"(.+):(\d+)$", location)
    if not match:
        return location, 1
    return match.group(1), int(match.group(2))


def severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for finding in findings:
        severity = str(finding.get("severity") or "Informational")
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def print_summary(artifacts: Path, *, label: str = "SecureScan") -> None:
    coverage = load_coverage(artifacts)
    findings = parse_analysis_findings(artifacts)
    counts = severity_counts(findings)
    summary = coverage.get("summary", {})

    print(f"\n{label} summary")
    print(f"Artifacts: {artifacts}")
    print(
        "Findings: "
        f"{len(findings)} total "
        f"(Critical {counts.get('Critical', 0)}, High {counts.get('High', 0)}, "
        f"Medium {counts.get('Medium', 0)}, Low {counts.get('Low', 0)})"
    )
    if summary:
        print(
            "Coverage: "
            f"{summary.get('coverage_percent', 'unknown')}% "
            f"({summary.get('files_scanned', 'unknown')} scanned, "
            f"{summary.get('files_skipped', 'unknown')} skipped)"
        )
    report = artifacts / "04-report.md"
    if report.exists():
        print(f"Report: {report}")
    top = findings[:3]
    if top:
        print("Top remediation items:")
        for index, finding in enumerate(top, start=1):
            location = finding.get("location") or "unknown"
            remediation = finding.get("remediation") or "Review and remediate this finding."
            print(f"{index}. {finding['severity']} - {finding['title']} ({location})")
            print(f"   {remediation}")


def cmd_doctor(args: argparse.Namespace) -> int:
    checks = [
        ("package root", ROOT_DIR.exists()),
        ("python3", shutil.which("python3") is not None),
        ("static scanner", STATIC_SCANNER.exists()),
        ("package validator", PACKAGE_VALIDATOR.exists()),
        ("artifact validator", ARTIFACT_VALIDATOR.exists()),
        ("demo project", DEMO_PROJECT.exists()),
    ]
    failures = 0
    for name, ok in checks:
        status = "PASS" if ok else "FAIL"
        print(f"{status}: {name}")
        failures += 0 if ok else 1

    optional_tools = ["rg", "semgrep", "gitleaks", "trufflehog", "osv-scanner", "trivy", "checkov"]
    available = [tool for tool in optional_tools if shutil.which(tool)]
    print(f"Optional tools available: {', '.join(available) if available else 'none detected'}")

    if not args.skip_package_check:
        result = run_command(["bash", str(PACKAGE_VALIDATOR), str(ROOT_DIR)], check=False)
        if result.returncode != 0:
            failures += 1
    if failures:
        print(f"SecureScan doctor failed with {failures} issue(s).")
        return 1
    print("SecureScan doctor passed.")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    output = Path(args.output).expanduser().resolve() if args.output else Path(
        tempfile.mkdtemp(prefix="securescan-demo-")
    )
    scan_result = run_static_scan(DEMO_PROJECT, output, max_file_bytes=1_000_000, fail_on_findings=False)
    if scan_result != 0:
        return scan_result
    result = run_command(["bash", str(DEMO_VALIDATOR), "--artifacts", str(output)], check=False)
    formats = parse_formats(args.format)
    export_paths = export_artifacts(output, formats, output / "exports")
    print_summary(output, label="SecureScan demo")
    print_export_paths(export_paths)
    print(f"Demo artifacts kept at: {output}")
    return result.returncode


def cmd_scan(args: argparse.Namespace) -> int:
    project = Path(args.project).expanduser().resolve()
    output = artifact_dir_for(project, args.output)
    scope = collect_scope(project, args)
    result = run_static_scan(project, output, args.max_file_bytes, fail_on_findings=False)
    if result != 0:
        return result
    write_cli_scope(output, project, scope)
    validate_result = run_command(["bash", str(ARTIFACT_VALIDATOR), "--artifacts", str(output), "--phase", "4"], check=False)
    formats = parse_formats(args.format)
    export_paths = export_artifacts(output, formats, output / "exports")
    print_summary(output)
    print_export_paths(export_paths)

    if validate_result.returncode != 0:
        return validate_result.returncode
    findings = parse_analysis_findings(output)
    if args.fail_on_findings and findings:
        return 10
    return result


def cmd_validate(args: argparse.Namespace) -> int:
    artifacts = artifacts_from_args(args)
    command = ["bash", str(ARTIFACT_VALIDATOR), "--artifacts", str(artifacts), "--phase", args.phase]
    result = run_command(command, check=False)
    if result.returncode != 0:
        return result.returncode
    if args.demo:
        return run_command(["bash", str(DEMO_VALIDATOR), "--artifacts", str(artifacts)], check=False).returncode
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    artifacts = artifacts_from_args(args)
    output_dir = Path(args.output_dir).expanduser().resolve() if args.output_dir else artifacts / "exports"
    formats = parse_formats(args.format)
    export_paths = export_artifacts(artifacts, formats, output_dir)
    print_summary(artifacts)
    print_export_paths(export_paths)
    return 0


def cmd_install(args: argparse.Namespace) -> int:
    command = ["bash", str(INSTALLER)]
    if args.global_install:
        command.append("--global")
    else:
        command.extend(["--project", args.project])
    if args.force:
        command.append("--force")
    if args.dry_run:
        command.append("--dry-run")
    return run_command(command, check=False).returncode


def run_static_scan(project: Path, output: Path, max_file_bytes: int, *, fail_on_findings: bool) -> int:
    command = [
        "bash",
        str(STATIC_SCANNER),
        "--project",
        str(project),
        "--output",
        str(output),
        "--max-file-bytes",
        str(max_file_bytes),
    ]
    if fail_on_findings:
        command.append("--fail-on-findings")
    return run_command(command, check=False).returncode


def collect_scope(project: Path, args: argparse.Namespace) -> dict[str, Any]:
    interactive = args.wizard or (sys.stdin.isatty() and not args.yes)
    authorized_by = args.authorized_by or getpass.getuser()
    notes = list(args.scope_note)
    confirmed = args.yes or not interactive

    if interactive:
        print("SecureScan static-local-review setup")
        print(f"Target project: {project}")
        response = input(f"Authorized by [{authorized_by}]: ").strip()
        if response:
            authorized_by = response
        note = input("Scope note [source/config/CI/container files only]: ").strip()
        if note:
            notes.append(note)
        approval = input("Type YES to confirm this authorized static local review: ").strip()
        confirmed = approval == "YES"
        if not confirmed:
            raise SystemExit("Scan cancelled because authorization was not confirmed.")

    return {
        "authorized_by": authorized_by,
        "confirmed": confirmed,
        "notes": notes or ["Static local review of discovered source, config, CI/CD, dependency, and container files."],
        "timestamp": dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "invocation": "wizard" if interactive else "non-interactive defaults",
    }


def write_cli_scope(output: Path, project: Path, scope: dict[str, Any]) -> None:
    notes = "\n".join(f"- {note}" for note in scope["notes"])
    content = f"""# SecureScan Scope And Authorization

Audit date: {dt.date.today().isoformat()}
Auditor: SecureScan CLI v{VERSION}
Target project: {project}

## Authorization

- Authorized by: {scope["authorized_by"]}
- Authorization evidence: SecureScan CLI {scope["invocation"]}
- Allowed mode: Static local review
- Explicitly approved active testing: No
- Explicitly approved external network testing: No
- Explicitly approved dependency installation/downloads: No
- Explicitly approved production access: No
- Authorization confirmed: {"Yes" if scope["confirmed"] else "No"}
- Recorded at: {scope["timestamp"]}

## In Scope

- Source files, manifests, configuration, CI/CD, container, and infrastructure files discovered under the target project.
{notes}

## Out Of Scope

- Runtime exploitation
- External network testing
- Dependency installation
- Production access
- Secret value disclosure

## Data Handling

- Secret-like values are redacted from code evidence where detected.
- Artifacts are written locally under this output directory.
"""
    (output / "00-scope.md").write_text(content, encoding="utf-8")


def export_artifacts(artifacts: Path, formats: set[str], output_dir: Path) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    coverage = load_coverage(artifacts)
    findings = parse_analysis_findings(artifacts)
    paths: list[Path] = []

    if "summary" in formats:
        paths.append(write_summary_json(output_dir, coverage, findings))
    if "json" in formats:
        paths.append(write_findings_json(output_dir, coverage, findings))
    if "sarif" in formats:
        paths.append(write_sarif(output_dir, findings))
    if "html" in formats:
        paths.append(write_html_report(output_dir, artifacts, coverage, findings))
    if "markdown" in formats:
        paths.append(write_markdown_summary(output_dir, artifacts, coverage, findings))
    return paths


def write_summary_json(output_dir: Path, coverage: dict[str, Any], findings: list[dict[str, Any]]) -> Path:
    path = output_dir / "summary.json"
    path.write_text(
        json.dumps(
            {
                "generated_at": dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                "coverage": coverage.get("summary", {}),
                "finding_count": len(findings),
                "severity_counts": severity_counts(findings),
                "top_findings": findings[:3],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def write_findings_json(output_dir: Path, coverage: dict[str, Any], findings: list[dict[str, Any]]) -> Path:
    path = output_dir / "findings.json"
    path.write_text(
        json.dumps({"coverage": coverage, "findings": findings}, indent=2) + "\n",
        encoding="utf-8",
    )
    return path


def write_sarif(output_dir: Path, findings: list[dict[str, Any]]) -> Path:
    path = output_dir / "securescan.sarif"
    rules = {}
    results = []
    for finding in findings:
        rule_id = str(finding.get("cwe") or finding.get("owasp") or "SecureScan")
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": rule_id},
                "helpUri": "https://cwe.mitre.org/",
            },
        )
        results.append(
            {
                "ruleId": rule_id,
                "level": SARIF_LEVELS.get(str(finding.get("severity")), "warning"),
                "message": {"text": f"{finding.get('title')} - {finding.get('remediation')}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.get("file") or "unknown"},
                            "region": {"startLine": finding.get("line") or 1},
                        }
                    }
                ],
                "properties": {
                    "secureScanId": finding.get("id"),
                    "severity": finding.get("severity"),
                    "confidence": finding.get("confidence"),
                },
            }
        )

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecureScan",
                        "semanticVersion": VERSION,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    path.write_text(json.dumps(sarif, indent=2) + "\n", encoding="utf-8")
    return path


def write_html_report(
    output_dir: Path,
    artifacts: Path,
    coverage: dict[str, Any],
    findings: list[dict[str, Any]],
) -> Path:
    path = output_dir / "report.html"
    counts = severity_counts(findings)
    summary = coverage.get("summary", {})
    rows = "\n".join(
        "<tr>"
        f"<td>{html.escape(str(finding.get('severity')))}</td>"
        f"<td>{html.escape(str(finding.get('title')))}</td>"
        f"<td>{html.escape(str(finding.get('location')))}</td>"
        f"<td>{html.escape(str(finding.get('remediation')))}</td>"
        "</tr>"
        for finding in findings
    )
    if not rows:
        rows = '<tr><td colspan="4">No findings.</td></tr>'

    html_text = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>SecureScan Report</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 32px; color: #1f2933; }}
    h1, h2 {{ margin-bottom: 8px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 16px; }}
    th, td {{ border: 1px solid #c8d0d9; padding: 8px; text-align: left; vertical-align: top; }}
    th {{ background: #eef3f8; }}
    .meta {{ color: #52606d; }}
  </style>
</head>
<body>
  <h1>SecureScan Report</h1>
  <p class="meta">Artifacts: {html.escape(str(artifacts))}</p>
  <h2>Summary</h2>
  <p>Findings: {len(findings)} total. Critical {counts.get('Critical', 0)}, High {counts.get('High', 0)}, Medium {counts.get('Medium', 0)}, Low {counts.get('Low', 0)}.</p>
  <p>Coverage: {html.escape(str(summary.get('coverage_percent', 'unknown')))}%.</p>
  <h2>Findings</h2>
  <table>
    <thead><tr><th>Severity</th><th>Finding</th><th>Location</th><th>Remediation</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</body>
</html>
"""
    path.write_text(html_text, encoding="utf-8")
    return path


def write_markdown_summary(
    output_dir: Path,
    artifacts: Path,
    coverage: dict[str, Any],
    findings: list[dict[str, Any]],
) -> Path:
    path = output_dir / "securescan-summary.md"
    counts = severity_counts(findings)
    summary = coverage.get("summary", {})
    lines = [
        "# SecureScan Summary",
        "",
        f"Artifacts: `{artifacts}`",
        "",
        "## Findings",
        "",
        f"- Total: {len(findings)}",
        f"- Critical: {counts.get('Critical', 0)}",
        f"- High: {counts.get('High', 0)}",
        f"- Medium: {counts.get('Medium', 0)}",
        f"- Low: {counts.get('Low', 0)}",
        "",
        "## Coverage",
        "",
        f"- Coverage percent: {summary.get('coverage_percent', 'unknown')}",
        f"- Files scanned: {summary.get('files_scanned', 'unknown')}",
        f"- Files skipped: {summary.get('files_skipped', 'unknown')}",
        "",
        "## Top Remediation Items",
        "",
    ]
    if findings:
        for index, finding in enumerate(findings[:5], start=1):
            lines.append(f"{index}. **{finding.get('severity')}** - {finding.get('title')} at `{finding.get('location')}`")
            lines.append(f"   - {finding.get('remediation')}")
    else:
        lines.append("No findings.")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def print_export_paths(paths: list[Path]) -> None:
    if not paths:
        return
    print("Exports:")
    for path in paths:
        print(f"- {path}")


def main() -> int:
    args = parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
