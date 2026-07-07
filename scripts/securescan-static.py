#!/usr/bin/env python3
"""Deterministic static SecureScan runner.

This script gives the package an executable path that produces the same artifact
contract as the Claude Code agents. It is intentionally conservative: findings
are static-analysis candidates with code evidence and remediation guidance, not
proof of runtime exploitability unless the pattern is provable from source alone.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


VERSION = "2.4.0"

EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".securescan",
    "node_modules",
    "dist",
    "build",
    "coverage",
    ".next",
    ".nuxt",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".turbo",
    "golden-output",
}

TEXT_SUFFIXES = {
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".py",
    ".rb",
    ".go",
    ".java",
    ".php",
    ".cs",
    ".rs",
    ".swift",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".env",
    ".example",
    ".md",
    ".txt",
    ".sh",
    ".bash",
    ".zsh",
    ".sql",
    ".tf",
    ".hcl",
}

SPECIAL_FILENAMES = {
    "Dockerfile",
    "Containerfile",
    "Makefile",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "requirements.txt",
    "pyproject.toml",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
}


@dataclass
class ManifestItem:
    path: str
    type: str
    risk_tier: str
    scan_required: str
    reason: str


@dataclass
class EntryPoint:
    type: str
    method: str
    path: str
    location: str
    auth_required: str = "Unknown"
    notes: str = ""


@dataclass
class Finding:
    raw_id: str
    final_id: str
    title: str
    pattern: str
    file: str
    line: int
    code: str
    category: str
    data_class: str
    confidence_initial: str
    confidence: str
    severity: str
    cvss: str
    cwe: str
    notes: str
    remediation: str
    verification: str
    root_cause: str
    patterns_applied: list[str] = field(default_factory=list)


NIST_AI_RMF_ROWS = [
    (
        "Govern",
        "Govern 1: AI risk policies, processes, procedures, and practices",
        "AI use policy, risk tolerance, model approval process, AI system inventory, review cadence, decommissioning process",
    ),
    (
        "Govern",
        "Govern 2: Accountability structures",
        "Named owners, reviewer roles, approval authority, training expectations, executive risk accountability",
    ),
    (
        "Govern",
        "Govern 3: Workforce and human-AI role definitions",
        "Human oversight roles, escalation paths, accessibility and inclusion review where relevant",
    ),
    (
        "Govern",
        "Govern 4: Risk culture and communication",
        "AI risk documentation, incident sharing, testing expectations, safety-first development practices",
    ),
    (
        "Govern",
        "Govern 5: Engagement with relevant AI actors",
        "User, stakeholder, affected-community, customer, operator, or domain-expert feedback channels",
    ),
    (
        "Govern",
        "Govern 6: Third-party software, data, and supply chain AI risks",
        "Model/provider due diligence, data provenance, license/IP review, third-party incident contingencies",
    ),
    (
        "Map",
        "Map 1: Context is established and understood",
        "Intended purpose, users, deployment setting, assumptions, laws, risk tolerance, AI system requirements",
    ),
    (
        "Map",
        "Map 2: AI system categorization",
        "Model/system type, task type, knowledge limits, human oversight, TEVV considerations",
    ),
    (
        "Map",
        "Map 3: Capabilities, usage, goals, benefits, and costs",
        "Target scope, expected benefits, error costs, operator proficiency, oversight process",
    ),
    (
        "Map",
        "Map 4: Risks and benefits for all components",
        "AI component inventory, third-party components, internal controls, legal/IP/security risks",
    ),
    (
        "Map",
        "Map 5: Individual, group, community, organizational, and societal impacts",
        "Likelihood and magnitude of impacts, feedback loops, impacted users or communities",
    ),
    (
        "Measure",
        "Measure 1: Methods and metrics are identified and applied",
        "Selected AI risk metrics, unmeasured risks, control effectiveness review, independent assessment",
    ),
    (
        "Measure",
        "Measure 2: Trustworthy characteristics are evaluated",
        "Test sets, evaluation methods, safety, validity, reliability, security, resilience, privacy, explainability, bias, transparency",
    ),
    (
        "Measure",
        "Measure 3: Mechanisms track AI risks over time",
        "Production monitoring, drift/error tracking, incident feedback, appeal or escalation signals",
    ),
    (
        "Measure",
        "Measure 4: Measurement efficacy feedback is gathered",
        "Domain-expert feedback, user feedback, affected-party input, field data, metric improvement review",
    ),
    (
        "Manage",
        "Manage 1: AI risks are prioritized, responded to, and managed",
        "Go/no-go decision, risk prioritization, treatment plan, residual risk documentation",
    ),
    (
        "Manage",
        "Manage 2: Benefits are maximized and negative impacts minimized",
        "Resource plan, non-AI alternatives, recovery from unknown risks, disengage/deactivate procedure",
    ),
    (
        "Manage",
        "Manage 3: Third-party AI risks and benefits are managed",
        "Provider/model monitoring, pretrained model maintenance, third-party control tracking",
    ),
    (
        "Manage",
        "Manage 4: Risk treatment, response, recovery, and communications",
        "Post-deployment monitoring, incident response, change management, appeal/override, continual improvement",
    ),
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run deterministic static SecureScan and write .securescan artifacts."
    )
    parser.add_argument(
        "--project",
        default=".",
        help="Project directory to scan. Defaults to current directory.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Artifact output directory. Defaults to PROJECT/.securescan.",
    )
    parser.add_argument(
        "--max-file-bytes",
        type=int,
        default=1_000_000,
        help="Skip individual files larger than this many bytes. Defaults to 1MB.",
    )
    parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Exit with code 10 when findings are produced.",
    )
    return parser.parse_args()


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def rel_path(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def is_excluded(path: Path, root: Path) -> bool:
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        return True
    return any(part in EXCLUDED_DIRS for part in parts)


def is_text_candidate(path: Path) -> bool:
    return path.name in SPECIAL_FILENAMES or path.suffix in TEXT_SUFFIXES


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def redact_code(line: str) -> str:
    redacted = line.rstrip("\n")
    redacted = re.sub(
        r"(?i)(api[_-]?key|secret|token|password)(['\"]?\s*[:=]\s*['\"])[^'\"]+(['\"])",
        r"\1\2[REDACTED]\3",
        redacted,
    )
    redacted = re.sub(r"AKIA[0-9A-Z]{16}", "[REDACTED_AWS_KEY]", redacted)
    redacted = re.sub(r"ghp_[A-Za-z0-9_]{30,}", "[REDACTED_GITHUB_TOKEN]", redacted)
    redacted = re.sub(r"sk-[A-Za-z0-9]{20,}", "[REDACTED_OPENAI_KEY]", redacted)
    return redacted


def list_files(project: Path, max_file_bytes: int) -> tuple[list[Path], list[dict[str, str]]]:
    files: list[Path] = []
    skipped: list[dict[str, str]] = []

    for current, dirs, names in os.walk(project):
        current_path = Path(current)
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        if is_excluded(current_path, project):
            continue

        for name in names:
            path = current_path / name
            if is_excluded(path, project):
                continue
            if not is_text_candidate(path):
                continue
            try:
                size = path.stat().st_size
            except OSError:
                skipped.append({"path": rel_path(path, project), "reason": "Could not stat file"})
                continue
            if size > max_file_bytes:
                skipped.append(
                    {
                        "path": rel_path(path, project),
                        "reason": f"File exceeds max-file-bytes limit ({max_file_bytes})",
                    }
                )
                continue
            files.append(path)

    files.sort(key=lambda item: rel_path(item, project))
    return files, skipped


def detect_type(path: Path, rel: str, text: str) -> str:
    lowered = rel.lower()
    if "/.github/workflows/" in f"/{lowered}" or lowered.startswith(".github/workflows/"):
        return "ci"
    if path.name in {"Dockerfile", "Containerfile"}:
        return "container"
    if path.name in {
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "requirements.txt",
        "pyproject.toml",
        "Pipfile",
        "Pipfile.lock",
        "poetry.lock",
        "go.mod",
        "Cargo.toml",
    }:
        return "dependency"
    if any(token in lowered for token in ["auth", "login", "session", "jwt", "oauth"]):
        return "auth"
    if any(token in lowered for token in ["api", "route", "controller", "handler", "server", "worker"]):
        return "api"
    if any(token in lowered for token in ["prompt", "llm", "agent", "mcp", "embedding", "vector"]):
        return "ai"
    if path.suffix in {".tf", ".hcl", ".yaml", ".yml", ".toml", ".ini", ".conf", ".cfg", ".env"}:
        return "config"
    if "app." in text or "@app." in text or "router." in text:
        return "api"
    if path.suffix in {".js", ".jsx", ".ts", ".tsx"}:
        return "source"
    if path.suffix == ".py":
        return "source"
    return "document"


def risk_tier(file_type: str, rel: str, text: str) -> str:
    lowered = rel.lower()
    high_tokens = ["auth", "login", "session", "jwt", "oauth", "password", "tenant", "admin"]
    critical_tokens = ["payment", "patient", "phi", "ephi", "ssn", "medical"]
    if any(token in lowered or token in text.lower() for token in critical_tokens):
        return "Critical"
    if file_type in {"auth", "api", "ai"} or any(token in lowered for token in high_tokens):
        return "High"
    if file_type in {"config", "ci", "container", "dependency"}:
        return "Medium"
    return "Low"


def build_manifest(project: Path, files: list[Path], skipped: list[dict[str, str]]) -> list[ManifestItem]:
    manifest: list[ManifestItem] = []
    for path in files:
        rel = rel_path(path, project)
        text = read_text(path)
        file_type = detect_type(path, rel, text)
        manifest.append(
            ManifestItem(
                path=rel,
                type=file_type,
                risk_tier=risk_tier(file_type, rel, text),
                scan_required="yes",
                reason=f"{file_type} file included in static review",
            )
        )

    for item in skipped:
        manifest.append(
            ManifestItem(
                path=item["path"],
                type="unknown",
                risk_tier="Low",
                scan_required="no",
                reason=item["reason"],
            )
        )

    tier_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    manifest.sort(key=lambda item: (tier_order.get(item.risk_tier, 4), item.path))
    return manifest


def detect_entry_points(project: Path, files: list[Path]) -> list[EntryPoint]:
    entries: list[EntryPoint] = []
    express_route = re.compile(r"\b(?:app|router)\.(get|post|put|patch|delete)\(\s*['\"]([^'\"]+)['\"]")
    fastapi_route = re.compile(r"@(?:app|router)\.(get|post|put|patch|delete)\(\s*['\"]([^'\"]+)['\"]")
    flask_route = re.compile(r"@(?:app|bp)\.route\(\s*['\"]([^'\"]+)['\"]")

    for path in files:
        rel = rel_path(path, project)
        text = read_text(path)
        for index, line in enumerate(text.splitlines(), start=1):
            if match := express_route.search(line):
                method, route = match.groups()
                entries.append(
                    EntryPoint("API", method.upper(), route, f"{rel}:{index}", "Unknown", "Express-style route")
                )
            if match := fastapi_route.search(line):
                method, route = match.groups()
                entries.append(
                    EntryPoint("API", method.upper(), route, f"{rel}:{index}", "Unknown", "FastAPI-style route")
                )
            if match := flask_route.search(line):
                route = match.group(1)
                entries.append(EntryPoint("API", "ANY", route, f"{rel}:{index}", "Unknown", "Flask-style route"))
            if "window.location" in line or "URLSearchParams" in line:
                entries.append(
                    EntryPoint("Browser", "LOAD", "query-string processing", f"{rel}:{index}", "No", "Browser input")
                )
    return entries


def language_summary(files: list[Path]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for path in files:
        key = path.suffix.lstrip(".") or path.name
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


def dependency_summary(project: Path) -> list[str]:
    candidates = [
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "requirements.txt",
        "pyproject.toml",
        "poetry.lock",
        "Pipfile",
        "Pipfile.lock",
        "go.mod",
        "Cargo.toml",
        "Cargo.lock",
    ]
    return [name for name in candidates if (project / name).exists()]


def classify_data(project: Path, files: list[Path]) -> dict[str, list[str]]:
    classes: dict[str, list[str]] = {"L4 Regulated": [], "L3 Confidential": [], "L2 Internal": [], "L1 Public": []}
    l4 = re.compile(r"\b(ephi|phi|patient|diagnosis|ssn|mrn|medical)\b", re.IGNORECASE)
    l3 = re.compile(r"\b(secret|token|api[_-]?key|password|credential|private key)\b", re.IGNORECASE)
    for path in files:
        rel = rel_path(path, project)
        text = read_text(path)
        if l4.search(text) or l4.search(rel):
            classes["L4 Regulated"].append(rel)
        elif l3.search(text) or l3.search(rel):
            classes["L3 Confidential"].append(rel)
        elif path.suffix in {".md", ".txt"}:
            classes["L1 Public"].append(rel)
        else:
            classes["L2 Internal"].append(rel)
    return classes


def add_finding(
    findings: list[Finding],
    title: str,
    pattern: str,
    rel: str,
    line_number: int,
    code: str,
    category: str,
    data_class: str,
    confidence_initial: str,
    confidence: str,
    severity: str,
    cvss: str,
    cwe: str,
    notes: str,
    remediation: str,
    verification: str,
    root_cause: str,
    patterns_applied: Iterable[str],
) -> None:
    raw_id = f"SCAN-{len(findings) + 1:03d}"
    final_id = f"F-{len(findings) + 1:03d}"
    findings.append(
        Finding(
            raw_id=raw_id,
            final_id=final_id,
            title=title,
            pattern=pattern,
            file=rel,
            line=line_number,
            code=redact_code(code),
            category=category,
            data_class=data_class,
            confidence_initial=confidence_initial,
            confidence=confidence,
            severity=severity,
            cvss=cvss,
            cwe=cwe,
            notes=notes,
            remediation=remediation,
            verification=verification,
            root_cause=root_cause,
            patterns_applied=list(patterns_applied),
        )
    )


def scan_file(project: Path, path: Path, findings: list[Finding]) -> list[str]:
    rel = rel_path(path, project)
    text = read_text(path)
    lines = text.splitlines()
    applied: set[str] = set()

    has_rate_limit = bool(re.search(r"rateLimit|express-rate-limit|slow_down|limiter", text, re.IGNORECASE))

    for index, line in enumerate(lines, start=1):
        lowered = line.lower()

        if path.suffix in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
            if re.search(r"\bSELECT\b", line, re.IGNORECASE) and ("+" in line or "${" in line):
                applied.add("sql-injection")
                add_finding(
                    findings,
                    "SQL Injection Through String-Built Query",
                    "SQL string concatenation",
                    rel,
                    index,
                    line,
                    "A05",
                    "L2",
                    "Likely",
                    "Confirmed",
                    "High",
                    "8.1 - CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    "CWE-89",
                    "SQL is built with string interpolation or concatenation; verify whether user input reaches it.",
                    "Use parameterized queries, prepared statements, or ORM query builders.",
                    "Add a regression test proving injection payloads are treated as data.",
                    "Insufficient input validation",
                    ["sql-injection"],
                )

            if "innerHTML" in line or "dangerouslySetInnerHTML" in line or "insertAdjacentHTML" in line:
                applied.add("xss")
                add_finding(
                    findings,
                    "DOM XSS Through Unsafe HTML Sink",
                    "unsafe HTML sink",
                    rel,
                    index,
                    line,
                    "A05",
                    "L1",
                    "Likely",
                    "Confirmed",
                    "Medium",
                    "6.1 - CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                    "CWE-79",
                    "Browser-controlled content may reach an HTML execution sink.",
                    "Use textContent or a vetted sanitizer with strict allowlists.",
                    "Add a browser/unit test showing HTML input is rendered as text.",
                    "Unsafe output handling",
                    ["xss", "dom-xss"],
                )

            if "res.send" in line and "<" in line and ("+" in line or "${" in line):
                applied.add("xss")
                add_finding(
                    findings,
                    "Reflected XSS In Server HTML Response",
                    "server-side reflected HTML",
                    rel,
                    index,
                    line,
                    "A05",
                    "L1",
                    "Likely",
                    "Confirmed",
                    "Medium",
                    "6.1 - CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                    "CWE-79",
                    "Server response builds HTML with concatenated values.",
                    "Escape output or render through a safe template engine.",
                    "Add a test proving script tags are escaped in the response.",
                    "Unsafe output handling",
                    ["xss"],
                )

            if re.search(r"cors\(\s*\{\s*origin\s*:\s*['\"]\*['\"]", line) or re.search(r"cors\(\s*\)", line):
                applied.add("cors")
                add_finding(
                    findings,
                    "Permissive CORS Configuration",
                    "wildcard CORS",
                    rel,
                    index,
                    line,
                    "API8",
                    "L2",
                    "Candidate",
                    "Likely",
                    "Low",
                    "4.3 - CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                    "CWE-942",
                    "CORS is permissive; impact depends on credentialed responses and sensitive endpoints.",
                    "Restrict allowed origins per environment and avoid wildcard on sensitive APIs.",
                    "Add an integration test that disallowed origins do not receive CORS approval.",
                    "Insecure default",
                    ["cors", "api-misconfiguration"],
                )

            if re.search(r"\.(post|get)\(\s*['\"][^'\"]*login", line, re.IGNORECASE) and not has_rate_limit:
                applied.add("rate-limit")
                add_finding(
                    findings,
                    "Missing Login Rate Limiting",
                    "authentication endpoint without visible limiter",
                    rel,
                    index,
                    line,
                    "API4",
                    "L2",
                    "Candidate",
                    "Likely",
                    "Medium",
                    "5.3 - CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                    "CWE-770",
                    "Login endpoint has no visible rate limiter or lockout control.",
                    "Add per-IP and per-account rate limiting plus alerting for repeated failures.",
                    "Add tests that repeated login attempts are throttled.",
                    "Missing security control",
                    ["rate-limit", "auth"],
                )

            if re.search(r"process\.env\.[A-Z0-9_]*(KEY|SECRET|TOKEN|PASSWORD)", line) and re.search(
                r"\|\|\s*['\"]", line
            ):
                applied.add("secrets")
                add_finding(
                    findings,
                    "Fallback Secret-Like Value",
                    "secret fallback",
                    rel,
                    index,
                    line,
                    "A04",
                    "L3",
                    "Candidate",
                    "Possible",
                    "Low",
                    "3.7 - CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    "CWE-798",
                    "Environment-backed secret has a literal fallback; impact depends on environment use.",
                    "Fail closed when required secrets are missing outside local fixtures.",
                    "Add startup validation that rejects missing production secrets.",
                    "Insecure default",
                    ["secrets"],
                )

            if "err.stack" in line or "error.stack" in line:
                applied.add("error-handling")
                add_finding(
                    findings,
                    "Stack Trace Exposure",
                    "verbose error response",
                    rel,
                    index,
                    line,
                    "A10",
                    "L2",
                    "Candidate",
                    "Likely",
                    "Low",
                    "3.7 - CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    "CWE-209",
                    "Stack traces can disclose internals to clients.",
                    "Return generic errors to clients and log detailed errors server-side.",
                    "Add a test that error responses do not contain stack traces.",
                    "Mishandling exceptional conditions",
                    ["error-handling"],
                )

            if re.search(r"\beval\(|new Function\(", line):
                applied.add("code-injection")
                add_finding(
                    findings,
                    "Dynamic Code Execution",
                    "eval/function constructor",
                    rel,
                    index,
                    line,
                    "A05",
                    "L2",
                    "Likely",
                    "Likely",
                    "High",
                    "8.1 - CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    "CWE-94",
                    "Dynamic code execution is present; analyst must verify attacker control.",
                    "Replace dynamic execution with explicit parsers or dispatch tables.",
                    "Add tests proving untrusted strings cannot be executed.",
                    "Unsafe code execution",
                    ["code-injection"],
                )

        if path.suffix == ".py":
            if re.search(r"f[\"'].*SELECT|\.format\(.*SELECT", line):
                applied.add("sql-injection")
                add_finding(
                    findings,
                    "SQL Injection Through Interpolated Python Query",
                    "Python interpolated SQL",
                    rel,
                    index,
                    line,
                    "A05",
                    "L2",
                    "Likely",
                    "Likely",
                    "High",
                    "8.1 - CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    "CWE-89",
                    "SQL appears to be interpolated into a query string.",
                    "Use parameterized queries or ORM query APIs.",
                    "Add a test proving SQL metacharacters are bound as data.",
                    "Insufficient input validation",
                    ["sql-injection"],
                )

            if "shell=True" in line or "os.system(" in line:
                applied.add("command-injection")
                add_finding(
                    findings,
                    "Command Execution Risk",
                    "shell execution",
                    rel,
                    index,
                    line,
                    "A05",
                    "L2",
                    "Likely",
                    "Likely",
                    "High",
                    "8.8 - CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                    "CWE-78",
                    "Shell execution is present; analyst must verify attacker-controlled arguments.",
                    "Use subprocess with argument arrays and strict allowlists.",
                    "Add tests for rejected shell metacharacters.",
                    "Unsafe code execution",
                    ["command-injection"],
                )

            if "yaml.load(" in line and "SafeLoader" not in line:
                applied.add("deserialization")
                add_finding(
                    findings,
                    "Unsafe YAML Deserialization",
                    "yaml.load without SafeLoader",
                    rel,
                    index,
                    line,
                    "A08",
                    "L2",
                    "Likely",
                    "Likely",
                    "Medium",
                    "6.5 - CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                    "CWE-502",
                    "YAML load can deserialize unsafe types without SafeLoader.",
                    "Use yaml.safe_load or yaml.load with SafeLoader.",
                    "Add a test with unsafe YAML tags and confirm rejection.",
                    "Insecure default",
                    ["deserialization"],
                )

        if path.name in {"Dockerfile", "Containerfile"}:
            if re.search(r"^FROM\s+.+:latest\b", line):
                applied.add("container-hardening")
                add_finding(
                    findings,
                    "Docker Image Uses latest Tag",
                    "mutable container base",
                    rel,
                    index,
                    line,
                    "A03",
                    "L2",
                    "Candidate",
                    "Likely",
                    "Low",
                    "3.7 - CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L",
                    "CWE-1104",
                    "Container base image is mutable and not pinned.",
                    "Pin base images by version and digest.",
                    "Add CI policy that blocks mutable base image tags.",
                    "Dependency risk",
                    ["container-hardening"],
                )

        if path.suffix in {".yml", ".yaml"} and ".github/workflows" in f"/{rel}":
            if re.search(r"uses:\s*[^@\s]+@v[0-9]+", line):
                applied.add("ci-supply-chain")
                add_finding(
                    findings,
                    "Mutable GitHub Action Tag",
                    "mutable GitHub Action tag",
                    rel,
                    index,
                    line,
                    "A03",
                    "L2",
                    "Candidate",
                    "Likely",
                    "Low",
                    "3.7 - CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L",
                    "CWE-829",
                    "Workflow uses a mutable action version tag rather than a commit SHA.",
                    "Pin third-party actions to full commit SHAs and review updates intentionally.",
                    "Add CI policy that rejects action tags matching @vN.",
                    "Dependency risk",
                    ["ci-supply-chain"],
                )

            if "pull_request_target" in line:
                applied.add("ci-supply-chain")
                add_finding(
                    findings,
                    "pull_request_target Workflow Trigger",
                    "high-risk CI trigger",
                    rel,
                    index,
                    line,
                    "A03",
                    "L2",
                    "Candidate",
                    "Likely",
                    "Medium",
                    "6.5 - CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                    "CWE-829",
                    "pull_request_target can expose privileged workflow context to untrusted changes.",
                    "Use pull_request with read-only permissions or isolate trusted workflows.",
                    "Add CI policy blocking pull_request_target unless justified.",
                    "Dependency risk",
                    ["ci-supply-chain"],
                )

    if path.name in {"Dockerfile", "Containerfile"}:
        applied.add("container-hardening")
        if not re.search(r"^USER\s+\S+", text, re.MULTILINE):
            add_finding(
                findings,
                "Container Does Not Configure Non-Root User",
                "missing non-root USER",
                rel,
                1,
                lines[0] if lines else path.name,
                "A02",
                "L2",
                "Candidate",
                "Likely",
                "Low",
                "3.7 - CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L",
                "CWE-250",
                "Container image does not declare a non-root runtime user.",
                "Create a dedicated user/group and add a USER directive.",
                "Add container policy checks for non-root execution.",
                "Insecure default",
                ["container-hardening"],
            )

    if path.name == "package.json":
        applied.add("dependency-manifest")
        if not any((project / lock_name).exists() for lock_name in ["package-lock.json", "pnpm-lock.yaml", "yarn.lock"]):
            add_finding(
                findings,
                "Missing JavaScript Lockfile",
                "dependency lockfile absent",
                rel,
                1,
                lines[0] if lines else "{",
                "A03",
                "L2",
                "Candidate",
                "Possible",
                "Low",
                "3.7 - CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L",
                "CWE-1104",
                "package.json is present without a recognized lockfile.",
                "Commit a package manager lockfile and use frozen installs in CI.",
                "Run package manager install in lockfile/frozen mode in CI.",
                "Dependency risk",
                ["dependency-manifest"],
            )

    return sorted(applied) or ["general-static-review"]


def scan_project(project: Path, manifest: list[ManifestItem]) -> tuple[list[Finding], dict[str, list[str]]]:
    findings: list[Finding] = []
    patterns_by_file: dict[str, list[str]] = {}
    for item in manifest:
        if item.scan_required != "yes":
            continue
        path = project / item.path
        if not path.exists() or not path.is_file():
            patterns_by_file[item.path] = []
            continue
        patterns_by_file[item.path] = scan_file(project, path, findings)
    return findings, patterns_by_file


def write_scope(output: Path, project: Path) -> None:
    content = f"""# SecureScan Scope And Authorization

Audit date: {dt.date.today().isoformat()}
Auditor: SecureScan deterministic static runner v{VERSION}
Target project: {project}

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
"""
    (output / "00-scope.md").write_text(content, encoding="utf-8")


def write_manifest(output: Path, manifest: list[ManifestItem]) -> None:
    lines = ["path\ttype\trisk_tier\tscan_required\treason"]
    for item in manifest:
        lines.append(f"{item.path}\t{item.type}\t{item.risk_tier}\t{item.scan_required}\t{item.reason}")
    (output / "file-manifest.tsv").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_recon(
    output: Path,
    project: Path,
    files: list[Path],
    manifest: list[ManifestItem],
    entries: list[EntryPoint],
) -> None:
    languages = language_summary(files)
    dependencies = dependency_summary(project)
    data_classes = classify_data(project, files)
    risk_counts: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for item in manifest:
        risk_counts[item.risk_tier] = risk_counts.get(item.risk_tier, 0) + 1

    entry_rows = "\n".join(
        f"| {entry.type} | {entry.method} | `{entry.path}` | `{entry.location}` | {entry.auth_required} | {entry.notes} |"
        for entry in entries
    )
    if not entry_rows:
        entry_rows = "| Not detected | N/A | N/A | N/A | N/A | Static runner found no route-like patterns |"

    data_rows = "\n".join(
        f"| {data_class} | {', '.join(f'`{loc}`' for loc in locations[:12]) or 'None detected'} | {'Truncated' if len(locations) > 12 else ''} |"
        for data_class, locations in data_classes.items()
    )

    high_risk = [item for item in manifest if item.risk_tier in {"Critical", "High"} and item.scan_required == "yes"]
    high_risk_lines = "\n".join(f"- `{item.path}` - {item.reason}" for item in high_risk) or "- None detected"
    out_of_scope = [item for item in manifest if item.scan_required != "yes"]
    out_of_scope_lines = "\n".join(f"- `{item.path}` - {item.reason}" for item in out_of_scope) or "- None"

    content = f"""# SecureScan Recon

## Architecture Summary

- Project root: `{project}`
- Files inventoried for static review: {len(files)}
- Languages/extensions: {json.dumps(languages, sort_keys=True)}

## Entry Points

| Type | Method/Event | Path/Name | File:Line | Auth Required | Notes |
|---|---|---|---|---|---|
{entry_rows}

## Data Classification

| Data Class | Locations | Notes |
|---|---|---|
{data_rows}

## Auth Architecture

The static runner identifies auth architecture heuristically from file names and route patterns. Review `auth`, `login`, `session`, `jwt`, and middleware files manually for final assurance.

## AI/LLM/Agent Inventory

AI-related files are flagged when paths or contents contain prompt, LLM, agent, MCP, embedding, vector, or memory keywords. See `file-manifest.tsv` for matching files.

## Dependency Summary

Detected manifests/lockfiles: {', '.join(f'`{name}`' for name in dependencies) or 'None detected'}

## CI/CD And Infrastructure

CI/CD, Docker, and IaC files are included in `file-manifest.tsv` when present.

## File Manifest Summary

| Risk Tier | Count | Notes |
|---|---:|---|
| Critical | {risk_counts.get('Critical', 0)} | Highest-risk regulated/sensitive surfaces |
| High | {risk_counts.get('High', 0)} | Auth/API/AI/security-sensitive files |
| Medium | {risk_counts.get('Medium', 0)} | Config, CI/CD, dependency, container files |
| Low | {risk_counts.get('Low', 0)} | Lower-risk source/docs |

## High-Risk Areas For Scanner

{high_risk_lines}

## Out Of Scope / Not Inspected

{out_of_scope_lines}
"""
    (output / "01-recon.md").write_text(content, encoding="utf-8")


def category_label(category: str) -> str:
    labels = {
        "A02": "Security Misconfiguration",
        "A03": "Software Supply Chain Failures",
        "A04": "Cryptographic Failures / Secret Handling",
        "A05": "Injection",
        "A08": "Software And Data Integrity Failures",
        "A10": "Mishandling Exceptional Conditions",
        "API4": "Unrestricted Resource Consumption",
        "API8": "Security Misconfiguration",
    }
    return labels.get(category, "Other")


def write_findings(output: Path, findings: list[Finding]) -> None:
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.category, []).append(finding)

    parts = ["# SecureScan Raw Findings\n"]
    if not findings:
        parts.append("No raw findings were identified by the deterministic static runner.\n")
    for category in sorted(grouped):
        parts.append(f"## {category} - {category_label(category)}\n")
        for finding in grouped[category]:
            parts.append(
                f"""ID: {finding.raw_id}
Pattern: {finding.pattern}
File: {finding.file}
Line: {finding.line}
Code: `{finding.code}`
Category: {finding.category}
Data_Class: {finding.data_class}
Confidence_Initial: {finding.confidence_initial}
Notes: {finding.notes}
Validation_Needed: Analyst should verify reachability, environment, and compensating controls.
"""
            )
    parts.append("\n## Coverage Log\n\nCoverage is recorded in `coverage.json`.\n")
    (output / "02-findings.md").write_text("\n".join(parts), encoding="utf-8")


def write_coverage(
    output: Path,
    project: Path,
    manifest: list[ManifestItem],
    findings: list[Finding],
    patterns_by_file: dict[str, list[str]],
) -> None:
    findings_by_file: dict[str, list[str]] = {}
    for finding in findings:
        findings_by_file.setdefault(finding.file, []).append(finding.raw_id)

    coverage = []
    skipped = []
    scanned = partial = skipped_count = 0
    for item in manifest:
        if item.scan_required == "yes":
            status = "Full"
            reason = ""
            scanned += 1
        elif item.scan_required == "partial":
            status = "Partial"
            reason = item.reason
            partial += 1
        else:
            status = "Skipped"
            reason = item.reason
            skipped_count += 1
            skipped.append({"path": item.path, "reason": item.reason})

        coverage.append(
            {
                "path": item.path,
                "risk_tier": item.risk_tier,
                "status": status,
                "reason": reason,
                "patterns_applied": patterns_by_file.get(item.path, []),
                "findings": findings_by_file.get(item.path, []),
            }
        )

    total = scanned + partial + skipped_count
    percent = round((scanned / total) * 100, 2) if total else 100

    data = {
        "schema_version": "1.0",
        "generated_at": utc_now(),
        "project_root": str(project),
        "scope": "static-local-review",
        "summary": {
            "files_total": total,
            "files_scanned": scanned,
            "files_partial": partial,
            "files_skipped": skipped_count,
            "coverage_percent": percent,
        },
        "coverage": coverage,
        "skipped": skipped,
        "tool_runs": [
            {
                "tool": "securescan-static",
                "status": "run",
                "reason": f"Deterministic static runner v{VERSION}",
            }
        ],
    }
    (output / "coverage.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def nist_ai_status(
    function: str,
    category: str,
    ai_items: list[ManifestItem],
    ai_findings: list[Finding],
) -> tuple[str, str, str, str]:
    if not ai_items:
        return (
            "Not Applicable",
            "`01-recon.md` AI/LLM/Agent Inventory; `file-manifest.tsv`",
            "No AI/LLM/RAG/agentic components were detected by the deterministic static inventory.",
            "Reassess if AI components are added or if dynamic/runtime AI services are in scope.",
        )

    if function == "Map" and category.startswith(("Map 2", "Map 4")):
        evidence = "`01-recon.md` AI/LLM/Agent Inventory; `file-manifest.tsv` AI-sensitive paths"
        return (
            "Partial",
            evidence,
            "Static inventory identified AI-sensitive code surfaces, but purpose, model limits, human oversight, and third-party context require owner confirmation.",
            "Have the system owner complete context, model/provider, oversight, and third-party risk fields.",
        )

    if function == "Measure" and category.startswith("Measure 2") and ai_findings:
        return (
            "Partial",
            "`02-findings.md`; `03-analysis.md`; OWASP LLM/Agentic categories",
            "Static security findings provide security/resilience signals only. Broader validity, reliability, safety, privacy, bias, and monitoring metrics are not proven.",
            "Add AI evaluation, red-team, privacy, safety, and monitoring evidence for the deployed context.",
        )

    if function == "Manage" and category.startswith("Manage 1") and ai_findings:
        return (
            "Partial",
            "`03-analysis.md`; `04-report.md` remediation roadmap; `nist-ai-rmf-evidence.md` residual-risk rows",
            "Risk treatment is prioritized for static findings, but formal AI go/no-go, acceptance, and residual-risk ownership are not proven.",
            "Assign owners and record risk treatment or acceptance for each AI security finding.",
        )

    return (
        "Not Assessed",
        "",
        "The deterministic static runner cannot verify this governance, operational, measurement, or lifecycle outcome from code alone.",
        "Collect owner-provided policy, test, monitoring, incident, model, provider, or risk-acceptance evidence.",
    )


def write_nist_ai_rmf_evidence(
    output: Path,
    project: Path,
    manifest: list[ManifestItem],
    findings: list[Finding],
) -> None:
    ai_items = [item for item in manifest if item.type == "ai" and item.scan_required == "yes"]
    ai_paths = ", ".join(f"`{item.path}`" for item in ai_items[:8]) or "None detected by static inventory"
    if len(ai_items) > 8:
        ai_paths += f", plus {len(ai_items) - 8} more"
    ai_findings = [
        finding
        for finding in findings
        if finding.category.startswith(("LLM", "ASI")) or any(item.path == finding.file for item in ai_items)
    ]

    status_counts = {"Compliant": 0, "Partial": 0, "Gap": 0, "Not Applicable": 0, "Not Assessed": 0}
    matrix_rows = []
    follow_up_rows = []

    for function, category, evidence_to_collect in NIST_AI_RMF_ROWS:
        status, evidence_links, gap, next_action = nist_ai_status(function, category, ai_items, ai_findings)
        status_counts[status] = status_counts.get(status, 0) + 1
        owner = "System owner"
        matrix_rows.append(
            "| "
            + " | ".join(
                [
                    function,
                    category,
                    evidence_to_collect,
                    status,
                    evidence_links,
                    gap,
                    owner,
                    next_action,
                ]
            )
            + " |"
        )
        if status in {"Partial", "Gap", "Not Assessed"}:
            follow_up_rows.append(
                f"| {status} | {function} | {category} | {gap} | {owner} | {next_action} |"
            )

    if not follow_up_rows:
        follow_up_rows.append("| None | None | No follow-up identified | None | None | None |")

    content = f"""# NIST AI RMF Evidence Matrix

Target: `{project}`
Assessment date: {dt.date.today().isoformat()}
Assessor: SecureScan deterministic static runner v{VERSION}
Source baseline: NIST AI RMF 1.0 Govern, Map, Measure, Manage

This is an evidence matrix, not a certification statement. Static code review can identify AI security surfaces and findings, but governance, measurement, monitoring, and lifecycle outcomes usually require owner-provided operational evidence.

## AI System Scope

AI-sensitive paths: {ai_paths}

AI-linked findings: {len(ai_findings)}

## Status Summary

- Compliant: {status_counts.get('Compliant', 0)}
- Partial: {status_counts.get('Partial', 0)}
- Gap: {status_counts.get('Gap', 0)}
- Not Applicable: {status_counts.get('Not Applicable', 0)}
- Not Assessed: {status_counts.get('Not Assessed', 0)}

## Govern / Map / Measure / Manage Matrix

| Function | Category | SecureScan Evidence To Collect | Status | Evidence Links | Gaps / Residual Risk | Owner | Next Action |
|---|---|---|---|---|---|---|---|
{chr(10).join(matrix_rows)}

## Residual Risk And Follow-Up

| Priority | Function | Gap | Residual Risk | Recommended Owner | Next Action |
|---|---|---|---|---|---|
{chr(10).join(follow_up_rows)}
"""
    (output / "nist-ai-rmf-evidence.md").write_text(content, encoding="utf-8")


def write_analysis(output: Path, findings: list[Finding], coverage_percent: float) -> None:
    parts = [
        "# SecureScan Analysis\n",
        "## Validation Summary\n",
        f"{len(findings)} raw findings were reviewed by the deterministic static runner. "
        "The runner provides static validation and marks runtime-dependent items as Likely or Possible.\n",
        "## Validated Findings\n",
    ]

    if not findings:
        parts.append("No validated findings were produced.\n")
    for finding in findings:
        parts.append(
            f"""### FINDING: {finding.final_id} - {finding.title}

Severity: {finding.severity}
CVSS Base: {finding.cvss}
Effective: {finding.severity}
Confidence: {finding.confidence}
Data Class: {finding.data_class}
OWASP: {finding.category}
CWE: {finding.cwe}
Location: {finding.file}:{finding.line}

Vulnerable Code:
`{finding.code}`

Proof Of Exploitability:
Static evidence: {finding.notes}

Attack Scenario:
An attacker who can influence the relevant input or build surface may trigger this weakness if no upstream control blocks it.

Compensating Controls:
Not proven by static runner. Manual analyst review should verify framework protections and deployment controls.

Root Cause:
{finding.root_cause}

Remediation:
{finding.remediation}

Verification:
{finding.verification}
"""
        )

    parts.extend(
        [
            "## False Positive Review\n",
            "No False Positive findings were closed by the deterministic runner. Claude analyst review should close protected or unreachable candidates.\n",
            "## STRIDE\n",
            "Trust boundaries identified by the static runner include user-controlled HTTP/browser inputs, server-side processing, dependency/build pipelines, and container runtime boundaries where present.\n",
            "## Attack Chain\n",
            "ATTACK CHAIN: Static Input And Build Surface Exposure\n\n"
            "Findings chained: see validated findings above.\n\n"
            "Chain-breaking fix: prioritize parameterization, output escaping, least-privilege build/runtime configuration, and rate limiting.\n",
            "## HIPAA\n",
            "Not Assessed unless L4/ePHI indicators were present in recon. Proposed HIPAA items must be reported only as proposed-readiness.\n",
            "## NIST AI RMF Evidence\n",
            "See `nist-ai-rmf-evidence.md` for the dedicated Govern, Map, Measure, and Manage evidence matrix. Static review can seed AI security evidence, but governance and lifecycle rows require owner-provided operational evidence.\n",
            "## Coverage Risk\n",
            f"Static file coverage is {coverage_percent} percent based on `coverage.json`.\n",
        ]
    )
    (output / "03-analysis.md").write_text("\n".join(parts), encoding="utf-8")


def posture_score(findings: list[Finding]) -> int:
    if not findings:
        return 9
    weights = {"Critical": 5, "High": 3, "Medium": 2, "Low": 1, "Informational": 0}
    score = sum(weights.get(finding.severity, 1) for finding in findings)
    return max(1, 10 - score)


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def write_report(output: Path, project: Path, findings: list[Finding], coverage_percent: float) -> None:
    counts = severity_counts(findings)
    top_findings = sorted(
        findings,
        key=lambda item: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}.get(
            item.severity, 5
        ),
    )[:5]
    top_lines = "\n".join(
        f"{index}. {finding.title} in `{finding.file}:{finding.line}`"
        for index, finding in enumerate(top_findings, start=1)
    ) or "No validated findings."

    finding_sections = []
    for finding in top_findings if len(findings) > 5 else findings:
        finding_sections.append(
            f"""### {finding.final_id} - {finding.title}

Severity: {finding.severity}
Confidence: {finding.confidence}
Location: `{finding.file}:{finding.line}`
Evidence: `{finding.code}`
Remediation: {finding.remediation}
Verification: {finding.verification}
"""
        )

    if not finding_sections:
        finding_sections.append("No validated findings.\n")

    content = f"""# SecureScan Final Report

Target: `{project}`
Date: {dt.date.today().isoformat()}
Methodology: SecureScan deterministic static runner v{VERSION}

## Executive Summary

Posture score: {posture_score(findings)}/10.

Finding counts:

- Critical: {counts.get('Critical', 0)}
- High: {counts.get('High', 0)}
- Medium: {counts.get('Medium', 0)}
- Low: {counts.get('Low', 0)}
- Informational: {counts.get('Informational', 0)}

Top risks:

{top_lines}

## Scope

Static local review of files discovered under the target project. Runtime exploit testing, external network testing, dependency installation, and production access were out of scope.

## Coverage

Static scanner coverage: {coverage_percent} percent coverage according to `coverage.json`.

## Validated Findings

{''.join(finding_sections)}

## Attack Chains

Potential chains should be reviewed by a human analyst. The static runner highlights likely chain surfaces across user input, output handling, authentication, CI/CD, and container boundaries.

	## Compliance Matrices

	HIPAA: Not Assessed unless ePHI indicators are present. Proposed-rule items must be labeled proposed-readiness.

	OWASP coverage is mapped per finding using the category field in `02-findings.md` and `03-analysis.md`.

NIST AI RMF: see `nist-ai-rmf-evidence.md` for the dedicated Govern, Map, Measure, and Manage evidence matrix.

## Remediation Roadmap

0-48hr: Fix High and confirmed Medium findings.

1-2wk: Fix remaining Medium findings and add regression tests.

1-3mo: Add CI policies for dependency, secrets, container, and IaC checks.

## Testing Recommendations

Run SAST, dependency scanning, secret scanning, IaC scanning, and targeted dynamic tests with explicit approval.

## Risk Acceptance

No risks are accepted by this static runner. Deferred findings require an owner, justification, compensating controls, residual risk, and reassessment date.
"""
    (output / "04-report.md").write_text(content, encoding="utf-8")


def run(project: Path, output: Path, max_file_bytes: int) -> list[Finding]:
    project = project.resolve()
    output = output.resolve()
    if not project.exists() or not project.is_dir():
        raise SystemExit(f"Project directory does not exist: {project}")

    output.mkdir(parents=True, exist_ok=True)
    (output / "tool-runs").mkdir(parents=True, exist_ok=True)

    files, skipped = list_files(project, max_file_bytes)
    manifest = build_manifest(project, files, skipped)
    entries = detect_entry_points(project, files)
    findings, patterns_by_file = scan_project(project, manifest)

    total = len([item for item in manifest if item.scan_required == "yes"]) + len(
        [item for item in manifest if item.scan_required != "yes"]
    )
    scanned = len([item for item in manifest if item.scan_required == "yes"])
    coverage_percent = round((scanned / total) * 100, 2) if total else 100

    write_scope(output, project)
    write_manifest(output, manifest)
    write_recon(output, project, files, manifest, entries)
    write_findings(output, findings)
    write_coverage(output, project, manifest, findings, patterns_by_file)
    write_nist_ai_rmf_evidence(output, project, manifest, findings)
    write_analysis(output, findings, coverage_percent)
    write_report(output, project, findings, coverage_percent)

    return findings


def main() -> int:
    args = parse_args()
    project = Path(args.project)
    output = Path(args.output) if args.output else project / ".securescan"
    findings = run(project, output, args.max_file_bytes)
    print(f"SecureScan static audit complete: {output}")
    print(f"Findings: {len(findings)}")
    if args.fail_on_findings and findings:
        return 10
    return 0


if __name__ == "__main__":
    sys.exit(main())
