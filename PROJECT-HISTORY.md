# SecureScan v2.4 - Project History & Decision Log

> Full development history of the SecureScan multi-agent security audit system for Claude Code.

---

## Project Timeline

### Phase 10: CLI And Export Usability (v2.4)

**Changes completed:**

1. Added one-command CLI entry points: `bin/securescan` and `scripts/securescan.sh`.
2. Added `doctor`, `demo`, `scan`, `validate`, `export`, and `install` commands.
3. Added first-run static scope metadata through `--wizard`, `--yes`, `--authorized-by`, and `--scope-note`.
4. Added scan summary output with finding counts, coverage, report path, and top remediation items.
5. Added JSON, SARIF, HTML, and Markdown exports under `.securescan/exports/`.
6. Added `scripts/build-overview-docx.py` so the Word overview can be rebuilt from the canonical Markdown overview.
7. Updated CI and package validation so CLI health and export generation are release gates.

**Design decision:** Keep `scripts/securescan-static.py` as the deterministic artifact generator and layer usability on top. This avoids a second scanning path while making the package easier for non-specialists to run.

### Phase 9: Operational Static Scanner (v2.3)

**Changes completed:**

1. Added dependency-free deterministic scanner: `scripts/securescan-static.py`.
2. Added shell wrapper: `scripts/securescan-static.sh`.
3. Scanner writes the full `.securescan/` artifact contract: scope, manifest, recon, findings, coverage, analysis, report.
4. CI and package validation now run the scanner against `examples/vulnerable-demo` and validate the generated output.

**Design decision:** The scanner is static-first and conservative. Claude agents remain the higher-reasoning workflow for manual validation, but the package is now operational without requiring an agent invocation.

### Phase 8: Regression And Release Hardening (v2.2)

**Changes completed:**

1. Added canonical `VERSION`.
2. Added GitHub Actions validation workflow.
3. Added golden output artifacts for `examples/vulnerable-demo`.
4. Added demo regression validator for expected vulnerability themes.
5. Strengthened `coverage.json` schema validation.

**Design decision:** Keep regression validation deterministic and dependency-free. The validator checks generated artifacts after an agent or static scanner run.

### Phase 7: Enterprise Hardening (v2.1)

**Changes completed:**

1. Added a safe installer with project-local/global modes, dry-run support, overwrite protection, and package validation.
2. Added package validation and generated-artifact validation scripts.
3. Added `.securescan/00-scope.md`, `file-manifest.tsv`, and `coverage.json` as required workflow contracts.
4. Added static-by-default authorization guardrails for active testing, external network testing, dependency installation, and production access.
5. Added official source registry with `last_verified` dates.
6. Split HIPAA current-rule checks from 2025 NPRM proposed-readiness checks.
7. Added report QA checklist and regression fixture under `examples/vulnerable-demo/`.

**Design decision:** Keep SecureScan as an installable Claude Code package rather than a standalone scanner. External tools are optional supporting evidence only and must be installed/approved in the target environment.

### Phase 1: Initial Research & Monolith Prompt

**Research conducted:**

1. **OWASP Top 10:2025** — 2025 edition changes: Broken Access Control #1, Security Misconfiguration surged to #2, Software Supply Chain Failures is NEW, SSRF consolidated into Access Control, Mishandling Exceptional Conditions is NEW (#10). Based on 175K+ CVE records and 589 CWEs.

2. **AI Code Security** — 45% of AI-generated code contains OWASP Top 10 vulnerabilities. XSS has 86% failure rate. CVSS 7.0+ vulnerabilities appear 2.5x more often in AI code. 40% increase in secrets exposure.

3. **HIPAA Security Rule 2025 NPRM** — Proposed stronger requirements around vulnerability scanning, penetration testing, restoration timelines, MFA, encryption, and network segmentation. SecureScan v2.3 labels these as proposed-readiness unless HHS publishes a final rule.

**Output:** 750-line monolith system prompt.

### Phase 2: AI Application Security Layer

4. **OWASP LLM Top 10:2025** — Prompt Injection #1, Sensitive Info Disclosure, Supply Chain, Data/Model Poisoning, Insecure Output Handling, Excessive Agency, System Prompt Leakage (NEW), Vector/Embedding Weaknesses (NEW), Misinformation, Unbounded Consumption.

5. **OWASP Agentic Top 10:2026** — Agent Goal Hijacking, Tool Misuse, Identity/Privilege Abuse, Agentic Supply Chain, Unexpected Code Execution, Memory/Context Poisoning, Insecure Inter-Agent Comms, Cascading Failures, Human-Agent Trust Exploitation, Rogue Agents.

### Phase 3: Expanded Coverage

6. **OWASP API Security Top 10:2023** — BOLA #1, Broken Auth, Mass Assignment, Resource Consumption, Function-Level Auth, Sensitive Business Flows, SSRF, Misconfiguration, Shadow APIs, Unsafe API Consumption.

7. **CI/CD Pipeline Security** — Secrets in configs, mutable GitHub Action tags, pipeline poisoning, supply chain via CI plugins.

8. **STRIDE Threat Modeling** — Applied at trust boundaries and AI agent perimeters.

### Phase 4: Production-Grade Upgrade

9. **Professional Audit Methodology (PTES)** — Pre-engagement scoping, data classification (L1-L4), contextual severity, confidence ratings, compensating controls, false positive prevention, coverage tracking.

**10 gaps identified and fixed:** No pre-engagement protocol, no data classification, no contextual risk scoring, no PoC requirement, no confidence ratings, no compensating controls assessment, no coverage documentation, no false positive prevention, no QA process, no risk acceptance framework.

### Phase 5: Managed Agents Feasibility

10. **Claude Managed Agents research** — Found agents one-shot complex tasks, instruction drift on 50+ sections, context rot with large codebases. Decision: restructure from monolith to multi-agent pipeline.

### Phase 6: Claude Code Pivot

11. **Claude Code subagents** — Markdown files in .claude/agents/ with YAML frontmatter. Skills in .claude/skills/. Auto-discovered from filesystem. No API needed.

**Final architecture:** 5 agents + 5 skills, installed with two cp commands.

---

## Architecture

### Agents

| Agent | Model | Purpose |
|---|---|---|
| securescan (orchestrator) | Opus | Runs all 4 phases in one invocation |
| securescan-recon | Sonnet | Phase 1: Maps codebase, classifies data |
| securescan-scanner | Sonnet | Phase 2: Scans every file for patterns |
| securescan-analyst | Opus | Phase 3: Validates, rates severity, models threats |
| securescan-reporter | Opus | Phase 4: Assembles audit-ready report |

### Skills

| Skill | Content |
|---|---|
| owasp-web-api | Web Top 10:2025 + API Top 10:2023 + CWE reference |
| owasp-ai-agentic | LLM Top 10:2025 + Agentic Top 10:2026 + AI patterns |
| scan-patterns | All vulnerability patterns for JS/TS, Python, Infra, CI/CD |
| hipaa-compliance | 18-row HIPAA gap matrix + ePHI checks |
| security-report | Finding template, CVSS methodology, report templates |

### Frameworks Covered

OWASP Web 2025, OWASP API 2023, OWASP LLM 2025, OWASP Agentic 2026, HIPAA Security Rule, STRIDE, CWE, CVSS v3.1, PTES, NIST CSF 2.0, SOC 2, NIST AI RMF, HITRUST.

### Key Design Decisions

1. Multi-agent over monolith — prevents instruction drift and context rot
2. Skills over system prompt — reference material loads on-demand
3. Artifacts as handoffs — each phase writes a file the next phase reads
4. Sonnet for volume, Opus for reasoning
5. Confidence ratings (Confirmed/Likely/Possible) over binary findings
6. Contextual severity over raw CVSS
7. False positives documented to prove audit rigor
