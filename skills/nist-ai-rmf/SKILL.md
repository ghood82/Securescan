---
name: nist-ai-rmf
description: >
  NIST AI Risk Management Framework evidence matrix for Govern, Map, Measure,
  and Manage. Load this skill when an audit includes AI/LLM/RAG/agentic systems
  or when the report needs NIST AI RMF alignment beyond a summary statement.
version: 2.4.0
last_verified: 2026-05-15
source_urls:
  - https://www.nist.gov/itl/ai-risk-management-framework
  - https://airc.nist.gov/airmf-resources/airmf/5-sec-core/
  - https://www.nist.gov/itl/ai-risk-management-framework/nist-ai-rmf-playbook
---

# NIST AI RMF Evidence Matrix

Source status: verified against official NIST AI RMF and AIRC pages on 2026-05-15. Re-check `SOURCES.md` before formal external reports.

Use this skill to produce `.securescan/nist-ai-rmf-evidence.md`. The matrix is an evidence artifact, not a certification statement. Do not mark an outcome Compliant unless the audit found concrete policy, code, operational, test, or monitoring evidence.

## Status Values

- Compliant: Evidence shows the outcome is implemented and operating.
- Partial: Some evidence exists, but scope, enforcement, monitoring, or ownership is incomplete.
- Gap: The audit found missing or materially insufficient evidence.
- Not Applicable: The outcome is outside the authorized scope or does not apply to the AI system.
- Not Assessed: The audit did not have enough access, artifacts, or approval to assess the outcome.

## Required Columns

| Function | Category | SecureScan Evidence To Collect | Status | Evidence Links | Gaps / Residual Risk | Owner | Next Action |
|---|---|---|---|---|---|---|---|

Evidence links must point to files, lines, generated artifacts, policy documents, test runs, monitoring dashboards, incident records, model cards, data lineage records, or risk acceptances. If the evidence is outside the repository, record the evidence name and access path without exposing secrets.

## Govern

| Category | What SecureScan Should Verify |
|---|---|
| Govern 1: AI risk policies, processes, procedures, and practices are in place | AI use policy, risk tolerance, model approval process, AI system inventory, review cadence, decommissioning process |
| Govern 2: Accountability structures are in place | Named owners, reviewer roles, approval authority, training expectations, executive risk accountability |
| Govern 3: Workforce and human-AI role definitions are prioritized | Human oversight roles, escalation paths, accessibility and inclusion review where relevant |
| Govern 4: Organizational culture considers and communicates AI risk | AI risk documentation, incident sharing, testing expectations, safety-first development practices |
| Govern 5: Engagement with relevant AI actors is in place | User, stakeholder, affected-community, customer, operator, or domain-expert feedback channels |
| Govern 6: Third-party software, data, and supply chain AI risks are addressed | Model/provider due diligence, data provenance, license/IP review, third-party incident contingencies |

## Map

| Category | What SecureScan Should Verify |
|---|---|
| Map 1: Context is established and understood | Intended purpose, users, deployment setting, assumptions, laws, risk tolerance, AI system requirements |
| Map 2: AI system categorization is performed | Model/system type, task type, knowledge limits, human oversight, TEVV considerations |
| Map 3: Capabilities, usage, goals, benefits, and costs are understood | Target scope, expected benefits, error costs, operator proficiency, oversight process |
| Map 4: Risks and benefits are mapped for all components | AI component inventory, third-party components, internal controls, legal/IP/security risks |
| Map 5: Impacts are characterized | Likelihood and magnitude of impacts, feedback loops, impacted users or communities |

## Measure

| Category | What SecureScan Should Verify |
|---|---|
| Measure 1: Methods and metrics are identified and applied | Selected AI risk metrics, unmeasured risks, control effectiveness review, independent assessment |
| Measure 2: AI systems are evaluated for trustworthy characteristics | Test sets, evaluation methods, safety, validity, reliability, security, resilience, privacy, explainability, bias, transparency |
| Measure 3: Mechanisms track AI risks over time | Production monitoring, drift/error tracking, incident feedback, appeal or escalation signals |
| Measure 4: Feedback about measurement efficacy is gathered | Domain-expert feedback, user feedback, affected-party input, field data, metric improvement review |

## Manage

| Category | What SecureScan Should Verify |
|---|---|
| Manage 1: AI risks are prioritized, responded to, and managed | Go/no-go decision, risk prioritization, treatment plan, residual risk documentation |
| Manage 2: Strategies maximize benefits and minimize negative impacts | Resource plan, non-AI alternatives, recovery from unknown risks, disengage/deactivate procedure |
| Manage 3: Third-party AI risks and benefits are managed | Provider/model monitoring, pretrained model maintenance, third-party control tracking |
| Manage 4: Risk treatment, response, recovery, and communications are documented and monitored | Post-deployment monitoring, incident response, change management, appeal/override, continual improvement |

## Analyst Guidance

- Start from `.securescan/01-recon.md` AI/LLM/Agent Inventory and file-manifest AI-sensitive files.
- Cross-reference OWASP LLM and Agentic findings into the Map, Measure, and Manage rows they affect.
- Mark governance rows Partial or Gap if policy/ownership evidence is missing, even when code safeguards exist.
- Mark technical rows Partial or Gap if implementation exists without tests, monitoring, approval gates, or operational evidence.
- Record residual risk and next action for every Partial or Gap row.
- Include a short summary in `03-analysis.md` and a matrix reference in `04-report.md`.
