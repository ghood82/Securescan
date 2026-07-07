---
name: owasp-ai-agentic
description: >
  Reference tables for OWASP Top 10 for LLM Applications 2025 and OWASP Top 10 for
  Agentic Applications 2026. Load this skill when the codebase contains LLM calls,
  RAG, vector databases, AI agents, MCP servers, tool-calling, memory, or autonomous workflows.
version: 2.3.0
last_verified: 2026-05-06
source_urls:
  - https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/
  - https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
---

# OWASP AI And Agentic Security Frameworks

Source status: verified against official OWASP GenAI Security Project pages on 2026-05-06. Re-check `SOURCES.md` before formal external reports.

## OWASP Top 10 For LLM Applications 2025

| ID | Category | What To Hunt |
|---|---|---|
| LLM01 | Prompt Injection | Direct, indirect, multimodal, or RAG-borne instructions that override system intent |
| LLM02 | Sensitive Information Disclosure | Secrets, PII/PHI, system prompts, internal URLs, or regulated data exposed in prompts/outputs/logs |
| LLM03 | Supply Chain | Unverified models, compromised plugins, vulnerable LLM libraries, poisoned datasets |
| LLM04 | Data And Model Poisoning | Untrusted training/fine-tuning data, poisoned embeddings, tampered retrieval corpora |
| LLM05 | Insecure Output Handling | LLM output passed to HTML, SQL, shell, code execution, API calls, or auth decisions without validation |
| LLM06 | Excessive Agency | Too many tools, too-broad permissions, irreversible actions without human approval |
| LLM07 | System Prompt Leakage | System prompts contain secrets or are extractable through adversarial prompting |
| LLM08 | Vector And Embedding Weaknesses | Missing tenant filters, unauthorized vector access, stale embeddings, poisoning or inversion risk |
| LLM09 | Misinformation | High-stakes outputs presented as fact without confidence, citations, review, or guardrails |
| LLM10 | Unbounded Consumption | Missing token/cost budgets, rate limits, recursion bounds, timeouts, or circuit breakers |

## OWASP Top 10 For Agentic Applications 2026

| ID | Category | What To Hunt |
|---|---|---|
| ASI01 | Agent Goal Hijacking | External content changes the agent objective or task boundaries |
| ASI02 | Tool Misuse | Tool parameters unvalidated; tools can be used destructively or out of intent |
| ASI03 | Identity And Privilege Abuse | Shared/broad credentials, no per-agent identity, no rotation or least privilege |
| ASI04 | Agentic Supply Chain | Untrusted MCP servers, tool registries, plugins, or runtime extensions |
| ASI05 | Unexpected Code Execution | Agent-generated code runs unsandboxed or with broad filesystem/network access |
| ASI06 | Memory And Context Poisoning | Untrusted content persists into memory/history and changes future behavior |
| ASI07 | Insecure Inter-Agent Communication | Spoofing, replay, missing authentication, or missing integrity on agent messages |
| ASI08 | Cascading Failures | No timeouts, isolation, circuit breakers, rollback, or blast-radius limits across agent chains |
| ASI09 | Human-Agent Trust Exploitation | Agent persuades or misleads humans into unsafe approvals |
| ASI10 | Rogue Agents | Agents can hide actions, modify instructions, persist unexpectedly, or evade oversight |

## AI-Specific Review Checklist

### Prompt Construction

- User input is delimited from system/developer instructions.
- RAG and web/document content cannot override system goals.
- Prompts do not contain secrets, credentials, or unnecessary internal implementation details.
- Prompt templates are covered by secret scanning.

### LLM API Integration

- LLM endpoints are authenticated and authorized.
- Provider keys never ship to client-side code.
- Requests have token caps, cost caps, timeouts, retries, and circuit breakers.
- Responses are treated as untrusted input.
- Logs redact prompts/outputs when they may contain sensitive data.

### RAG And Embeddings

- Retrieval enforces tenant/user authorization at query time.
- Vector collections are tenant-isolated or tenant-filtered with tests.
- User-uploaded content is sanitized/annotated as untrusted before retrieval.
- Embeddings can be invalidated when source permissions change.

### Agent And Tool Security

- Tools have schemas and parameter validation.
- Destructive or irreversible actions require human approval.
- Agents have least-privilege identities and scoped credentials.
- Tool results are sanitized before re-entering context.
- Tool calls and approvals are audit logged.
- Agents cannot modify their own prompts, tools, permissions, or memory without approval.

### Output Handling

- LLM output is not rendered as raw HTML.
- LLM output is not executed as code, shell, SQL, or privileged API input without validation.
- AI-generated clinical, legal, compliance, or financial decisions require human review.
- AI-generated content containing regulated data is not sent to analytics/logging without an approved data path.

## Analyst Guidance

- Elevate severity when an AI finding combines untrusted input, tool access, sensitive data, or autonomous action.
- Distinguish chatbot-only risk from agentic action risk.
- Look for indirect prompt injection through documents, web pages, emails, tickets, pull requests, memories, and tool outputs.
- Validate whether safeguards are enforced in code, not only described in prompts.
