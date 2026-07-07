# SecureScan Recon

## Architecture Summary

- Project root: `/Users/garethhood/Desktop/SecureScan-Package/examples/vulnerable-demo`
- Files inventoried for static review: 7
- Languages/extensions: {"Dockerfile": 1, "js": 2, "json": 1, "md": 2, "yml": 1}

## Entry Points

| Type | Method/Event | Path/Name | File:Line | Auth Required | Notes |
|---|---|---|---|---|---|
| Browser | LOAD | `query-string processing` | `src/client.js:1` | No | Browser input |
| API | GET | `/users` | `src/server.js:13` | Unknown | Express-style route |
| API | POST | `/login` | `src/server.js:27` | Unknown | Express-style route |
| API | GET | `/hello` | `src/server.js:38` | Unknown | Express-style route |

## Data Classification

| Data Class | Locations | Notes |
|---|---|---|
| L4 Regulated | None detected |  |
| L3 Confidential | `EXPECTED-FINDINGS.md`, `src/server.js` |  |
| L2 Internal | `.github/workflows/ci.yml`, `Dockerfile`, `package.json`, `src/client.js` |  |
| L1 Public | `README.md` |  |

## Auth Architecture

The static runner identifies auth architecture heuristically from file names and route patterns. Review `auth`, `login`, `session`, `jwt`, and middleware files manually for final assurance.

## AI/LLM/Agent Inventory

AI-related files are flagged when paths or contents contain prompt, LLM, agent, MCP, embedding, vector, or memory keywords. See `file-manifest.tsv` for matching files.

## Dependency Summary

Detected manifests/lockfiles: `package.json`

## CI/CD And Infrastructure

CI/CD, Docker, and IaC files are included in `file-manifest.tsv` when present.

## File Manifest Summary

| Risk Tier | Count | Notes |
|---|---:|---|
| Critical | 0 | Highest-risk regulated/sensitive surfaces |
| High | 1 | Auth/API/AI/security-sensitive files |
| Medium | 3 | Config, CI/CD, dependency, container files |
| Low | 3 | Lower-risk source/docs |

## High-Risk Areas For Scanner

- `src/server.js` - api file included in static review

## Out Of Scope / Not Inspected

- None
