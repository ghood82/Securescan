# Expected Demo Findings

The vulnerable demo is not intended to produce exact IDs because IDs depend on scan order. It should produce findings equivalent to:

| Theme | Evidence |
|---|---|
| SQL injection | `src/server.js` builds SQL with `req.query.email` |
| XSS | `src/server.js` sends unsanitized `name` into HTML; `src/client.js` assigns query input to `innerHTML` |
| CORS misconfiguration | `src/server.js` allows `origin: "*"` |
| Missing rate limiting | `POST /login` has no rate limiter |
| Weak secret fallback | `src/server.js` defines a demo-only fallback API key |
| Mutable CI action | `.github/workflows/ci.yml` uses `actions/checkout@v4` instead of a pinned SHA |
| Container hardening | `Dockerfile` uses `node:latest` and does not set a non-root `USER` |

The analyst phase should close or downgrade any finding that lacks an actual reachable data flow.
