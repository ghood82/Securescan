# SecureScan Raw Findings

## A02 - Security Misconfiguration

ID: SCAN-010
Pattern: missing non-root USER
File: Dockerfile
Line: 1
Code: `FROM node:latest`
Category: A02
Data_Class: L2
Confidence_Initial: Candidate
Notes: Container image does not declare a non-root runtime user.
Validation_Needed: Analyst should verify reachability, environment, and compensating controls.

## A03 - Software Supply Chain Failures

ID: SCAN-007
Pattern: mutable GitHub Action tag
File: .github/workflows/ci.yml
Line: 11
Code: `      - uses: actions/checkout@v4`
Category: A03
Data_Class: L2
Confidence_Initial: Candidate
Notes: Workflow uses a mutable action version tag rather than a commit SHA.
Validation_Needed: Analyst should verify reachability, environment, and compensating controls.

ID: SCAN-008
Pattern: mutable GitHub Action tag
File: .github/workflows/ci.yml
Line: 12
Code: `      - uses: actions/setup-node@v4`
Category: A03
Data_Class: L2
Confidence_Initial: Candidate
Notes: Workflow uses a mutable action version tag rather than a commit SHA.
Validation_Needed: Analyst should verify reachability, environment, and compensating controls.

ID: SCAN-009
Pattern: mutable container base
File: Dockerfile
Line: 1
Code: `FROM node:latest`
Category: A03
Data_Class: L2
Confidence_Initial: Candidate
Notes: Container base image is mutable and not pinned.
Validation_Needed: Analyst should verify reachability, environment, and compensating controls.

ID: SCAN-011
Pattern: dependency lockfile absent
File: package.json
Line: 1
Code: `{`
Category: A03
Data_Class: L2
Confidence_Initial: Candidate
Notes: package.json is present without a recognized lockfile.
Validation_Needed: Analyst should verify reachability, environment, and compensating controls.

## A04 - Cryptographic Failures / Secret Handling

ID: SCAN-001
Pattern: secret fallback
File: src/server.js
Line: 8
Code: `const demoFallbackApiKey = process.env.DEMO_API_KEY || "DEMO_ONLY_NOT_A_SECRET";`
Category: A04
Data_Class: L3
Confidence_Initial: Candidate
Notes: Environment-backed secret has a literal fallback; impact depends on environment use.
Validation_Needed: Analyst should verify reachability, environment, and compensating controls.

## A05 - Injection

ID: SCAN-003
Pattern: SQL string concatenation
File: src/server.js
Line: 15
Code: `  const sql = "SELECT * FROM users WHERE email = '" + email + "'";`
Category: A05
Data_Class: L2
Confidence_Initial: Likely
Notes: SQL is built with string interpolation or concatenation; verify whether user input reaches it.
Validation_Needed: Analyst should verify reachability, environment, and compensating controls.

ID: SCAN-006
Pattern: server-side reflected HTML
File: src/server.js
Line: 40
Code: `  res.send("<h1>Hello " + name + "</h1>");`
Category: A05
Data_Class: L1
Confidence_Initial: Likely
Notes: Server response builds HTML with concatenated values.
Validation_Needed: Analyst should verify reachability, environment, and compensating controls.

ID: SCAN-012
Pattern: unsafe HTML sink
File: src/client.js
Line: 4
Code: `document.getElementById("message").innerHTML = message;`
Category: A05
Data_Class: L1
Confidence_Initial: Likely
Notes: Browser-controlled content may reach an HTML execution sink.
Validation_Needed: Analyst should verify reachability, environment, and compensating controls.

## A10 - Mishandling Exceptional Conditions

ID: SCAN-004
Pattern: verbose error response
File: src/server.js
Line: 19
Code: `      res.status(500).send(err.stack);`
Category: A10
Data_Class: L2
Confidence_Initial: Candidate
Notes: Stack traces can disclose internals to clients.
Validation_Needed: Analyst should verify reachability, environment, and compensating controls.

## API4 - Unrestricted Resource Consumption

ID: SCAN-005
Pattern: authentication endpoint without visible limiter
File: src/server.js
Line: 27
Code: `app.post("/login", (req, res) => {`
Category: API4
Data_Class: L2
Confidence_Initial: Candidate
Notes: Login endpoint has no visible rate limiter or lockout control.
Validation_Needed: Analyst should verify reachability, environment, and compensating controls.

## API8 - Security Misconfiguration

ID: SCAN-002
Pattern: wildcard CORS
File: src/server.js
Line: 11
Code: `app.use(cors({ origin: "*" }));`
Category: API8
Data_Class: L2
Confidence_Initial: Candidate
Notes: CORS is permissive; impact depends on credentialed responses and sensitive endpoints.
Validation_Needed: Analyst should verify reachability, environment, and compensating controls.


## Coverage Log

Coverage is recorded in `coverage.json`.
