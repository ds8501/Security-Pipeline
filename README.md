# Security Pipeline

This repository contains a Java/Spring Boot backend for the automated security pipeline prototype, along with a static front-end demo. It includes two GitHub Actions CI/CD gates that run automatically on PR.

## Components

- `scanner-service/`: Spring Boot application with JPA and H2 persistence
- `demo-app/`: lightweight browser UI for the trigger panel and dashboard
- `.github/workflows/`: CI/CD gates that run on every PR

## Running locally

Run the backend from the project root:

1. `cd scanner-service`
2. `/Users/divya.singh/.local/bin/mvn spring-boot:run`
3. Open the UI and API at `http://localhost:8080` (the Spring Boot app now serves the demo UI and API on the same port)

## Supported API

- `GET /api/health`
- `GET /api/scans`
- `POST /api/scans`
- `GET /api/scans/{id}`

The service stores scan metadata and findings in an in-memory H2 database and returns final verdicts for clean, vulnerable, and hidden-instruction scenarios.

## Demo behavior

- Repo URLs or branches containing `vulnerable`, `secret`, `unsafe`, or `leak` trigger a blocked verdict with a confirmed finding.
- Repo URLs or branches containing `hidden`, `instruction`, or `prompt` trigger the tampering guard and still block the merge.
- Any other repo URL completes with a passing verdict.

## CI/CD Pipelines

### Gate 1: Tests & Scanning (on PR and push to main)

**File:** `.github/workflows/security-gate-1.yml`

Runs on every PR and push to main:
- Maven tests (JUnit) **+ JaCoCo coverage**, with **diff-cover** reporting coverage on changed lines
- **Semgrep** SAST (security-audit rules) → SARIF uploaded to GitHub code scanning; build fails on error-level findings
- **Gitleaks** secret detection
- **osv-scanner** — vulnerable dependencies (reusable workflow, uploads SARIF)
- **Trivy** — filesystem vuln + IaC/container misconfig + secret scan → SARIF
- **Syft** — CycloneDX SBOM artifact
- **actionlint + zizmor** — GitHub Actions workflow linting and pipeline-hardening audit → SARIF

This is the "basic checks" gate that runs fast (< 5 minutes target). All findings are published to
the repo's **Security → Code scanning** tab via SARIF.

These same Gate-1 tools also run **inside the scanner-service** (see below), so a single scan through
the API/UI executes Gate 1 (tools) followed by Gate 2 (AI layers).

### Gate 2: AI-Powered Review (on PR to main)

**File:** `.github/workflows/security-gate-2.yml`

Runs on PR to main:
- **`claude-code-security-review`** — Anthropic's official reviewer action on the PR diff (needs `ANTHROPIC_API_KEY`; skipped if absent)
- Builds and boots `scanner-service`, then drives the real API against the PR diff
- Runs the full L1–L6 layered review and verifies findings with Semgrep
- **OPA policy gate** — evaluates the verdict against `verdict.rego` and fails the job on a block decision
- **OWASP ZAP baseline DAST** against the running service (informational; report uploaded as an artifact)
- Posts findings (grouped by layer) as PR comments
- Sets verdict (PASS or BLOCKED)
- Blocks merge if critical issues found

Requires an `LLM_API_KEY` repository secret (optionally `LLM_BASE_URL` and `LLM_MODEL`).
When the key is absent — e.g. on fork PRs — the gate posts a neutral "skipped" comment
instead of failing.

This is the "hacker layer" gate that uses AI to detect issues a scanner would miss.

#### Gate-2 review layers

Gate 2 runs a defense-in-depth stack of focused, OWASP-aligned review passes. Each layer
below `L1` is an AI pass scoped to a single risk category, and its findings are then verified
with Semgrep before they can affect the verdict:

- **L1 · Integrity** — prompt-injection / instruction-tampering guard (`IntegrityService`); gates the whole run
- **L2 · Access control & auth** — broken access control, IDOR, authz gaps (OWASP A01)
- **L3 · Data protection** — secrets, PII, sensitive logging, crypto failures (OWASP A02)
- **L4 · Injection & unsafe input** — SQLi, command injection, XSS, path traversal, deserialization (OWASP A03)
- **L5 · Dependencies & supply chain** — vulnerable/outdated components, unsafe install scripts (OWASP A06)
- **L6 · Insecure design & logic** — fail-open handling, race conditions, business-logic flaws (OWASP A04)

Layers L2–L6 implement the `ReviewLayer` interface (`service/layer/`) and are run in order by
`ScanService`, which reports progress one layer at a time in the live status view.

#### Combined scan pipeline (Gate 1 + Gate 2 in one run)

A single scan through `POST /api/scans` now runs **both gates** in sequence against the checked-out repo:

1. **Gate 1 tools** (`service/gate1/`) — Semgrep, Gitleaks, osv-scanner, Trivy, Syft, actionlint, zizmor,
   each implementing the `Gate1Tool` interface and shelling out via `ProcessBuilder`. Their findings are
   deterministic, so they are recorded as `CONFIRMED` and can block the verdict directly. A tool that is
   not installed on the host reports `UNAVAILABLE` and is skipped (the scan does not fail).
2. **Gate 2 supporting tools** — **ripgrep** (`RipgrepScanner`) sweeps for security hotspots, and
   **tree-sitter** (`TreeSitterService`) parses the changed files for a structural summary. Both are
   deterministic, LLM-independent, and degrade to `UNAVAILABLE` when their binary is missing.
3. **Gate 2 layers** — L1 integrity, then the L2–L6 AI review, then proof of the AI findings. Proof
   has two paths: an LLM-generated **Semgrep rule** that must fire on the code, and — when enabled
   (`SANDBOX_ENABLED=true`, Docker present) — a **sandboxed test proof** that runs an LLM-generated
   check script inside a network-disabled Docker container. A finding is only `CONFIRMED` if a proof
   path actually demonstrates it.
4. **Verdict** — decided by the **OPA policy** (`OpaPolicyService` + `policy/verdict.rego`) when the
   `opa` binary is present, falling back to the built-in Java logic otherwise.

Gate 1 runs regardless of LLM configuration. If `LLM_API_KEY` is not set, Gate 1 tools still run and the
scan reaches a verdict from their (deterministic, confirmed) findings; the Gate-2 AI rows are marked
**skipped** rather than erroring the scan.

Each tool/layer appears as its own row in the live status view. Configure tool binary locations via the
`secgate.*-binary` properties (or their env overrides) if they are not on `PATH`.

## How to use

1. Create a feature branch: `git checkout -b feature/fix-something`
2. Make your changes
3. Push to GitHub
4. Create a PR to main
5. GitHub Actions runs both gates automatically:
   - Gate 1 runs tests and scans
   - Gate 2 analyzes the diff with AI
6. If either gate fails, the PR is blocked
7. Fix issues and push again - gates run automatically on update

The workflow follows the proposal: Gate 1 is fast and broad (tests, basic scanning), Gate 2 is deep and AI-powered (permission checks, data protection, etc.).
