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
- Maven tests (JUnit)
- Semgrep code scanning (security-audit rules)
- Gitleaks secret detection
- Fails the build if critical issues found

This is the "basic checks" gate that runs fast (< 5 minutes target).

### Gate 2: AI-Powered Review (on PR to main)

**File:** `.github/workflows/security-gate-2.yml`

Runs on PR to main:
- Analyzes the PR diff for security patterns
- Posts findings as PR comments
- Sets verdict (PASS or BLOCKED)
- Blocks merge if critical issues found

This is the "hacker layer" gate that uses AI to detect issues a scanner would miss.

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
