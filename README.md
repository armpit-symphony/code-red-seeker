# Code Red Seeker

Code Red Seeker is a SparkPit Labs R&D playground for a unified security review tool.

It combines:

- A governed audit control plane from Red Spark Team.
- Code review and scanner engines from SwarmReview.
- A product direction aligned with SparkPit Guardian Services.

The working idea is simple: give AI-built software one place to create targets, run reviews, collect scanner output, normalize findings, draft reports, require human approval, and keep an audit trail.

This repo is expected to become private before real operational use.

## What It Does

Code Red Seeker is intended to cover four connected workflows:

- **Code review:** scan repos, diffs, and pull requests for insecure code, risky AI-generated patterns, hardcoded secrets, and SAST findings.
- **Governed red-team review:** run scoped web or service checks only when target, policy, and consent requirements pass.
- **Finding operations:** normalize results from Bandit, Semgrep, detect-secrets, custom scanners, imported JSON, and human notes into one findings model.
- **Report workflow:** use multi-agent LLM review to summarize evidence, prioritize risk, draft remediation, require approval, and export reports.

## Current Repo Layout

```text
code-red-seeker/
  code_red_seeker.py              # temporary root CLI wrapper
  platform/                       # Red Spark Team control plane
    backend/
    frontend/
    configs/
    k8s/
    docker-compose.yml
  engines/
    swarm-review/                 # SwarmReview scanner engine seed
      agents/
      core/
      configs/
      github_app/
      playbooks/
      tests/
  docs/
    ROADMAP.md
    ARCHITECTURE.md
  HANDOFF.md
```

## Root CLI

The root wrapper exists so the merged repo has one command while the older projects are refactored.

```bash
python code_red_seeker.py review --repo ./some-repo --profile cautious
python code_red_seeker.py doctor --target example.com --auth ./policy.yml --scope ./configs/scope.json
python code_red_seeker.py scan --target example.com --mode exploratory
python code_red_seeker.py platform
```

The wrapper currently delegates scanner commands to `engines/swarm-review/swarm_review_cli.py`.

## Product Model

Code Red Seeker should be built as a control plane plus engines:

```text
Control Plane
  targets
  runs
  policies
  findings
  artifacts
  reports
  approvals
  audit log
  model routing

Engines
  code review engine
  secrets engine
  web/security scan engine
  evidence normalization engine
  report/LLM review engine

Integrations
  GitHub App
  GitHub Actions
  SARIF import/export
  JSON/text scanner import
  SparkPit Guardian Services dashboard
```

## Roadmap

### Phase 0 - Repo Consolidation

- [x] Create `code-red-seeker` repo.
- [x] Import Red Spark Team into `platform/`.
- [x] Import SwarmReview into `engines/swarm-review/`.
- [x] Add root CLI wrapper.
- [x] Add README, roadmap, architecture notes, and handoff.

### Phase 1 - Make The Merge Coherent

- [ ] Rename platform-visible product strings to Code Red Seeker.
- [ ] Add root `.env.example` and setup instructions.
- [ ] Add a root `Makefile` or task runner for backend, frontend, tests, and scanner commands.
- [ ] Move scanner execution behind a platform backend service module.
- [ ] Normalize SwarmReview findings into the platform finding schema.
- [ ] Persist scanner runs, artifacts, and logs in the platform database.

### Phase 2 - Code Guardian

- [ ] Add repo, diff, and PR target types as first-class run modes.
- [ ] Wire Bandit, Semgrep, detect-secrets, regex patterns, and entropy checks into platform runs.
- [ ] Add SARIF output for GitHub code scanning.
- [ ] Add PR comment generation with severity thresholds.
- [ ] Add deduplication by rule, file, line, fingerprint, and evidence hash.

### Phase 3 - Consent-Gated Web Guardian

- [ ] Keep passive checks available in exploratory mode.
- [ ] Require scope file, auth policy, and consent token for deep mode.
- [ ] Move web scanners into a worker sandbox.
- [ ] Add target allowlists, rate limits, and artifact redaction.
- [ ] Make all scanner actions visible in the audit log.

### Phase 4 - AI Review And Reporting

- [ ] Replace placeholder LLM logic analysis with platform-routed model calls.
- [ ] Add agent roles for planner, evidence normalizer, risk reviewer, remediation writer, and report drafter.
- [ ] Require human approval before export.
- [ ] Add customer-ready SparkPit Guardian Services report templates.

### Phase 5 - Production Hardening

- [ ] Add authentication, roles, and tenant boundaries.
- [ ] Add a real job queue and scanner workers.
- [ ] Lock down CORS and deployment secrets.
- [ ] Add backup, retention, and audit-log immutability strategy.
- [ ] Prepare private deployment profile for SparkPit Labs.

## Non-Goals For This R&D Repo

- Do not optimize for public package polish yet.
- Do not run active scans against third-party targets without written authorization.
- Do not treat the current GitHub App scaffold as production-ready.
- Do not expose generated reports until human review gates are implemented.

## Source Repos

- `armpit-symphony/red-spark-team` became `platform/`.
- `armpit-symphony/swarm-review` became `engines/swarm-review/`.

## Current Integration Status

- Root CLI can delegate code review scans into the SwarmReview engine.
- Platform backend has `POST /api/runs/{run_id}/scanner-jobs/code-review`.
- The scanner job runs SwarmReview, imports normalized findings, and appends raw scanner output to the run's `tool-output` artifact.
- The run detail frontend exposes a Code Red Seeker scanner panel on the Findings tab.

See `HANDOFF.md` for next-agent instructions.
