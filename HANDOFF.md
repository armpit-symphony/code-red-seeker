# Code Red Seeker Handoff

Date: 2026-05-03

## Context

The user created `armpit-symphony/code-red-seeker` as an R&D playground. The goal is to merge:

- `armpit-symphony/red-spark-team`
- `armpit-symphony/swarm-review`

into one SparkPit Labs aligned tool for Guardian Services.

The repo is public at the moment but is expected to become private before real use.

## What Was Done

- Cloned the three repos locally under `C:\Users\limap`.
- Copied Red Spark Team into `code-red-seeker/platform/`.
- Copied SwarmReview into `code-red-seeker/engines/swarm-review/`.
- Added `code_red_seeker.py` as a temporary root CLI wrapper.
- Replaced the minimal README with product definition, layout, and roadmap summary.
- Added `docs/ROADMAP.md`.
- Added `docs/ARCHITECTURE.md`.
- Added this handoff file.

## Current Layout

```text
C:\Users\limap\code-red-seeker
  README.md
  LICENSE
  code_red_seeker.py
  HANDOFF.md
  docs/
    ROADMAP.md
    ARCHITECTURE.md
  platform/
    backend/
    frontend/
    configs/
    docs/
    k8s/
    docker-compose.yml
  engines/
    swarm-review/
      agents/
      core/
      configs/
      github_app/
      playbooks/
      scripts/
      tests/
```

## Important Notes

- This is a physical merge seed, not a fully integrated runtime yet.
- `platform/` is still branded and structured like Red Spark Team internally.
- `engines/swarm-review/` is still branded and structured like SwarmReview internally.
- The root CLI delegates to `engines/swarm-review/swarm_review_cli.py`.
- No destructive cleanup was done.
- Generated screenshots and large `test_reports/` from Red Spark Team were not copied.

## Next Best Task

Build the bridge from scanner engine to platform:

1. Add a backend module in `platform/backend/` that can run `engines/swarm-review/swarm_review_cli.py review`.
2. Capture the JSON output path.
3. Normalize findings into the platform `findings` collection.
4. Attach the raw scanner JSON and Markdown report as artifacts.
5. Add an API endpoint like `POST /api/runs/{run_id}/scanner-jobs/code-review`.
6. Add frontend action on the run detail page to start a code review scan.

## Files To Read First

- `README.md`
- `docs/ROADMAP.md`
- `docs/ARCHITECTURE.md`
- `platform/backend/server.py`
- `platform/backend/models.py`
- `platform/frontend/src/pages/RunDetailPage.jsx`
- `engines/swarm-review/swarm_review_cli.py`
- `engines/swarm-review/agents/static_analyzer.py`
- `engines/swarm-review/agents/secrets_detector.py`

## Caution

Do not run deep web scans against third-party targets unless the target is explicitly authorized and scope/consent checks pass. Treat this repo as internal R&D until auth, tenant isolation, and secret redaction are hardened.
