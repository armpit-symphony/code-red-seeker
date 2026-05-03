# Code Red Seeker Roadmap

This roadmap is written for the R&D monorepo state created on 2026-05-03.

## North Star

Code Red Seeker should become the internal SparkPit Labs platform for governed AI-era security review:

- One target registry.
- One run model.
- One findings model.
- One report workflow.
- Multiple engines behind it.
- Human approval before export or customer delivery.

## Milestone 1: Consolidated Developer Repo

Status: started.

Deliverables:

- Import Red Spark Team under `platform/`.
- Import SwarmReview under `engines/swarm-review/`.
- Add root CLI wrapper.
- Preserve source history context in docs.
- Avoid copying generated UI screenshots and bulky test artifacts.

Exit criteria:

- `python code_red_seeker.py --help` works.
- `python code_red_seeker.py platform` points contributors to the platform.
- README explains the merged direction.

## Milestone 2: Shared Finding Contract

Status: not started.

Deliverables:

- Define `Finding`, `Evidence`, `Run`, `Target`, and `Artifact` contracts.
- Map SwarmReview scanner output to platform findings.
- Add fingerprints for dedupe.
- Add source metadata for every imported scanner result.
- Add regression tests for JSON normalization.

Exit criteria:

- A SwarmReview JSON output can be imported into a platform run without manual copy/paste.
- Duplicate findings do not create duplicate open issues.

## Milestone 3: Scanner Job Service

Status: not started.

Deliverables:

- [x] Add `platform/backend/scanner_jobs.py`.
- [x] Add backend endpoint to launch a code review scan.
- [x] Add run status transitions for scanner execution.
- [x] Store raw scanner artifacts under the run.
- [x] Store normalized findings in Mongo.
- [x] Add frontend control to launch code review scans from run detail.
- [ ] Add dedupe before inserting scanner findings.

Exit criteria:

- A repo path or uploaded diff can be scanned from the platform API.
- Results appear in the existing findings and report views.

## Milestone 4: Code Guardian

Status: not started.

Deliverables:

- Repo scan.
- Diff scan.
- GitHub PR scan.
- Semgrep support.
- Bandit support.
- detect-secrets support.
- Regex fallback support.
- SARIF export.
- PR comment draft.

Exit criteria:

- A local repo scan produces normalized findings.
- A PR scan can produce a Markdown review summary and SARIF.

## Milestone 5: Web Guardian

Status: not started.

Deliverables:

- Web target type.
- Exploratory mode with passive checks.
- Deep mode with explicit scope and consent.
- Rate limits.
- Evidence redaction.
- Scanner action audit logs.

Exit criteria:

- Passive checks run without active validation.
- Deep checks fail closed unless consent requirements pass.

## Milestone 6: AI Review Layer

Status: partially available in platform.

Deliverables:

- Reuse Red Spark Team provider and routing settings.
- Add scanner-aware prompt templates.
- Add role-specific agents for triage and report writing.
- Add finding confidence review.
- Add remediation plan generation.

Exit criteria:

- Findings can be summarized into a report draft.
- Reports require approval before export.

## Milestone 7: Private Service Readiness

Status: not started.

Deliverables:

- Auth and roles.
- Tenant separation.
- Secret handling and redaction audit.
- Production deployment profile.
- Backup and retention policy.
- Internal operating runbook.

Exit criteria:

- SparkPit Labs can operate Code Red Seeker privately for Guardian Services without exposing customer data publicly.
