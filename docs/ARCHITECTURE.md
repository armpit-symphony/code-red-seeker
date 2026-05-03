# Code Red Seeker Architecture

## Product Shape

Code Red Seeker is a control plane plus scanner engines.

The control plane owns users, targets, runs, findings, approvals, reports, and audit logs. Scanner engines are replaceable workers that emit normalized results.

## Current Components

### Platform

Path: `platform/`

Origin: `armpit-symphony/red-spark-team`

Responsibilities:

- Target registry.
- Audit runs.
- Findings database.
- Report workspace.
- Provider/model settings.
- Routing policies.
- Multi-agent report workflow.
- Human approval before export.
- Audit log.

### SwarmReview Engine

Path: `engines/swarm-review/`

Origin: `armpit-symphony/swarm-review`

Responsibilities:

- Static code analysis with Bandit and Semgrep.
- Secret detection with detect-secrets and regex fallback.
- Scoped web/security checks from the legacy bug bounty workflow.
- Scope, policy, and consent gate primitives.
- JSON and Markdown scanner output.

### Root CLI

Path: `code_red_seeker.py`

Responsibilities:

- Provide one root command during the R&D merge.
- Delegate `review`, `scan`, and `doctor` to SwarmReview.
- Point contributors to the platform application.

This CLI is temporary. Later it should become a real package entrypoint.

### Scanner Job Bridge

Path: `platform/backend/scanner_jobs.py`

Endpoint: `POST /api/runs/{run_id}/scanner-jobs/code-review`

Responsibilities:

- Resolve a platform run target to a local repo path.
- Execute `engines/swarm-review/swarm_review_cli.py review`.
- Collect SwarmReview JSON and Markdown artifacts.
- Return raw scanner findings to `platform/backend/server.py` for normalization.
- Store scanner artifacts under `artifacts/scanner-runs/<run_id>/`.

## Target End State

```text
code_red_seeker/
  platform_api/
  platform_ui/
  engines/
    code_review/
    web_guardian/
    secrets/
    evidence/
  integrations/
    github/
    sarif/
    openclaw/
  shared/
    schemas/
    policies/
    redaction/
    audit/
```

## Integration Contract

Every engine should return:

```json
{
  "engine": "code-review",
  "run_id": "string",
  "target": "string",
  "started_at": "iso8601",
  "finished_at": "iso8601",
  "findings": [
    {
      "title": "string",
      "severity": "critical|high|medium|low",
      "confidence": "high|medium|low",
      "affected_surfaces": ["string"],
      "evidence": "string",
      "remediation": "string",
      "source_name": "string",
      "source_rule_id": "string",
      "fingerprint": "string"
    }
  ],
  "artifacts": [
    {
      "name": "string",
      "path": "string",
      "kind": "json|markdown|sarif|log|screenshot"
    }
  ]
}
```

The platform should never rely on raw scanner formats directly. Raw output can be attached as an artifact, but the findings view should use the shared contract.

## Safety Model

Default behavior:

- Code and repo scanning is self-authorized.
- Web scanning is exploratory/passive unless explicit consent unlocks deeper validation.
- Report export requires human approval.
- Secrets are redacted before evidence is shown or exported.
- All scanner actions are auditable.

## Immediate Technical Debt

- The platform and engine currently have separate dependency trees.
- SwarmReview still has older product names and legacy files.
- Some SwarmReview advertised features are TODOs.
- GitHub App handling needs production hardening.
- Platform scanner import is manual today; it needs direct engine execution.
