# CI & Security Scanning

This repository is hosted as a **private GitHub project**
(`github.com/schinchli/poc-validator-agent`) and runs its full offline verification plus a
set of security scanners on every push. A mirror also exists on GitLab
(`gitlab.com/hey.schinchli/poc-validator-agent`, private) with an equivalent
`.gitlab-ci.yml`; GitHub is primary.

## Pipeline layout (`.github/workflows/ci.yml`)

| Job | What it verifies |
|---|---|
| `pytest` | The 106 offline tests — deterministic core, tool boundary, catalogue integrity, repo conventions. Python 3.12. |
| `pip-audit` | The exact dependency set the agent container installs (`source/agent/requirements.txt`) against the PyPI advisory database. Any known-vulnerable resolved version fails the job. |
| `jest-cdk` (matrix ×2) | TypeScript build + jest suite for the AgentCore CDK app and the web-layer CDK app, plus an `npm audit` JSON artifact per app. |
| `semgrep` | SAST over Python and TypeScript with the `p/ci` ruleset; any finding fails the job. |
| `gitleaks` | Secret scan over the **full git history** (`fetch-depth: 0`), not just the tip commit. |
| `trivy` | Filesystem scan: dependency advisories (lockfiles + requirements), Dockerfile/IaC misconfigurations, and a second secret-scan opinion. HIGH/CRITICAL fail the job (`trivy.yaml`). |

Dependabot is configured (`.github/dependabot.yml`) for pip, both npm apps, and the
workflow's own actions, weekly.

All of this works on a free private repository — findings are read from job logs and
artifacts; no GitHub Advanced Security features are required. (CodeQL and native secret
scanning need Advanced Security on private repos, which is why the pipeline carries its
own scanners instead.)

## Dependency posture (as of 2026-08-12)

**Python (agent):** floors raised to the versions the suite is verified against —
`bedrock-agentcore >=1.21.0`, `strands-agents >=1.51.0`, `mcp >=1.29.0`,
`botocore[crt] >=1.43.69`, `aws-opentelemetry-distro >=0.19.0`. Upper bounds unchanged
(the Dockerfile installs `requirements.txt`, so deployed containers stay reproducible).

**Python (UI):** `streamlit` verified on 1.61.1 within the existing `>=1.50,<2` range.
The UI and agent still cannot share a virtualenv — see ADR 0005.

**npm (both CDK apps):** `aws-cdk-lib` bumped `~2.261.0 → 2.264.0` (exact pin);
`npm overrides` keeps every reachable `brace-expansion` at ≥5.0.9. Known residual:
`aws-cdk-lib`'s *bundled* `brace-expansion` 5.0.8 (GHSA-rgw5-rvv9-x895, HIGH) — bundled
dependencies are physically inside the published `aws-cdk-lib` tarball and cannot be
overridden. Build-time-only exposure (`cdk synth` asset-globbing, devDependency path);
clears automatically at the next `aws-cdk-lib` release that bundles 5.0.9. Tracked in the
README's Known Limitations.

## Scanner findings log

The running record of every scanner finding and its resolution, newest first.

### Run 2 (2026-08-12) — all 7 jobs green

`pytest`, `pip-audit`, `jest-cdk` ×2, `semgrep`, `gitleaks` (full history, no leaks),
`trivy` — all passing. The two GitHub Dependabot alerts (both CVE-2026-69152, the bundled
`brace-expansion` documented above) were dismissed as *tolerable risk* with a comment
pointing at this document and `.trivyignore.yaml`; they are re-examined on every
`aws-cdk-lib` bump. Dependabot's initial sweep also opened version-bump PRs (including
majors: TypeScript 7, `@types/node` 26); those are left for deliberate review, and the
7-day cooldown now paces future ones.

### Run 1 (initial push, 2026-08-12) — 4 jobs failed, all triaged

| Scanner | Finding | Resolution |
|---|---|---|
| semgrep | 12 × `github-actions-mutable-action-tag` — every action referenced by mutable tag (`@v4`, `@v2`) | All actions pinned to full 40-char commit SHAs (with human-readable version comments). |
| semgrep | 4 × `dependabot-missing-cooldown` — no cooldown on any ecosystem | `cooldown: default-days: 7` added to all four Dependabot entries — newly published packages wait a week before update PRs. |
| semgrep | Python / TypeScript app code | **No findings.** |
| gitleaks | Job aborted: `gitleaks-action@v2` fails on any git stderr output (`"stderr is not empty"`), producing no verdict | Replaced the action with the pinned gitleaks 8.30.1 binary (SHA-256 verified at download) running `gitleaks git` over the full history. Verified locally first: **12 commits scanned, no leaks.** |
| trivy | Job aborted: `aquasecurity/trivy-action@0.28.0` tag does not exist | Pinned to v0.36.0 by commit SHA. |
| trivy (local pre-run) | `DS-0002` (HIGH): agent runtime image ran as root | Real fix: `source/agent/Dockerfile` now creates and switches to a non-root user (uid 10001). |
| trivy (local pre-run) | `DS-0002` (HIGH) on the Lambda MCP-target Dockerfile | Justified exception in `.trivyignore.yaml`: Lambda executes container images under its own unprivileged sandbox user; altering the base image's user risks breaking the runtime interface client. |
| trivy (local pre-run) | `CVE-2026-69152` (HIGH): `brace-expansion` 5.0.8 in both CDK lockfiles | Justified, scoped exception in `.trivyignore.yaml` — this is `aws-cdk-lib`'s bundled copy (see Dependency posture above); every reachable copy is ≥5.0.9 via `npm overrides`. Entry is removed when aws-cdk-lib bundles the fix. |
| jest (agentcore/cdk) | Not a scanner finding: `AgentCoreApplication` requires `agentcore/agentcore.json`, which is gitignored (holds live deploy state), so the suite failed in CI while passing locally | CI materialises it from the tracked `agentcore.json.template` before running jest — the same first step the README gives developers. |
| pytest, pip-audit, jest (infrastructure/cdk) | — | Passed on the first run. |
