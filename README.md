# Glasswall

[![CI](https://github.com/sravan27/glasswall/actions/workflows/ci.yml/badge.svg)](https://github.com/sravan27/glasswall/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/sravan27/glasswall?display_name=tag)](https://github.com/sravan27/glasswall/releases/latest)
[![License](https://img.shields.io/badge/license-MIT-154c57)](https://github.com/sravan27/glasswall/blob/main/LICENSE)
[![Patch-Gap Operations](https://img.shields.io/badge/focus-patch--gap%20operations-c66030)](https://github.com/sravan27/glasswall/blob/main/ROADMAP.md)
[![Site](https://img.shields.io/badge/site-live-8a6a16)](https://sravan27.github.io/glasswall/)

Glasswall is a local-first defensive scanner for the patch gap: the dangerous window after a fix or advisory becomes public and before most teams actually patch.

That matters more in the Project Glasswing / Claude Mythos world than another generic vulnerability list. When attackers can turn patch diffs into working exploits quickly, defenders need tooling that treats a public fix as an urgent operational event.

## What it does

- Scans common dependency manifests in a local repository.
- Queries the public [OSV](https://osv.dev/) API for package-specific advisories.
- Correlates advisories with the public [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) feed.
- Caches advisory and KEV lookups locally so repeated scans stay fast and cheap.
- Deduplicates overlapping GHSA/PYSEC-style records into one actionable vulnerability.
- Scores findings for patch-gap urgency using deterministic, explainable rules.
- Builds remediation plans with recommended target versions using live PyPI and npm registry metadata.
- Applies the safest currently supported upgrades for exact-pinned `requirements.txt` and exact-pinned npm direct dependencies backed by `package-lock.json` or `npm-shrinkwrap.json`.
- Stores scan history in SQLite, computes deltas between scans, and exposes a FastAPI dashboard plus JSON API.
- Computes fleet pressure and resolved patch-gap MTTP from saved scan history.
- Grades fleet posture with a deterministic scorecard that weighs live urgency, patch-gap backlog, public exposure age, recent drift, and resolved MTTP.
- Surfaces a change feed for newly dangerous and recently cleared findings across the fleet.
- Exports public proof bundles with `glasswall showcase` so GitHub Pages and demo repos can render live product output instead of hand-written marketing copy.
- Emits SARIF for GitHub code scanning and Markdown summaries for GitHub Actions job summaries.
- Applies optional `.glasswall.yml` policy files so teams can suppress noise without hiding risk silently.

## Why this scope

Glasswall is intentionally not an LLM wrapper. The critical problem here is prioritization and actionability:

- A fixed bug with a public patch is often more dangerous than teams treat it.
- Known exploited vulnerabilities deserve immediate visibility.
- Zero-budget teams still need an opinionated queue, not a giant dump of CVEs.

Glasswall is also intentionally not a clone of inventory-first scanners. Tools like OSV-Scanner and Dependabot already cover broad dependency visibility and update automation well. Glasswall’s bet is narrower: make newly dangerous public-fix windows visible fast, rank them hard, and surface them inside GitHub workflows in a way that is difficult to ignore.

## Why teams reach for it

| If you need... | Existing tools already help with... | Glasswall focuses on... |
| --- | --- | --- |
| vulnerability inventory | broad dependency visibility and CVE lookup | public-fix pressure and patch-gap ranking |
| update automation | recurring dependency bump PRs | smallest safe remediation that clears the visible advisory set |
| one-repo scanning | local or CI scans | fleet pressure, newly dangerous feeds, and resolved patch-gap MTTP |
| security dashboards | counts and backlogs | pressure that gets harder to ignore in GitHub workflows |

## Supported manifests

- `package-lock.json`
- `npm-shrinkwrap.json`
- `pnpm-lock.yaml`
- `requirements.txt`
- `poetry.lock`
- `uv.lock`
- `Pipfile.lock`
- `Cargo.lock`
- `go.sum`
- `Gemfile.lock`
- `composer.lock`

This first version is optimized for resolved dependency manifests. If only abstract constraints are present, Glasswall intentionally does not guess.

## Run it

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e ".[dev]"
glasswall scan /path/to/repo --format summary --fail-on high
glasswall plan /path/to/repo --format markdown
glasswall remediate /path/to/repo --format markdown
glasswall scan /path/to/repo --format sarif --output reports/glasswall.sarif
glasswall showcase examples/showcase/python-legacy examples/showcase/npm-legacy --format markdown
glasswall fleet --format summary
glasswall scorecard --format markdown
glasswall history /path/to/repo
glasswall serve --host 127.0.0.1 --port 8080
```

Then open <http://127.0.0.1:8080>.

## Commands

```bash
glasswall scan /path/to/repo --format summary
glasswall scan /path/to/repo --format markdown --fail-on urgent
glasswall scan /path/to/repo --format sarif --output reports/glasswall.sarif
glasswall plan /path/to/repo --format summary
glasswall plan /path/to/repo --format json --output reports/glasswall-plan.json
glasswall remediate /path/to/repo --format summary
glasswall remediate /path/to/repo --apply --max-upgrades 3 --format markdown
glasswall showcase examples/showcase/python-legacy examples/showcase/npm-legacy --format json --output site/demo.json
glasswall fleet --format markdown
glasswall scorecard --format json
glasswall scan /path/to/repo --policy .glasswall.yml --format summary
glasswall history /path/to/repo --limit 20
glasswall serve
```

`glasswall scan` prints to stdout by default and stores the result in `glasswall.db` in the current working directory unless `GLASSWALL_DB_PATH` is set.

`glasswall scan --fail-on high` exits with status `1` when any finding is `high`, `urgent`, or `critical-now`, which makes it suitable for CI gating.

`glasswall scan --output path/to/report.sarif` writes the rendered output to a file, which is useful for GitHub code scanning uploads.

`glasswall plan` groups findings by dependency and chooses the lowest upgrade target that clears the visible advisory set for that dependency. For PyPI and npm packages, Glasswall also fetches live registry metadata to show the latest available version and release recency.

`glasswall remediate` is the first automation layer. Today it safely updates exact-pinned `requirements.txt` entries plus exact-pinned npm direct dependencies when an adjacent `package.json` is backed by `package-lock.json` or `npm-shrinkwrap.json`. Unsupported manifests and non-exact npm ranges stay explicit in the output so teams know where human review or ecosystem-specific tooling is still required.

`glasswall showcase` turns one or more repositories into a compact proof bundle for GitHub Pages, docs, or launch material. The bundle includes per-target scan results, remediation plans, dry-run remediation previews, and a fleet-style summary that can be rendered as JSON or Markdown.

`glasswall fleet` turns scan history into a pressure board. It aggregates current urgent exposure across targets, computes resolved patch-gap MTTP from findings that were resolved after entering a patch-gap window, and highlights what just became dangerous between each target's latest two scans.

`glasswall scorecard` sits one layer above `fleet`. It turns those same histories into grades and trend labels so teams can tell whether they are hardening, holding, or backsliding without reading every raw metric first.

## Live showcase

The public site reads a generated bundle from `site/demo.json`. You can refresh it locally with:

```bash
glasswall showcase \
  examples/showcase/python-legacy \
  examples/showcase/npm-legacy \
  --format json \
  --output site/demo.json
```

Those demo targets are intentionally small and exact-pinned so the site shows the real supported remediation path, not a synthetic screenshot.

## API

- `GET /healthz`
- `GET /api/scans`
- `GET /api/scans/latest`
- `GET /api/scans/latest/delta`
- `GET /api/scans/{id}`
- `GET /api/scans/{id}/delta`
- `GET /api/scans/{id}/plan`
- `GET /api/plans/latest`
- `GET /api/fleet`
- `GET /api/scorecard`
- `GET /api/github/status`
- `POST /api/scans`
- `POST /api/plans`
- `POST /api/remediate`
- `POST /github/webhooks`
- `POST /scan`

## Policy File

If `.glasswall.yml` or `.glasswall.yaml` exists in the scanned repository root, Glasswall loads it automatically. You can also pass `--policy /path/to/file.yml`.

Example:

```yaml
minimum_urgency: high
fail_on: urgent
patch_gap_only: false
max_findings: 50
ignore:
  advisories:
    - CVE-2024-0000
  packages:
    - example-package
  paths:
    - vendor/*
  ecosystems:
    - npm
```

A starter file lives at [.glasswall.example.yml](/Users/sravansridhar/Documents/Codex/glasswall/.glasswall.example.yml).

## GitHub Action

Glasswall ships as a reusable composite GitHub Action in [action.yml](/Users/sravansridhar/Documents/Codex/glasswall/action.yml). It:

- installs Glasswall
- writes a remediation-plan Markdown summary to `GITHUB_STEP_SUMMARY`
- emits a SARIF file
- optionally uploads SARIF to GitHub code scanning
- can apply supported remediation changes directly in the checked-out repository
- fails the job on the urgency threshold you choose

Example workflow: [examples/github-actions/glasswall.yml](/Users/sravansridhar/Documents/Codex/glasswall/examples/github-actions/glasswall.yml)

Remediation PR workflow example: [examples/github-actions/remediation-pr.yml](/Users/sravansridhar/Documents/Codex/glasswall/examples/github-actions/remediation-pr.yml)

Daily fleet digest example: [examples/github-actions/daily-fleet-digest.yml](/Users/sravansridhar/Documents/Codex/glasswall/examples/github-actions/daily-fleet-digest.yml)

Showcase refresh workflow: [.github/workflows/showcase.yml](/Users/sravansridhar/Documents/Codex/glasswall/.github/workflows/showcase.yml)

## GitHub App Mode

Glasswall can also run as a GitHub App webhook receiver so pull requests get patch-gap comments automatically.

Current behavior:

- validates `X-Hub-Signature-256` before any processing
- accepts pull request `opened`, `reopened`, `synchronize`, and `ready_for_review` events
- scans the PR head commit, including forked pull requests
- renders a remediation-first comment and updates it in place by default
- can open or update a remediation PR from `push` events on the default branch when auto-PR mode is enabled

Required environment:

- `GLASSWALL_GITHUB_APP_ID`
- `GLASSWALL_GITHUB_PRIVATE_KEY`
- `GLASSWALL_GITHUB_WEBHOOK_SECRET`

Optional GitHub environment:

- `GLASSWALL_GITHUB_API_BASE_URL` default: `https://api.github.com`
- `GLASSWALL_GITHUB_API_VERSION` default: `2026-03-10`
- `GLASSWALL_GITHUB_COMMENT_MODE` values: `upsert`, `create`, `off`
- `GLASSWALL_GITHUB_AUTO_PR_MODE` values: `off`, `push`
- `GLASSWALL_GITHUB_AUTO_PR_BRANCH` default: `glasswall/remediation`
- `GLASSWALL_GITHUB_AUTO_PR_MAX_UPGRADES` default: `3`
- `GLASSWALL_GITHUB_AUTO_PR_COMMIT_MESSAGE` default: `glasswall remediation`
- `GLASSWALL_GITHUB_AUTO_PR_TITLE` default: `[glasswall] apply top supported patch-gap remediation`

Run the server and point your GitHub App webhook at:

```bash
glasswall serve --host 0.0.0.0 --port 8080
```

Webhook endpoint:

```text
POST /github/webhooks
```

## Design choices

- Local-first: repository scanning happens on your machine.
- Zero-money friendly: only public, no-cost feeds are used.
- Deterministic: every urgency score is accompanied by explicit reasons.
- Narrow scope: patch-gap visibility first, then the safest possible remediation automation.

## Environment

- `GLASSWALL_DB_PATH`: path to the SQLite database.
- `GLASSWALL_CACHE_DIR`: directory for cached OSV and KEV responses.
- `GLASSWALL_HTTP_TIMEOUT_SECONDS`: HTTP timeout for public feeds.
- `GLASSWALL_OSV_QUERY_TTL_SECONDS`: TTL for per-package OSV match lookups.
- `GLASSWALL_OSV_VULN_TTL_SECONDS`: TTL for full OSV vulnerability documents.
- `GLASSWALL_KEV_TTL_SECONDS`: TTL for the CISA KEV cache.
- `GLASSWALL_MAX_DETAIL_REQUESTS`: max parallel full-vuln fetches.
- `GLASSWALL_GITHUB_APP_ID`: GitHub App identifier.
- `GLASSWALL_GITHUB_PRIVATE_KEY`: PEM private key used to mint the app JWT.
- `GLASSWALL_GITHUB_WEBHOOK_SECRET`: secret used to validate webhook deliveries.
- `GLASSWALL_GITHUB_API_BASE_URL`: GitHub API base URL.
- `GLASSWALL_GITHUB_API_VERSION`: GitHub API version header value.
- `GLASSWALL_GITHUB_COMMENT_MODE`: `upsert`, `create`, or `off`.
- `GLASSWALL_GITHUB_AUTO_PR_MODE`: `off` or `push`.
- `GLASSWALL_GITHUB_AUTO_PR_BRANCH`: branch name used for auto remediation PRs.
- `GLASSWALL_GITHUB_AUTO_PR_MAX_UPGRADES`: number of top supported upgrades to apply in automation.
- `GLASSWALL_GITHUB_AUTO_PR_COMMIT_MESSAGE`: commit message used for auto remediation commits.
- `GLASSWALL_GITHUB_AUTO_PR_TITLE`: PR title used for auto remediation branches.

## Repo Workflows

- CI runs on Python 3.12 and 3.13 via [ci.yml](/Users/sravansridhar/Documents/Codex/glasswall/.github/workflows/ci.yml).
- GitHub Pages deploys the public landing page from [pages.yml](/Users/sravansridhar/Documents/Codex/glasswall/.github/workflows/pages.yml).
- Security reporting guidance lives in [SECURITY.md](/Users/sravansridhar/Documents/Codex/glasswall/SECURITY.md).
- The repository is MIT-licensed via [LICENSE](/Users/sravansridhar/Documents/Codex/glasswall/LICENSE).
- The category thesis and product path live in [ROADMAP.md](/Users/sravansridhar/Documents/Codex/glasswall/ROADMAP.md).
- Contribution guidance lives in [CONTRIBUTING.md](/Users/sravansridhar/Documents/Codex/glasswall/CONTRIBUTING.md).

## Docker

```bash
docker build -t glasswall .
docker run --rm -p 8080:8080 -v "$PWD:/workspace" glasswall
```
