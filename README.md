# Glasswall

[![CI](https://github.com/sravan27/glasswall/actions/workflows/ci.yml/badge.svg)](https://github.com/sravan27/glasswall/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-154c57)](https://github.com/sravan27/glasswall/blob/main/LICENSE)
[![Patch-Gap Operations](https://img.shields.io/badge/focus-patch--gap%20operations-c66030)](https://github.com/sravan27/glasswall/blob/main/ROADMAP.md)

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
- Applies the safest currently supported upgrades for exact-pinned `requirements.txt` files.
- Stores scan history in SQLite, computes deltas between scans, and exposes a FastAPI dashboard plus JSON API.
- Emits SARIF for GitHub code scanning and Markdown summaries for GitHub Actions job summaries.
- Applies optional `.glasswall.yml` policy files so teams can suppress noise without hiding risk silently.

## Why this scope

Glasswall is intentionally not an LLM wrapper. The critical problem here is prioritization and actionability:

- A fixed bug with a public patch is often more dangerous than teams treat it.
- Known exploited vulnerabilities deserve immediate visibility.
- Zero-budget teams still need an opinionated queue, not a giant dump of CVEs.

Glasswall is also intentionally not a clone of inventory-first scanners. Tools like OSV-Scanner and Dependabot already cover broad dependency visibility and update automation well. Glasswall’s bet is narrower: make newly dangerous public-fix windows visible fast, rank them hard, and surface them inside GitHub workflows in a way that is difficult to ignore.

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
glasswall scan /path/to/repo --policy .glasswall.yml --format summary
glasswall history /path/to/repo --limit 20
glasswall serve
```

`glasswall scan` prints to stdout by default and stores the result in `glasswall.db` in the current working directory unless `GLASSWALL_DB_PATH` is set.

`glasswall scan --fail-on high` exits with status `1` when any finding is `high`, `urgent`, or `critical-now`, which makes it suitable for CI gating.

`glasswall scan --output path/to/report.sarif` writes the rendered output to a file, which is useful for GitHub code scanning uploads.

`glasswall plan` groups findings by dependency and chooses the lowest upgrade target that clears the visible advisory set for that dependency. For PyPI and npm packages, Glasswall also fetches live registry metadata to show the latest available version and release recency.

`glasswall remediate` is the first automation layer. Today it safely updates exact-pinned `requirements.txt` entries and produces a machine-readable record of what it changed and what it skipped. Unsupported manifests stay explicit in the output so teams know where human review or ecosystem-specific tooling is still required.

## API

- `GET /healthz`
- `GET /api/scans`
- `GET /api/scans/latest`
- `GET /api/scans/latest/delta`
- `GET /api/scans/{id}`
- `GET /api/scans/{id}/delta`
- `GET /api/scans/{id}/plan`
- `GET /api/plans/latest`
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

## GitHub App Mode

Glasswall can also run as a GitHub App webhook receiver so pull requests get patch-gap comments automatically.

Current behavior:

- validates `X-Hub-Signature-256` before any processing
- accepts pull request `opened`, `reopened`, `synchronize`, and `ready_for_review` events
- scans the PR head commit, including forked pull requests
- renders a remediation-first comment and updates it in place by default

Required environment:

- `GLASSWALL_GITHUB_APP_ID`
- `GLASSWALL_GITHUB_PRIVATE_KEY`
- `GLASSWALL_GITHUB_WEBHOOK_SECRET`

Optional GitHub environment:

- `GLASSWALL_GITHUB_API_BASE_URL` default: `https://api.github.com`
- `GLASSWALL_GITHUB_API_VERSION` default: `2026-03-10`
- `GLASSWALL_GITHUB_COMMENT_MODE` values: `upsert`, `create`, `off`

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

## Repo Workflows

- CI runs on Python 3.12 and 3.13 via [ci.yml](/Users/sravansridhar/Documents/Codex/glasswall/.github/workflows/ci.yml).
- Security reporting guidance lives in [SECURITY.md](/Users/sravansridhar/Documents/Codex/glasswall/SECURITY.md).
- The repository is MIT-licensed via [LICENSE](/Users/sravansridhar/Documents/Codex/glasswall/LICENSE).
- The category thesis and product path live in [ROADMAP.md](/Users/sravansridhar/Documents/Codex/glasswall/ROADMAP.md).

## Docker

```bash
docker build -t glasswall .
docker run --rm -p 8080:8080 -v "$PWD:/workspace" glasswall
```
