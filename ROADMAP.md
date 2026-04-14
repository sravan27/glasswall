# Roadmap

Glasswall is not trying to become another generic vulnerability dashboard. The category bet is tighter:

> Make patch-gap exposure visible, actionable, and operationally expensive to ignore.

## Phase 1: Patch-gap visibility

Current work:

- resolved manifest scanning
- OSV and CISA KEV correlation
- deterministic urgency scoring
- scan history and deltas
- SARIF and GitHub job summaries
- GitHub App pull request comments
- remediation planning
- first supported local remediation path for exact-pinned `requirements.txt`
- exact-pinned npm remediation with safe lock refresh for `package-lock.json`
- fleet pressure overview and initial resolved patch-gap MTTP analytics
- newly dangerous fleet change feed across latest scans

## Phase 2: Patch-gap compression

Next product moves:

- broaden safe auto-remediation across ecosystems
- open remediation pull requests automatically
- org-level MTTP tracking
- stronger suppression and policy ergonomics
- repo and team exposure dashboards

## Phase 3: Patch-intel moat

The longer-term moat is not more scanning. It is intelligence about when risk just changed:

- silent security fix detection
- suspicious upstream diff classification
- fix-availability monitoring before teams reprioritize
- “newly dangerous today” fleet reporting

## Product scorecard

The metrics that matter most:

- mean time to patch after public fix
- count of urgent patch-gap items older than 7 days
- percent of repos with remediation automation enabled
- percent of findings that become pull requests instead of terminal output
