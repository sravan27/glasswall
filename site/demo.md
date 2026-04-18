# Glasswall Showcase

- Title: `Glasswall Showcase`
- Generated: `2026-04-18T19:46:16+00:00`
- Targets: `2`
- Open findings: `20`
- Urgent findings: `0`
- Patch-gap findings: `3`
- Average resolved patch-gap MTTP (days): `n/a`

## Npm Legacy
- Target: `/Users/sravansridhar/Documents/Codex/glasswall/examples/showcase/npm-legacy`
- Findings: `5`
- Urgent findings: `0`
- Patch-gap findings: `2`
- Recommendations: `1`
- Dry-run changed files: `2`

### Top findings
- [high] lodash@4.17.20 CVE-2026-2950 score=51
- [high] lodash@4.17.20 CVE-2026-4800 score=51
- [watch] lodash@4.17.20 CVE-2020-28500 score=28
- [watch] lodash@4.17.20 CVE-2021-23337 score=28
- [watch] lodash@4.17.20 CVE-2025-13465 score=28

### Top remediation queue
- [high] lodash@4.17.20 -> 4.18.0 action=refresh-node-lockfile

## Python Legacy
- Target: `/Users/sravansridhar/Documents/Codex/glasswall/examples/showcase/python-legacy`
- Findings: `15`
- Urgent findings: `0`
- Patch-gap findings: `1`
- Recommendations: `2`
- Dry-run changed files: `1`

### Top findings
- [high] requests@2.19.0 CVE-2026-25645 score=51
- [watch] requests@2.19.0 CVE-2018-18074 score=28
- [watch] requests@2.19.0 CVE-2023-32681 score=28
- [watch] requests@2.19.0 CVE-2024-35195 score=28
- [watch] requests@2.19.0 CVE-2024-47081 score=28

### Top remediation queue
- [high] requests@2.19.0 -> 2.33.0 action=update-pinned-requirement
- [watch] urllib3@1.25.2 -> 2.6.3 action=update-pinned-requirement