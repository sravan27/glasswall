# Contributing

Glasswall is opinionated on purpose. The goal is not to collect every vulnerability workflow on earth. The goal is to make the patch gap operationally expensive to ignore.

## What we value most

- clearer prioritization over more noise
- deterministic behavior over magic
- remediation paths that are safe enough to trust
- GitHub-native workflows that reduce time to patch

## Good contribution areas

- new manifest parsers
- better patch-gap scoring signals
- safe remediation support for more ecosystems
- GitHub App and workflow ergonomics
- operator-facing docs and examples

## Local setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
pytest
python -m compileall src
```

## Pull requests

- keep scope tight
- explain the operator value, not just the code change
- add or update tests for behavior changes
- avoid speculative abstractions unless they make the next safe remediation path easier

## Starter Contribution Path for Patch-Gap Cases

We welcome real-world patch-gap cases from the community! You do not need to write code to contribute—submitting threat intelligence cases helps sharpen Glasswall's detection and prioritization rules.

### Case Triage Checklist

Before submitting a patch-gap case, verify your case meets these quality criteria:

- [ ] **Real-World Evidence:** Includes CVE ID, GHSA ID, vendor advisory link, or public disclosure source.
- [ ] **Clear Gap Definition:** Explains why existing patches or heuristics missed or delayed detection.
- [ ] **Reproducible Behavior:** Describes conditions, manifest types, or payload structures triggering the gap.
- [ ] **Impact & Severity:** Briefly estimates potential exploitability or operational risk.

### What Makes a Strong Patch-Gap Case?

1. **Context over Raw Data:** Explain *why* the threat was missed rather than just attaching log files.
2. **Minimal Working Example:** Provide a concise payload, requirement snippet, or step-by-step trigger.
3. **Vendor Reference:** Attach official fix links, security advisories, or commit SHAs.

### Case Lifecycle & Tagging

Submitted cases are triaged and tagged for product integration:

| Tag | Target Outcome |
|---|---|
| `type:test-case` | Converts case into automated regression tests |
| `type:heuristic` | Informs detection rules and urgency scoring logic |
| `type:dashboard` | Enhances UX visualization and fleet pressure metrics |

> **Product Linkage:** Accepted cases are linked back to shipped product updates, release notes, and detection enhancements to credit community contributors.
