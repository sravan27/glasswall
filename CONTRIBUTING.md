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
