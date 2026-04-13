# Security Policy

Glasswall exists to reduce patch-gap risk, so the repo should be held to a high operational bar too.

## Reporting

If you believe you found a security issue in Glasswall itself, please avoid filing a public issue first.

Send details to the maintainer through a private GitHub security advisory or direct contact if one is listed on the repository profile. Include:

- affected version or commit
- reproduction steps
- impact
- any suggested fix or mitigation

## Scope

Please report vulnerabilities in:

- the FastAPI service
- GitHub App webhook handling
- credential or signature verification logic
- dependency parsing that can cause unsafe code execution or file writes
- remediation logic that can overwrite unintended files

## Supported versions

The current focus is the latest `main` branch and the latest tagged release once releases exist.
