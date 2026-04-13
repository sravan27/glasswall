from __future__ import annotations

from glasswall.advisories import days_since
from glasswall.models import Dependency, Finding, Vulnerability


def assess_findings(
    dependencies: tuple[Dependency, ...],
    vulnerability_index: dict[tuple[str, str, str], tuple[Vulnerability, ...]],
) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    dependency_map = {dependency.key(): dependency for dependency in dependencies}
    for key, vulnerabilities in vulnerability_index.items():
        dependency = dependency_map.get(key)
        if dependency is None:
            continue
        for vulnerability in vulnerabilities:
            findings.append(_assess_single(dependency, vulnerability))
    return tuple(sorted(findings, key=lambda finding: (-finding.urgency_score, finding.dependency.name)))


def _assess_single(dependency: Dependency, vulnerability: Vulnerability) -> Finding:
    score = 10
    rationale: list[str] = []

    if vulnerability.kev:
        score += 65
        rationale.append("Present in the CISA Known Exploited Vulnerabilities catalogue.")

    if vulnerability.fixed_versions:
        score += 18
        rationale.append(f"Fix published: {', '.join(vulnerability.fixed_versions[:3])}.")
    else:
        rationale.append("No fixed version advertised yet.")

    modified_days = days_since(vulnerability.modified)
    if modified_days is not None:
        if modified_days <= 7:
            score += 14
            rationale.append("Advisory changed in the last 7 days.")
        elif modified_days <= 30:
            score += 8
            rationale.append("Advisory changed in the last 30 days.")

    published_days = days_since(vulnerability.published)
    if published_days is not None:
        if published_days <= 7:
            score += 10
            rationale.append("Advisory was published in the last 7 days.")
        elif published_days <= 30:
            score += 5
            rationale.append("Advisory was published in the last 30 days.")

    if vulnerability.kev_ransomware and vulnerability.kev_ransomware.lower() == "known":
        score += 12
        rationale.append("CISA links this item to ransomware activity.")

    if not vulnerability.aliases:
        rationale.append("Missing CVE/GHSA aliases reduces external correlation.")

    patch_gap = bool(vulnerability.fixed_versions) and (
        vulnerability.kev
        or (modified_days is not None and modified_days <= 30)
        or (published_days is not None and published_days <= 30)
    )

    if patch_gap:
        score += 10
        rationale.append("Patch-gap risk: attackers can study a public fix before most teams deploy it.")

    label = _label_for(score)
    return Finding(
        dependency=dependency,
        vulnerability=vulnerability,
        urgency_score=score,
        urgency_label=label,
        patch_gap=patch_gap,
        rationale=tuple(rationale),
    )


def _label_for(score: int) -> str:
    if score >= 90:
        return "critical-now"
    if score >= 70:
        return "urgent"
    if score >= 45:
        return "high"
    return "watch"

