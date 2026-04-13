from __future__ import annotations

import asyncio

from glasswall.models import Finding, PackageMetadata, RemediationPlan, RemediationRecommendation, ScanResult, urgency_rank
from glasswall.registry import RegistryClient, choose_group_target_version


class RemediationPlanner:
    def __init__(self, registry_client: RegistryClient | None = None) -> None:
        self.registry_client = registry_client or RegistryClient()

    async def build_plan(self, result: ScanResult) -> RemediationPlan:
        groups = _group_findings(result.findings)
        metadata_tasks = {
            key: asyncio.create_task(self.registry_client.fetch_metadata(group[0].dependency.ecosystem, group[0].dependency.name))
            for key, group in groups.items()
        }
        recommendations: list[RemediationRecommendation] = []
        for key, group in groups.items():
            metadata = await metadata_tasks[key]
            recommendations.append(_build_recommendation(group, metadata))
        recommendations.sort(
            key=lambda recommendation: (
                -urgency_rank(recommendation.urgency_label),
                -recommendation.urgency_score,
                recommendation.name,
            )
        )
        return RemediationPlan(
            target_path=result.target_path,
            generated_at=result.generated_at,
            policy_path=result.policy_path,
            recommendations=tuple(recommendations),
        )


def _group_findings(findings: tuple[Finding, ...]) -> dict[tuple[str, str, str, str], list[Finding]]:
    groups: dict[tuple[str, str, str, str], list[Finding]] = {}
    for finding in findings:
        key = (
            finding.dependency.source_file,
            finding.dependency.ecosystem,
            finding.dependency.name,
            finding.dependency.version,
        )
        groups.setdefault(key, []).append(finding)
    return groups


def _build_recommendation(findings: list[Finding], metadata: PackageMetadata | None) -> RemediationRecommendation:
    lead = max(findings, key=lambda finding: (urgency_rank(finding.urgency_label), finding.urgency_score))
    advisory_fixed_versions = tuple(finding.vulnerability.fixed_versions for finding in findings if finding.vulnerability.fixed_versions)
    target_version = choose_group_target_version(
        lead.dependency.ecosystem,
        lead.dependency.version,
        advisory_fixed_versions,
    )
    rationale = []
    if target_version:
        rationale.append(f"Lowest version that clears visible advisories: {target_version}.")
    else:
        rationale.append("No machine-readable fix version available; manual triage required.")
    if metadata and metadata.latest_version:
        rationale.append(f"Latest registry version: {metadata.latest_version}.")
    if any(finding.patch_gap for finding in findings):
        rationale.append("At least one advisory is in a patch-gap window.")
    if any(finding.vulnerability.kev for finding in findings):
        rationale.append("At least one advisory appears in CISA KEV.")
    action = _action_for_source_file(lead.dependency.source_file, lead.dependency.ecosystem, target_version)
    advisories = tuple(sorted({finding.vulnerability.canonical_id for finding in findings}))
    return RemediationRecommendation(
        ecosystem=lead.dependency.ecosystem,
        name=lead.dependency.name,
        source_file=lead.dependency.source_file,
        current_version=lead.dependency.version,
        target_version=target_version,
        latest_version=metadata.latest_version if metadata else None,
        latest_published=metadata.latest_published if metadata else None,
        registry_url=metadata.registry_url if metadata else None,
        repository_url=metadata.repository_url if metadata else None,
        rationale=tuple(rationale),
        advisories=advisories,
        urgency_label=lead.urgency_label,
        urgency_score=max(finding.urgency_score for finding in findings),
        patch_gap=any(finding.patch_gap for finding in findings),
        action=action,
    )


def _action_for_source_file(source_file: str, ecosystem: str, target_version: str | None) -> str:
    if target_version is None:
        return "manual-review"
    if source_file.endswith("requirements.txt"):
        return "update-pinned-requirement"
    if source_file.endswith(("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml")):
        return "refresh-node-lockfile"
    if source_file.endswith(("poetry.lock", "uv.lock", "Pipfile.lock")):
        return "refresh-python-lockfile"
    if source_file.endswith("Cargo.lock"):
        return "refresh-rust-lockfile"
    if source_file.endswith("Gemfile.lock"):
        return "refresh-bundler-lockfile"
    if source_file.endswith("composer.lock"):
        return "refresh-composer-lockfile"
    return f"upgrade-{ecosystem.lower()}"
