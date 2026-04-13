import pytest

from glasswall.models import Dependency, Finding, PackageMetadata, ScanResult, Vulnerability
from glasswall.planner import RemediationPlanner


class StubRegistryClient:
    async def fetch_metadata(self, ecosystem: str, name: str) -> PackageMetadata | None:
        return PackageMetadata(
            ecosystem=ecosystem,
            name=name,
            latest_version="2.33.0",
            latest_published="2026-03-25T00:00:00+00:00",
            registry_url="https://example.com/pkg",
            repository_url="https://example.com/repo",
        )


@pytest.mark.anyio
async def test_remediation_planner_builds_dependency_level_upgrade_plan() -> None:
    dependency = Dependency("PyPI", "requests", "2.19.0", "requirements.txt")
    vulnerability_one = Vulnerability(
        osv_id="GHSA-one",
        source_ids=("GHSA-one",),
        aliases=("CVE-2026-0001",),
        summary="Issue one",
        details=None,
        published="2026-03-01T00:00:00+00:00",
        modified="2026-03-02T00:00:00+00:00",
        fixed_versions=("2.20.0",),
        references=("https://example.com/one",),
        kev=False,
        kev_due_date=None,
        kev_ransomware=None,
    )
    vulnerability_two = Vulnerability(
        osv_id="GHSA-two",
        source_ids=("GHSA-two",),
        aliases=("CVE-2026-0002",),
        summary="Issue two",
        details=None,
        published="2026-03-10T00:00:00+00:00",
        modified="2026-03-11T00:00:00+00:00",
        fixed_versions=("2.31.0",),
        references=("https://example.com/two",),
        kev=False,
        kev_due_date=None,
        kev_ransomware=None,
    )
    result = ScanResult(
        scan_id=None,
        target_path="/tmp/repo",
        generated_at="2026-04-12T00:00:00+00:00",
        dependencies=(dependency,),
        findings=(
            Finding(
                dependency=dependency,
                vulnerability=vulnerability_one,
                urgency_score=51,
                urgency_label="high",
                patch_gap=True,
                rationale=("one",),
            ),
            Finding(
                dependency=dependency,
                vulnerability=vulnerability_two,
                urgency_score=28,
                urgency_label="watch",
                patch_gap=False,
                rationale=("two",),
            ),
        ),
    )

    planner = RemediationPlanner(registry_client=StubRegistryClient())
    plan = await planner.build_plan(result)

    assert plan.recommendation_count == 1
    recommendation = plan.recommendations[0]
    assert recommendation.target_version == "2.31.0"
    assert recommendation.latest_version == "2.33.0"
    assert recommendation.action == "update-pinned-requirement"
    assert recommendation.advisories == ("CVE-2026-0001", "CVE-2026-0002")
    assert plan.to_dict()["recommendation_count"] == 1
