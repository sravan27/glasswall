import asyncio

from glasswall.models import (
    Dependency,
    Finding,
    RemediationFileChange,
    RemediationPlan,
    RemediationRecommendation,
    RemediationRun,
    ScanResult,
    Vulnerability,
)
from glasswall.render import render_showcase_markdown, render_showcase_summary
from glasswall.showcase import build_showcase


class _StubPlanner:
    async def build_plan(self, scan: ScanResult) -> RemediationPlan:
        dependency = scan.dependencies[0]
        return RemediationPlan(
            target_path=scan.target_path,
            generated_at="2026-04-19T09:00:00+00:00",
            policy_path=None,
            recommendations=(
                RemediationRecommendation(
                    ecosystem=dependency.ecosystem,
                    name=dependency.name,
                    source_file=dependency.source_file,
                    current_version=dependency.version,
                    target_version="2.33.0",
                    latest_version="2.33.1",
                    latest_published="2026-04-15T00:00:00+00:00",
                    registry_url="https://example.com/requests",
                    repository_url="https://github.com/example/requests",
                    rationale=("Clears visible advisory set.",),
                    advisories=("CVE-2026-1234",),
                    urgency_label="urgent",
                    urgency_score=88,
                    patch_gap=True,
                    action="upgrade-direct-dependency",
                ),
            ),
        )


class _StubApplier:
    def apply_plan(self, root, plan, *, apply=False, max_recommendations=None) -> RemediationRun:
        recommendation = plan.recommendations[0]
        return RemediationRun(
            target_path=str(root),
            generated_at="2026-04-19T09:00:00+00:00",
            policy_path=None,
            apply_mode=apply,
            changed_files=(
                RemediationFileChange(
                    source_file=recommendation.source_file,
                    ecosystem=recommendation.ecosystem,
                    action="update-pinned-requirement",
                    package_names=(recommendation.name,),
                    changed=True,
                    before_digest="before",
                    after_digest="after",
                ),
            ),
            skipped=(),
        )


class _StubService:
    remediation_planner = _StubPlanner()
    remediation_applier = _StubApplier()

    async def scan_path(self, target_path: str) -> ScanResult:
        dependency = Dependency("PyPI", "requests", "2.19.0", "requirements.txt")
        return ScanResult(
            scan_id=None,
            target_path=target_path,
            generated_at="2026-04-19T08:00:00+00:00",
            dependencies=(dependency,),
            findings=(
                Finding(
                    dependency=dependency,
                    vulnerability=Vulnerability(
                        osv_id="GHSA-one",
                        source_ids=("GHSA-one",),
                        aliases=("CVE-2026-1234",),
                        summary="Example issue",
                        details=None,
                        published="2026-04-10T00:00:00+00:00",
                        modified="2026-04-10T00:00:00+00:00",
                        fixed_versions=("2.33.0",),
                        references=("https://example.com/advisory",),
                        kev=False,
                        kev_due_date=None,
                        kev_ransomware=None,
                    ),
                    urgency_score=88,
                    urgency_label="urgent",
                    patch_gap=True,
                    rationale=("Patch gap",),
                ),
            ),
            policy_path=None,
        )


def test_build_showcase_returns_sorted_targets_and_compact_metrics(tmp_path) -> None:
    first = tmp_path / "python-legacy"
    second = tmp_path / "npm-legacy"
    first.mkdir()
    second.mkdir()

    bundle = asyncio.run(
        build_showcase(
            [str(second), str(first)],
            title="Demo",
            service=_StubService(),
            max_recommendations=1,
        )
    )

    assert bundle.title == "Demo"
    assert bundle.fleet.target_count == 2
    assert bundle.targets[0].label == "Npm Legacy"
    assert bundle.targets[0].urgent_finding_count == 1
    assert bundle.targets[0].patch_gap_finding_count == 1
    assert bundle.targets[0].remediation_preview.applied_recommendation_count == 1
    payload = bundle.to_dict()
    assert payload["targets"][0]["scan"]["finding_count"] == 1
    assert payload["targets"][0]["plan"]["recommendation_count"] == 1


def test_render_showcase_outputs_include_target_snapshot(tmp_path) -> None:
    target = tmp_path / "python-legacy"
    target.mkdir()
    bundle = asyncio.run(build_showcase([str(target)], service=_StubService()))

    summary = render_showcase_summary(bundle)
    markdown = render_showcase_markdown(bundle)

    assert "Showcase: Glasswall Showcase" in summary
    assert "python legacy".title() in summary
    assert "## Python Legacy" in markdown
    assert "Top remediation queue" in markdown
