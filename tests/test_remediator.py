from pathlib import Path

from glasswall.models import RemediationPlan, RemediationRecommendation
from glasswall.remediator import RemediationApplier


def test_remediation_applier_previews_requirements_upgrade_without_writing(tmp_path: Path) -> None:
    project = tmp_path / "repo"
    project.mkdir()
    requirements = project / "requirements.txt"
    requirements.write_text("requests==2.19.0\nurllib3==1.25.0\n")
    plan = RemediationPlan(
        target_path=str(project),
        generated_at="2026-04-13T00:00:00+00:00",
        policy_path=str(project / ".glasswall.yml"),
        recommendations=(
            _recommendation("requests", "2.19.0", "2.33.0"),
            _recommendation("urllib3", "1.25.0", "2.2.2"),
        ),
    )

    result = RemediationApplier().apply_plan(project, plan, apply=False)

    assert result.changed_file_count == 1
    assert result.applied_recommendation_count == 2
    assert requirements.read_text() == "requests==2.19.0\nurllib3==1.25.0\n"
    assert result.changed_files[0].package_names == ("requests", "urllib3")


def test_remediation_applier_writes_supported_changes_when_apply_enabled(tmp_path: Path) -> None:
    project = tmp_path / "repo"
    project.mkdir()
    requirements = project / "requirements.txt"
    requirements.write_text("requests==2.19.0\n")
    plan = RemediationPlan(
        target_path=str(project),
        generated_at="2026-04-13T00:00:00+00:00",
        policy_path=None,
        recommendations=(_recommendation("requests", "2.19.0", "2.33.0"),),
    )

    result = RemediationApplier().apply_plan(project, plan, apply=True)

    assert result.changed_file_count == 1
    assert "2.33.0" in requirements.read_text()


def test_remediation_applier_marks_unsupported_manifests_as_skipped(tmp_path: Path) -> None:
    project = tmp_path / "repo"
    project.mkdir()
    (project / "package-lock.json").write_text("{}")
    plan = RemediationPlan(
        target_path=str(project),
        generated_at="2026-04-13T00:00:00+00:00",
        policy_path=None,
        recommendations=(
            RemediationRecommendation(
                ecosystem="npm",
                name="lodash",
                source_file="package-lock.json",
                current_version="4.17.20",
                target_version="4.17.21",
                latest_version="4.17.21",
                latest_published=None,
                registry_url=None,
                repository_url=None,
                rationale=("lowest fix",),
                advisories=("CVE-2026-9999",),
                urgency_label="high",
                urgency_score=50,
                patch_gap=True,
                action="refresh-node-lockfile",
            ),
        ),
    )

    result = RemediationApplier().apply_plan(project, plan, apply=False)

    assert result.changed_file_count == 0
    assert result.skipped_count == 1
    assert "not yet supported" in result.skipped[0].reason


def _recommendation(name: str, current: str, target: str) -> RemediationRecommendation:
    return RemediationRecommendation(
        ecosystem="PyPI",
        name=name,
        source_file="requirements.txt",
        current_version=current,
        target_version=target,
        latest_version=target,
        latest_published="2026-04-01T00:00:00+00:00",
        registry_url=f"https://example.com/{name}",
        repository_url=f"https://example.com/{name}/repo",
        rationale=(f"Upgrade {name}.",),
        advisories=("CVE-2026-0001",),
        urgency_label="high",
        urgency_score=51,
        patch_gap=True,
        action="update-pinned-requirement",
    )
