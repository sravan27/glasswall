import json
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


def test_remediation_applier_previews_npm_package_lock_upgrade_without_writing(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "repo"
    project.mkdir()
    package_json = project / "package.json"
    package_lock = project / "package-lock.json"
    package_json.write_text(
        json.dumps(
            {
                "name": "repo",
                "version": "1.0.0",
                "dependencies": {
                    "lodash": "4.17.20",
                },
            },
            indent=2,
        )
        + "\n"
    )
    package_lock.write_text(
        json.dumps(
            {
                "name": "repo",
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"lodash": "4.17.20"}},
                    "node_modules/lodash": {"version": "4.17.20"},
                },
            },
            indent=2,
        )
        + "\n"
    )
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

    def fake_runner(args: list[str], cwd: Path) -> None:
        assert args == ["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"]
        assert cwd == project
        lock_payload = json.loads(package_lock.read_text())
        lock_payload["packages"][""]["dependencies"]["lodash"] = "4.17.21"
        lock_payload["packages"]["node_modules/lodash"]["version"] = "4.17.21"
        package_lock.write_text(json.dumps(lock_payload, indent=2) + "\n")

    monkeypatch.setattr("glasswall.remediator.shutil.which", lambda name: "/opt/homebrew/bin/npm")
    result = RemediationApplier(command_runner=fake_runner).apply_plan(project, plan, apply=False)

    assert result.changed_file_count == 2
    assert result.applied_recommendation_count == 1
    assert package_json.read_text().count("4.17.20") == 1
    assert package_lock.read_text().count("4.17.20") == 2
    assert tuple(change.source_file for change in result.changed_files) == ("package.json", "package-lock.json")


def test_remediation_applier_writes_npm_package_lock_upgrade_when_apply_enabled(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "repo"
    project.mkdir()
    package_json = project / "package.json"
    package_lock = project / "package-lock.json"
    package_json.write_text('{\n  "dependencies": {\n    "lodash": "4.17.20"\n  }\n}\n')
    package_lock.write_text(
        json.dumps(
            {
                "name": "repo",
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"lodash": "4.17.20"}},
                    "node_modules/lodash": {"version": "4.17.20"},
                },
            },
            indent=2,
        )
        + "\n"
    )
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

    def fake_runner(args: list[str], cwd: Path) -> None:
        assert cwd == project
        package_lock.write_text(package_lock.read_text().replace("4.17.20", "4.17.21"))

    monkeypatch.setattr("glasswall.remediator.shutil.which", lambda name: "/opt/homebrew/bin/npm")
    result = RemediationApplier(command_runner=fake_runner).apply_plan(project, plan, apply=True)

    assert result.changed_file_count == 2
    assert result.applied_recommendation_count == 1
    assert "4.17.21" in package_json.read_text()
    assert "4.17.21" in package_lock.read_text()


def test_remediation_applier_skips_npm_ranges_that_are_not_exact_pins(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "repo"
    project.mkdir()
    (project / "package.json").write_text('{\n  "dependencies": {\n    "lodash": "^4.17.20"\n  }\n}\n')
    (project / "package-lock.json").write_text("{}\n")
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

    monkeypatch.setattr("glasswall.remediator.shutil.which", lambda name: "/opt/homebrew/bin/npm")
    result = RemediationApplier().apply_plan(project, plan, apply=False)

    assert result.changed_file_count == 0
    assert result.skipped_count == 1
    assert "exact-pinned" in result.skipped[0].reason


def test_remediation_applier_marks_unsupported_manifests_as_skipped(tmp_path: Path) -> None:
    project = tmp_path / "repo"
    project.mkdir()
    (project / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n")
    plan = RemediationPlan(
        target_path=str(project),
        generated_at="2026-04-13T00:00:00+00:00",
        policy_path=None,
        recommendations=(
            RemediationRecommendation(
                ecosystem="npm",
                name="lodash",
                source_file="pnpm-lock.yaml",
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
