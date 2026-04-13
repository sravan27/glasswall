from glasswall.github_render import COMMENT_MARKER, render_pull_request_comment
from glasswall.models import (
    Dependency,
    RemediationPlan,
    RemediationRecommendation,
    ScanResult,
    Vulnerability,
)


def test_render_pull_request_comment_includes_marker_and_upgrade_queue() -> None:
    dependency = Dependency("PyPI", "requests", "2.19.0", "requirements.txt")
    scan = ScanResult(
        scan_id=7,
        target_path="/tmp/repo",
        generated_at="2026-04-12T00:00:00+00:00",
        dependencies=(dependency,),
        findings=(),
        policy_path="/tmp/repo/.glasswall.yml",
    )
    plan = RemediationPlan(
        target_path="/tmp/repo",
        generated_at="2026-04-12T00:00:00+00:00",
        policy_path="/tmp/repo/.glasswall.yml",
        recommendations=(
            RemediationRecommendation(
                ecosystem="PyPI",
                name="requests",
                source_file="requirements.txt",
                current_version="2.19.0",
                target_version="2.33.0",
                latest_version="2.33.0",
                latest_published="2026-03-25T00:00:00+00:00",
                registry_url="https://pypi.org/project/requests/",
                repository_url="https://github.com/psf/requests",
                rationale=("Lowest version that clears visible advisories: 2.33.0.",),
                advisories=("CVE-2026-0001",),
                urgency_label="high",
                urgency_score=51,
                patch_gap=True,
                action="update-pinned-requirement",
            ),
        ),
    )

    body = render_pull_request_comment(scan, plan)

    assert COMMENT_MARKER in body
    assert "Glasswall Patch-Gap Report" in body
    assert "requests" in body
    assert "2.19.0 -> 2.33.0" in body
