from pathlib import Path
import textwrap

from glasswall.models import Dependency, Finding, ScanResult, Vulnerability
from glasswall.policy import apply_scan_policy, load_scan_policy


def test_policy_filters_findings_and_sets_policy_path(tmp_path: Path) -> None:
    project = tmp_path / "repo"
    project.mkdir()
    (project / ".glasswall.yml").write_text(
        textwrap.dedent(
            """
            minimum_urgency: high
            patch_gap_only: true
            max_findings: 1
            ignore:
              packages:
                - urllib3
            """
        ).strip()
    )

    policy = load_scan_policy(project)

    requests_dependency = Dependency("PyPI", "requests", "2.19.0", "requirements.txt")
    urllib_dependency = Dependency("PyPI", "urllib3", "1.25.0", "requirements.txt")
    high_patch_gap = Finding(
        dependency=requests_dependency,
        vulnerability=_vulnerability("GHSA-high", "CVE-2026-1111"),
        urgency_score=51,
        urgency_label="high",
        patch_gap=True,
        rationale=("patch gap",),
    )
    watch_patch_gap = Finding(
        dependency=requests_dependency,
        vulnerability=_vulnerability("GHSA-watch", "CVE-2026-1112"),
        urgency_score=28,
        urgency_label="watch",
        patch_gap=True,
        rationale=("watch",),
    )
    high_ignored = Finding(
        dependency=urllib_dependency,
        vulnerability=_vulnerability("GHSA-ignore", "CVE-2026-1113"),
        urgency_score=60,
        urgency_label="high",
        patch_gap=True,
        rationale=("ignored",),
    )
    result = ScanResult(
        scan_id=None,
        target_path=str(project),
        generated_at="2026-04-10T00:00:00+00:00",
        dependencies=(requests_dependency, urllib_dependency),
        findings=(high_patch_gap, watch_patch_gap, high_ignored),
    )

    filtered = apply_scan_policy(result, policy)

    assert filtered.policy_path == str(project / ".glasswall.yml")
    assert len(filtered.findings) == 1
    assert filtered.findings[0].vulnerability.canonical_id == "CVE-2026-1111"


def test_policy_can_ignore_specific_advisory_alias(tmp_path: Path) -> None:
    project = tmp_path / "repo"
    project.mkdir()
    (project / ".glasswall.yml").write_text(
        textwrap.dedent(
            """
            ignore:
              advisories:
                - CVE-2026-2222
            """
        ).strip()
    )

    policy = load_scan_policy(project)
    dependency = Dependency("PyPI", "requests", "2.19.0", "requirements.txt")
    finding = Finding(
        dependency=dependency,
        vulnerability=_vulnerability("GHSA-dup", "CVE-2026-2222"),
        urgency_score=55,
        urgency_label="high",
        patch_gap=True,
        rationale=("ignored",),
    )
    result = ScanResult(
        scan_id=None,
        target_path=str(project),
        generated_at="2026-04-10T00:00:00+00:00",
        dependencies=(dependency,),
        findings=(finding,),
    )

    filtered = apply_scan_policy(result, policy)

    assert filtered.findings == ()


def _vulnerability(osv_id: str, alias: str) -> Vulnerability:
    return Vulnerability(
        osv_id=osv_id,
        source_ids=(osv_id,),
        aliases=(alias,),
        summary="Example issue",
        details=None,
        published="2026-04-01T00:00:00+00:00",
        modified="2026-04-02T00:00:00+00:00",
        fixed_versions=("2.0.0",),
        references=("https://example.com",),
        kev=False,
        kev_due_date=None,
        kev_ransomware=None,
    )
