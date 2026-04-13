from glasswall.diffing import build_scan_delta
from glasswall.models import Dependency, Finding, ScanResult, Vulnerability


def test_build_scan_delta_tracks_new_and_resolved_findings() -> None:
    dependency = Dependency("PyPI", "requests", "2.31.0", "requirements.txt")
    old_vulnerability = Vulnerability(
        osv_id="GHSA-old",
        source_ids=("GHSA-old",),
        aliases=("CVE-2025-0001",),
        summary="Old issue",
        details=None,
        published="2025-01-01T00:00:00+00:00",
        modified="2025-01-02T00:00:00+00:00",
        fixed_versions=("2.31.1",),
        references=(),
        kev=False,
        kev_due_date=None,
        kev_ransomware=None,
    )
    new_vulnerability = Vulnerability(
        osv_id="GHSA-new",
        source_ids=("GHSA-new",),
        aliases=("CVE-2026-0002",),
        summary="New issue",
        details=None,
        published="2026-04-01T00:00:00+00:00",
        modified="2026-04-02T00:00:00+00:00",
        fixed_versions=("2.32.0",),
        references=(),
        kev=False,
        kev_due_date=None,
        kev_ransomware=None,
    )
    previous = ScanResult(
        scan_id=1,
        target_path="/tmp/repo",
        generated_at="2026-04-01T00:00:00+00:00",
        dependencies=(dependency,),
        findings=(
            Finding(
                dependency=dependency,
                vulnerability=old_vulnerability,
                urgency_score=28,
                urgency_label="watch",
                patch_gap=False,
                rationale=("old",),
            ),
        ),
    )
    current = ScanResult(
        scan_id=2,
        target_path="/tmp/repo",
        generated_at="2026-04-02T00:00:00+00:00",
        dependencies=(dependency,),
        findings=(
            Finding(
                dependency=dependency,
                vulnerability=new_vulnerability,
                urgency_score=51,
                urgency_label="high",
                patch_gap=True,
                rationale=("new",),
            ),
        ),
    )

    delta = build_scan_delta(current, previous)

    assert len(delta.new_findings) == 1
    assert len(delta.resolved_findings) == 1
    assert delta.new_findings[0].vulnerability.canonical_id == "CVE-2026-0002"
    assert delta.resolved_findings[0].vulnerability.canonical_id == "CVE-2025-0001"

