from glasswall.analytics import build_fleet_overview, build_target_pressure
from glasswall.models import Dependency, Finding, ScanResult, Vulnerability


def test_build_target_pressure_computes_resolved_mttp_and_open_age() -> None:
    dependency = Dependency("PyPI", "requests", "2.19.0", "requirements.txt")
    resolved_history = (
        ScanResult(
            scan_id=1,
            target_path="/repo-a",
            generated_at="2026-04-01T00:00:00+00:00",
            dependencies=(dependency,),
            findings=(
                Finding(
                    dependency=dependency,
                    vulnerability=_vulnerability("CVE-2026-0001", published="2026-03-28T00:00:00+00:00"),
                    urgency_score=50,
                    urgency_label="high",
                    patch_gap=True,
                    rationale=("patch gap",),
                ),
            ),
            policy_path=None,
        ),
        ScanResult(
            scan_id=2,
            target_path="/repo-a",
            generated_at="2026-04-04T00:00:00+00:00",
            dependencies=(dependency,),
            findings=(),
            policy_path=None,
        ),
    )

    target = build_target_pressure(resolved_history)

    assert target.open_finding_count == 0
    assert target.average_resolved_mttp_days == 7.0
    assert target.average_resolved_detection_days == 3.0
    assert target.resolved_finding_count == 1


def test_build_fleet_overview_ranks_hottest_target_and_totals() -> None:
    dependency = Dependency("PyPI", "requests", "2.19.0", "requirements.txt")
    history_a = (
        ScanResult(
            scan_id=1,
            target_path="/repo-a",
            generated_at="2026-04-05T00:00:00+00:00",
            dependencies=(dependency,),
            findings=(
                Finding(
                    dependency=dependency,
                    vulnerability=_vulnerability("CVE-2026-0002", published="2026-04-01T00:00:00+00:00"),
                    urgency_score=78,
                    urgency_label="urgent",
                    patch_gap=True,
                    rationale=("urgent",),
                ),
            ),
            policy_path=None,
        ),
    )
    history_b = (
        ScanResult(
            scan_id=2,
            target_path="/repo-b",
            generated_at="2026-04-05T00:00:00+00:00",
            dependencies=(dependency,),
            findings=(
                Finding(
                    dependency=dependency,
                    vulnerability=_vulnerability("CVE-2026-0003", published="2026-04-04T00:00:00+00:00"),
                    urgency_score=20,
                    urgency_label="watch",
                    patch_gap=False,
                    rationale=("watch",),
                ),
            ),
            policy_path=None,
        ),
    )

    overview = build_fleet_overview((history_a, history_b))

    assert overview.target_count == 2
    assert overview.total_open_findings == 2
    assert overview.total_urgent_findings == 1
    assert overview.total_patch_gap_findings == 1
    assert overview.hottest_target_path == "/repo-a"
    assert overview.targets[0].target_path == "/repo-a"


def _vulnerability(alias: str, published: str) -> Vulnerability:
    return Vulnerability(
        osv_id=f"GHSA-{alias.lower()}",
        source_ids=(f"GHSA-{alias.lower()}",),
        aliases=(alias,),
        summary="Example issue",
        details=None,
        published=published,
        modified=published,
        fixed_versions=("2.33.0",),
        references=("https://example.com",),
        kev=False,
        kev_due_date=None,
        kev_ransomware=None,
    )
