from glasswall.analytics import FleetOverview, FleetSignal, TargetPressure
from glasswall.models import Dependency, Finding, RemediationFileChange, RemediationRun, ScanResult, Vulnerability
from glasswall.render import render_fleet_summary, render_remediation_summary, render_sarif


def test_render_sarif_uses_canonical_vuln_id_and_relative_lockfile() -> None:
    dependency = Dependency("PyPI", "requests", "2.19.0", "requirements.txt")
    finding = Finding(
        dependency=dependency,
        vulnerability=Vulnerability(
            osv_id="GHSA-gc5v-m9x4-r6x2",
            source_ids=("GHSA-gc5v-m9x4-r6x2",),
            aliases=("CVE-2026-25645",),
            summary="Requests temp file reuse",
            details="Longer description",
            published="2026-03-25T00:00:00+00:00",
            modified="2026-03-27T00:00:00+00:00",
            fixed_versions=("2.33.0",),
            references=("https://example.com/advisory",),
            kev=False,
            kev_due_date=None,
            kev_ransomware=None,
        ),
        urgency_score=51,
        urgency_label="high",
        patch_gap=True,
        rationale=("Patch gap",),
    )
    result = ScanResult(
        scan_id=1,
        target_path="/tmp/repo",
        generated_at="2026-04-10T00:00:00+00:00",
        dependencies=(dependency,),
        findings=(finding,),
        policy_path="/tmp/repo/.glasswall.yml",
    )

    sarif = render_sarif(result)

    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    sarif_result = sarif["runs"][0]["results"][0]

    assert rule["id"] == "CVE-2026-25645"
    assert sarif_result["ruleId"] == "CVE-2026-25645"
    assert sarif_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "requirements.txt"
    assert sarif_result["properties"]["policyPath"] == "/tmp/repo/.glasswall.yml"
    assert "glasswall/finding/v1" in sarif_result["partialFingerprints"]


def test_render_remediation_summary_reports_counts() -> None:
    result = RemediationRun(
        target_path="/tmp/repo",
        generated_at="2026-04-13T00:00:00+00:00",
        policy_path="/tmp/repo/.glasswall.yml",
        apply_mode=False,
        changed_files=(
            RemediationFileChange(
                source_file="requirements.txt",
                ecosystem="PyPI",
                action="update-pinned-requirement",
                package_names=("requests",),
                changed=True,
                before_digest="before",
                after_digest="after",
            ),
        ),
        skipped=(),
    )

    rendered = render_remediation_summary(result)

    assert "Applied recommendations: 1" in rendered
    assert "requirements.txt packages=requests" in rendered


def test_render_fleet_summary_reports_mttp_and_targets() -> None:
    overview = FleetOverview(
        generated_at="2026-04-14T00:00:00+00:00",
        target_count=1,
        total_open_findings=3,
        total_urgent_findings=1,
        total_patch_gap_findings=2,
        average_resolved_mttp_days=6.5,
        hottest_target_path="/repo-a",
        targets=(
            TargetPressure(
                target_path="/repo-a",
                latest_scan_id=2,
                latest_generated_at="2026-04-14T00:00:00+00:00",
                dependency_count=12,
                open_finding_count=3,
                urgent_open_finding_count=1,
                patch_gap_open_finding_count=2,
                top_urgency_label="urgent",
                oldest_open_public_days=4.0,
                average_resolved_mttp_days=6.5,
                average_resolved_detection_days=2.0,
                resolved_finding_count=5,
            ),
        ),
        newly_dangerous_count=1,
        recently_resolved_count=0,
        signals=(
            FleetSignal(
                kind="new",
                target_path="/repo-a",
                scan_id=2,
                generated_at="2026-04-14T00:00:00+00:00",
                dependency_name="requests",
                current_version="2.19.0",
                source_file="requirements.txt",
                vulnerability_id="CVE-2026-1234",
                urgency_label="urgent",
                urgency_score=82,
                patch_gap=True,
                days_since_public=4.0,
            ),
        ),
    )

    rendered = render_fleet_summary(overview)

    assert "Newly dangerous findings: 1" in rendered
    assert "Average resolved patch-gap MTTP (days): 6.5" in rendered
    assert "open=3 urgent=1 patch-gap=2" in rendered
    assert "[Newly dangerous] /repo-a requests@2.19.0 CVE-2026-1234" in rendered
