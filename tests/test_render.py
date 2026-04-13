from glasswall.models import Dependency, Finding, RemediationFileChange, RemediationRun, ScanResult, Vulnerability
from glasswall.render import render_remediation_summary, render_sarif


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
