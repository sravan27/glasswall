from glasswall.models import Dependency, Vulnerability
from glasswall.risk import assess_findings


def test_risk_prioritizes_kev_and_patch_gap() -> None:
    dependency = Dependency("PyPI", "requests", "2.28.1", "requirements.txt")
    vulnerability = Vulnerability(
        osv_id="GHSA-test-123",
        source_ids=("GHSA-test-123",),
        aliases=("CVE-2026-12345",),
        summary="Example bug",
        details=None,
        published="2026-04-05T00:00:00+00:00",
        modified="2026-04-08T00:00:00+00:00",
        fixed_versions=("2.32.4",),
        references=("https://example.com",),
        kev=True,
        kev_due_date="2026-04-30",
        kev_ransomware="Known",
    )

    findings = assess_findings((dependency,), {dependency.key(): (vulnerability,)})

    assert len(findings) == 1
    finding = findings[0]
    assert finding.urgency_label == "critical-now"
    assert finding.patch_gap is True
    assert finding.urgency_score >= 90
    assert any("CISA" in reason for reason in finding.rationale)
