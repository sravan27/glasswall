from glasswall.advisories import AdvisoryClient
from glasswall.models import Vulnerability


def test_extract_fixed_versions_skips_commit_hashes() -> None:
    client = AdvisoryClient()
    payload = {
        "affected": [
            {
                "ranges": [
                    {
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "1.26.17"},
                            {"fixed": "01220354d389cd05474713f8c982d05c9b17aafb"},
                        ]
                    }
                ],
                "database_specific": {
                    "fixed_version": "644124ecd0b6e417c527191f866daa05a5a2056d"
                },
            }
        ]
    }

    assert client._extract_fixed_versions(payload) == ("1.26.17",)


def test_deduplicate_vulnerabilities_merges_alias_related_records() -> None:
    client = AdvisoryClient()
    first = Vulnerability(
        osv_id="GHSA-abc",
        source_ids=("GHSA-abc",),
        aliases=("CVE-2026-1111",),
        summary="Short summary",
        details=None,
        published="2026-04-01T00:00:00+00:00",
        modified="2026-04-02T00:00:00+00:00",
        fixed_versions=("1.2.3",),
        references=("https://example.com/ghsa",),
        kev=False,
        kev_due_date=None,
        kev_ransomware=None,
    )
    second = Vulnerability(
        osv_id="PYSEC-2026-1",
        source_ids=("PYSEC-2026-1",),
        aliases=("CVE-2026-1111", "GHSA-abc"),
        summary="Longer, richer summary",
        details="Detailed description",
        published="2026-04-01T00:00:00+00:00",
        modified="2026-04-03T00:00:00+00:00",
        fixed_versions=("1.2.4",),
        references=("https://example.com/pysec",),
        kev=True,
        kev_due_date="2026-05-01",
        kev_ransomware="Known",
    )

    merged = client._deduplicate_vulnerabilities((first, second))

    assert len(merged) == 1
    vulnerability = merged[0]
    assert vulnerability.source_ids == ("GHSA-abc", "PYSEC-2026-1")
    assert vulnerability.aliases == ("CVE-2026-1111", "GHSA-abc")
    assert vulnerability.summary == "Longer, richer summary"
    assert vulnerability.fixed_versions == ("1.2.3", "1.2.4")
    assert vulnerability.kev is True
    assert vulnerability.kev_ransomware == "Known"
