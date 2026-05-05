from glasswall.github_setup import GitHubSetupService
from glasswall.settings import Settings


def _settings(tmp_path) -> Settings:
    return Settings(
        db_path=str(tmp_path / "glasswall.db"),
        cache_dir=str(tmp_path / "cache"),
        request_timeout_seconds=5,
        osv_query_ttl_seconds=10,
        osv_vuln_ttl_seconds=10,
        kev_ttl_seconds=10,
        max_concurrent_detail_requests=2,
        github_app_id=None,
        github_private_key=None,
        github_webhook_secret=None,
        github_api_base_url="https://api.github.com",
        github_api_version="2026-03-10",
        github_comment_mode="upsert",
        github_auto_pr_mode="off",
        github_auto_pr_branch="glasswall/remediation",
        github_auto_pr_max_upgrades=3,
        github_auto_pr_commit_message="glasswall remediation",
        github_auto_pr_title="[glasswall] apply top supported patch-gap remediation",
    )


def test_build_report_includes_manifest_preview_and_urls(tmp_path) -> None:
    service = GitHubSetupService(_settings(tmp_path))

    report = service.build_report(
        public_base_url="https://glasswall.example.com",
        account_type="organization",
        owner="acme",
        app_name="Glasswall",
        public_app=False,
    )

    assert report.webhook_url == "https://glasswall.example.com/github/webhooks"
    assert report.redirect_url == "https://glasswall.example.com/github/setup/callback"
    assert report.setup_url == "https://glasswall.example.com/github/setup/complete"
    assert report.action_url == "https://github.com/organizations/acme/settings/apps/new"
    assert report.manifest is not None
    assert report.manifest["default_permissions"]["contents"] == "write"
    assert report.manifest["default_events"] == ["pull_request", "push"]
    assert 'GLASSWALL_PUBLIC_BASE_URL="https://your-public-glasswall-url"' in report.env_template


def test_create_launch_generates_stateful_action_url(tmp_path) -> None:
    service = GitHubSetupService(_settings(tmp_path))

    launch = service.create_launch(
        public_base_url="https://glasswall.example.com",
        account_type="personal",
        app_name="Glasswall",
    )

    assert launch.action_url.startswith("https://github.com/settings/apps/new?state=")
    assert '"name": "Glasswall"' in launch.manifest_json
    assert launch.state


def test_build_report_flags_localhost_as_not_public(tmp_path) -> None:
    service = GitHubSetupService(_settings(tmp_path))

    report = service.build_report(public_base_url="http://localhost:8080")

    public_url_check = next(check for check in report.checks if check.name == "Public base URL")
    assert public_url_check.ok is False
