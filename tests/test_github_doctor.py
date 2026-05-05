from dataclasses import replace

import pytest

from glasswall.github_doctor import GitHubDoctorService
from glasswall.settings import Settings


class StubInstallationClient:
    async def list_repositories(self, *, per_page: int = 100):
        return {
            "total_count": 2,
            "repositories": [
                {
                    "full_name": "acme/api",
                    "private": True,
                    "default_branch": "main",
                    "html_url": "https://github.com/acme/api",
                    "permissions": {"admin": True},
                }
            ],
        }


class StubDoctorClient:
    async def get_authenticated_app(self):
        return {
            "id": 123,
            "name": "Glasswall",
            "slug": "glasswall",
            "description": "Patch-gap operations",
            "html_url": "https://github.com/settings/apps/glasswall",
            "external_url": "https://glasswall.example.com",
            "installations_count": 1,
        }

    async def get_webhook_config(self):
        return {
            "url": "https://glasswall.example.com/github/webhooks",
            "content_type": "json",
            "insecure_ssl": "0",
        }

    async def list_webhook_deliveries(self, *, per_page: int = 30, status: str | None = None):
        return [
            {
                "id": 7,
                "event": "pull_request",
                "action": "opened",
                "status": "OK",
                "status_code": 200,
                "delivered_at": "2026-05-05T11:00:00Z",
                "duration": 0.18,
                "redelivery": False,
                "installation_id": 99,
                "repository_id": 1001,
            },
            {
                "id": 6,
                "event": "push",
                "action": None,
                "status": "Internal Server Error",
                "status_code": 500,
                "delivered_at": "2026-05-05T10:55:00Z",
                "duration": 0.25,
                "redelivery": False,
                "installation_id": 99,
                "repository_id": 1001,
            },
        ]

    async def list_installations(self, *, per_page: int = 100):
        return [
            {
                "id": 99,
                "account": {"login": "acme", "type": "Organization"},
                "repository_selection": "selected",
                "html_url": "https://github.com/organizations/acme/settings/installations/99",
                "events": ["pull_request", "push"],
                "permissions": {
                    "contents": "write",
                    "issues": "write",
                    "pull_requests": "write",
                },
                "suspended_at": None,
            }
        ]

    async def create_installation_client(self, installation_id: int):
        assert installation_id == 99
        return StubInstallationClient()


def _settings(tmp_path) -> Settings:
    return Settings(
        db_path=str(tmp_path / "glasswall.db"),
        cache_dir=str(tmp_path / "cache"),
        request_timeout_seconds=5,
        osv_query_ttl_seconds=10,
        osv_vuln_ttl_seconds=10,
        kev_ttl_seconds=10,
        max_concurrent_detail_requests=2,
        github_app_id="123",
        github_private_key="-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
        github_webhook_secret="secret",
        github_api_base_url="https://api.github.com",
        github_api_version="2026-03-10",
        github_comment_mode="upsert",
        github_auto_pr_mode="off",
        github_auto_pr_branch="glasswall/remediation",
        github_auto_pr_max_upgrades=3,
        github_auto_pr_commit_message="glasswall remediation",
        github_auto_pr_title="[glasswall] apply top supported patch-gap remediation",
        github_public_base_url="https://glasswall.example.com",
    )


@pytest.mark.anyio
async def test_github_doctor_reports_missing_credentials(tmp_path) -> None:
    settings = replace(
        _settings(tmp_path),
        github_app_id=None,
        github_private_key=None,
        github_webhook_secret=None,
    )
    report = await GitHubDoctorService(settings).diagnose()

    assert report.configured is False
    assert report.total_installation_count == 0
    assert report.checks[0].name == "GitHub App credentials"
    assert report.api_error is None


@pytest.mark.anyio
async def test_github_doctor_reports_live_status_and_delivery_warning(tmp_path) -> None:
    report = await GitHubDoctorService(_settings(tmp_path), client=StubDoctorClient()).diagnose()

    assert report.configured is True
    assert report.app is not None
    assert report.app.slug == "glasswall"
    assert report.total_installation_count == 1
    assert report.total_repository_count == 2
    assert report.webhook is not None
    assert report.webhook.recent_failure_count == 1
    assert any(check.name == "Webhook outcomes" and check.ok is False for check in report.checks)
    assert "failed" in report.summary
