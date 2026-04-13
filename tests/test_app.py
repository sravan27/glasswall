import hashlib
import hmac
import json

from fastapi.testclient import TestClient

from glasswall.app import create_app
from glasswall.models import RemediationFileChange, RemediationRun
from glasswall.settings import Settings


class StubWebhookProcessor:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    async def handle_event(self, event_name: str, payload: dict[str, object]) -> None:
        self.calls.append((event_name, payload))


def test_github_webhook_endpoint_verifies_signature_and_queues_processing(tmp_path) -> None:
    settings = Settings(
        db_path=str(tmp_path / "glasswall.db"),
        cache_dir=str(tmp_path / "cache"),
        request_timeout_seconds=5,
        osv_query_ttl_seconds=10,
        osv_vuln_ttl_seconds=10,
        kev_ttl_seconds=10,
        max_concurrent_detail_requests=2,
        github_app_id="12345",
        github_private_key="-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
        github_webhook_secret="super-secret",
        github_api_base_url="https://api.github.com",
        github_api_version="2026-03-10",
        github_comment_mode="upsert",
        github_auto_pr_mode="off",
        github_auto_pr_branch="glasswall/remediation",
        github_auto_pr_max_upgrades=3,
        github_auto_pr_commit_message="glasswall remediation",
        github_auto_pr_title="[glasswall] apply top supported patch-gap remediation",
    )
    processor = StubWebhookProcessor()
    client = TestClient(create_app(settings=settings, webhook_processor=processor))
    payload = {"action": "opened", "pull_request": {"number": 1}}
    body = json.dumps(payload).encode("utf-8")
    signature = "sha256=" + hmac.new(b"super-secret", body, hashlib.sha256).hexdigest()

    response = client.post(
        "/github/webhooks",
        content=body,
        headers={
            "X-GitHub-Event": "pull_request",
            "X-Hub-Signature-256": signature,
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 202
    assert response.json() == {"accepted": True, "event": "pull_request"}
    assert processor.calls == [("pull_request", payload)]


def test_github_status_api_reports_configuration_state(tmp_path) -> None:
    settings = Settings(
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
        github_comment_mode="off",
        github_auto_pr_mode="off",
        github_auto_pr_branch="glasswall/remediation",
        github_auto_pr_max_upgrades=3,
        github_auto_pr_commit_message="glasswall remediation",
        github_auto_pr_title="[glasswall] apply top supported patch-gap remediation",
    )
    client = TestClient(create_app(settings=settings))

    response = client.get("/api/github/status")

    assert response.status_code == 200
    assert response.json()["github"]["configured"] is False
    assert response.json()["github"]["comment_mode"] == "off"


def test_remediate_api_returns_dry_run_result(tmp_path) -> None:
    class StubService:
        async def remediate_path(self, target_path, policy=None, apply=False, max_recommendations=None):
            return RemediationRun(
                target_path=target_path,
                generated_at="2026-04-13T00:00:00+00:00",
                policy_path=policy.path if policy else None,
                apply_mode=apply,
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

    project = tmp_path / "repo"
    project.mkdir()
    (project / ".glasswall.yml").write_text("minimum_urgency: high\n")
    settings = Settings(
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
        github_comment_mode="off",
        github_auto_pr_mode="off",
        github_auto_pr_branch="glasswall/remediation",
        github_auto_pr_max_upgrades=3,
        github_auto_pr_commit_message="glasswall remediation",
        github_auto_pr_title="[glasswall] apply top supported patch-gap remediation",
    )
    client = TestClient(create_app(settings=settings, service=StubService()))

    response = client.post(
        "/api/remediate",
        json={
            "path": str(project),
            "policy_path": str(project / ".glasswall.yml"),
            "apply": False,
            "max_upgrades": 1,
        },
    )

    assert response.status_code == 201
    assert response.json()["remediation"]["changed_file_count"] == 1
