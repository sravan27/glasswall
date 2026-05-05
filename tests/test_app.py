import hashlib
import hmac
import json

from fastapi.testclient import TestClient

from glasswall.app import create_app
from glasswall.github_doctor import (
    GitHubDoctorApp,
    GitHubDoctorCheck,
    GitHubDoctorDelivery,
    GitHubDoctorReport,
    GitHubDoctorWebhook,
)
from glasswall.github_setup import GitHubAppCredentials, GitHubSetupCheck, GitHubSetupReport
from glasswall.models import Dependency, Finding, RemediationFileChange, RemediationRun, ScanResult, Vulnerability
from glasswall.settings import Settings
from glasswall.storage import Database


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


def test_fleet_api_returns_aggregated_pressure_metrics(tmp_path) -> None:
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
    database = Database(settings.db_path)
    dependency = Dependency("PyPI", "requests", "2.19.0", "requirements.txt")
    finding = Finding(
        dependency=dependency,
        vulnerability=Vulnerability(
            osv_id="GHSA-one",
            source_ids=("GHSA-one",),
            aliases=("CVE-2026-1234",),
            summary="Example issue",
            details=None,
            published="2026-04-01T00:00:00+00:00",
            modified="2026-04-01T00:00:00+00:00",
            fixed_versions=("2.33.0",),
            references=("https://example.com",),
            kev=False,
            kev_due_date=None,
            kev_ransomware=None,
        ),
        urgency_score=80,
        urgency_label="urgent",
        patch_gap=True,
        rationale=("urgent",),
    )
    database.save_scan(
        ScanResult(
            scan_id=None,
            target_path="/repo-a",
            generated_at="2026-04-03T00:00:00+00:00",
            dependencies=(dependency,),
            findings=(finding,),
            policy_path=None,
        )
    )

    client = TestClient(create_app(settings=settings, database=database))
    response = client.get("/api/fleet")

    assert response.status_code == 200
    payload = response.json()["fleet"]
    assert payload["target_count"] == 1
    assert payload["total_urgent_findings"] == 1
    assert payload["newly_dangerous_count"] == 0
    assert payload["targets"][0]["target_path"] == "/repo-a"


def test_scorecard_api_returns_grades_and_summary(tmp_path) -> None:
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
    database = Database(settings.db_path)
    dependency = Dependency("PyPI", "requests", "2.19.0", "requirements.txt")
    database.save_scan(
        ScanResult(
            scan_id=None,
            target_path="/repo-a",
            generated_at="2026-04-03T00:00:00+00:00",
            dependencies=(dependency,),
            findings=(
                Finding(
                    dependency=dependency,
                    vulnerability=Vulnerability(
                        osv_id="GHSA-one",
                        source_ids=("GHSA-one",),
                        aliases=("CVE-2026-1234",),
                        summary="Example issue",
                        details=None,
                        published="2026-04-01T00:00:00+00:00",
                        modified="2026-04-01T00:00:00+00:00",
                        fixed_versions=("2.33.0",),
                        references=("https://example.com",),
                        kev=False,
                        kev_due_date=None,
                        kev_ransomware=None,
                    ),
                    urgency_score=80,
                    urgency_label="urgent",
                    patch_gap=True,
                    rationale=("urgent",),
                ),
            ),
            policy_path=None,
        )
    )

    client = TestClient(create_app(settings=settings, database=database))
    response = client.get("/api/scorecard")

    assert response.status_code == 200
    payload = response.json()["scorecard"]
    assert payload["fleet_score"] <= 100
    assert payload["targets"][0]["target_path"] == "/repo-a"
    assert payload["targets"][0]["grade"] in {"C", "D", "F"}


def test_github_setup_api_returns_manifest_preview(tmp_path) -> None:
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

    response = client.get(
        "/api/github/setup",
        params={
            "public_base_url": "https://glasswall.example.com",
            "account_type": "organization",
            "owner": "acme",
            "app_name": "Glasswall",
        },
    )

    assert response.status_code == 200
    payload = response.json()["setup"]
    assert payload["webhook_url"] == "https://glasswall.example.com/github/webhooks"
    assert payload["manifest"]["default_permissions"]["issues"] == "write"
    assert payload["action_url"] == "https://github.com/organizations/acme/settings/apps/new"


def test_github_setup_callback_renders_credentials_from_stub_service(tmp_path) -> None:
    class StubSetupService:
        def build_report(self, **kwargs):
            return GitHubSetupReport(
                public_base_url="https://glasswall.example.com",
                webhook_url="https://glasswall.example.com/github/webhooks",
                redirect_url="https://glasswall.example.com/github/setup/callback",
                setup_url="https://glasswall.example.com/github/setup/complete",
                account_type="personal",
                owner=None,
                app_name="Glasswall",
                public_app=False,
                action_url="https://github.com/settings/apps/new",
                manifest={"name": "Glasswall"},
                checks=(GitHubSetupCheck(name="Public base URL", ok=True, detail="ok"),),
                env_template='GLASSWALL_GITHUB_APP_ID="123"',
            )

        def create_launch(self, **kwargs):
            raise AssertionError("not used")

        async def exchange_manifest_code(self, code: str, state: str):
            report = self.build_report()
            return GitHubAppCredentials(
                app_id="123",
                app_name="Glasswall",
                app_slug="glasswall",
                owner_login="sravan27",
                html_url="https://github.com/settings/apps/glasswall",
                client_id=None,
                client_secret=None,
                webhook_secret="secret",
                pem="-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n",
                install_url="https://github.com/apps/glasswall/installations/new",
                env_snippet='GLASSWALL_GITHUB_APP_ID="123"',
                shell_exports='export GLASSWALL_GITHUB_APP_ID="123"',
                report=report,
            )

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
    client = TestClient(create_app(settings=settings, setup_service=StubSetupService()))

    response = client.get("/github/setup/callback", params={"code": "one-time", "state": "state-token"})

    assert response.status_code == 200
    assert "The GitHub App is real now." in response.text
    assert "GLASSWALL_GITHUB_APP_ID=&#34;123&#34;" in response.text


def test_github_doctor_api_returns_live_diagnostics(tmp_path) -> None:
    class StubDoctorService:
        async def diagnose(self):
            return GitHubDoctorReport(
                generated_at="2026-05-05T11:00:00+00:00",
                configured=True,
                summary="GitHub App mode is alive.",
                expected_public_base_url="https://glasswall.example.com",
                app=GitHubDoctorApp(
                    app_id="123",
                    name="Glasswall",
                    slug="glasswall",
                    description="Patch-gap operations",
                    html_url="https://github.com/settings/apps/glasswall",
                    external_url="https://glasswall.example.com",
                    install_url="https://github.com/apps/glasswall/installations/new",
                    installations_count=1,
                ),
                webhook=GitHubDoctorWebhook(
                    url="https://glasswall.example.com/github/webhooks",
                    content_type="json",
                    insecure_ssl="0",
                    recent_delivery_count=1,
                    recent_success_count=1,
                    recent_failure_count=0,
                    last_delivery_at="2026-05-05T11:00:00Z",
                ),
                checks=(GitHubDoctorCheck(name="Webhook URL", ok=True, detail="ok"),),
                installations=(),
                recent_deliveries=(
                    GitHubDoctorDelivery(
                        delivery_id=7,
                        event="pull_request",
                        action="opened",
                        status="OK",
                        status_code=200,
                        delivered_at="2026-05-05T11:00:00Z",
                        duration_seconds=0.18,
                        redelivery=False,
                        installation_id=99,
                        repository_id=1001,
                    ),
                ),
                total_installation_count=1,
                total_repository_count=2,
            )

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
    client = TestClient(create_app(settings=settings, doctor_service=StubDoctorService()))

    response = client.get("/api/github/doctor")

    assert response.status_code == 200
    payload = response.json()["doctor"]
    assert payload["summary"] == "GitHub App mode is alive."
    assert payload["app"]["slug"] == "glasswall"
    assert payload["recent_deliveries"][0]["status_code"] == 200
