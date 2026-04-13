from pathlib import Path

import pytest

from glasswall.github_app import DownloadedRepository, GitHubFileSnapshot
from glasswall.github_webhooks import GitHubWebhookProcessor
from glasswall.models import (
    Dependency,
    RemediationFileChange,
    RemediationPlan,
    RemediationRecommendation,
    RemediationRun,
    ScanResult,
)
from glasswall.settings import Settings


class StubInstallationClient:
    def __init__(self, download: DownloadedRepository) -> None:
        self.download = download
        self.updated_files: list[tuple[str, str, str]] = []
        self.branches: list[tuple[str, str, str]] = []
        self.pull_requests: list[dict[str, str]] = []

    async def download_repository_zip(self, repository) -> DownloadedRepository:
        return self.download

    async def ensure_branch(self, owner: str, repo: str, branch: str, base_sha: str) -> None:
        self.branches.append((owner, repo, branch))

    async def get_file_snapshot(self, owner: str, repo: str, path: str, ref: str) -> GitHubFileSnapshot | None:
        return GitHubFileSnapshot(path=path, sha="abc123", content="requests==2.19.0\n")

    async def update_file_contents(
        self,
        owner: str,
        repo: str,
        path: str,
        content: str,
        message: str,
        branch: str,
        sha: str,
    ) -> dict[str, str]:
        self.updated_files.append((path, content, branch))
        return {"path": path}

    async def upsert_pull_request(
        self,
        owner: str,
        repo: str,
        *,
        title: str,
        body: str,
        head_owner: str,
        head_branch: str,
        base_branch: str,
    ) -> dict[str, str]:
        self.pull_requests.append(
            {
                "title": title,
                "body": body,
                "head_owner": head_owner,
                "head_branch": head_branch,
                "base_branch": base_branch,
            }
        )
        return {"title": title}


class StubAppClient:
    def __init__(self, installation_client: StubInstallationClient) -> None:
        self.installation_client = installation_client

    async def create_installation_client(self, installation_id: int) -> StubInstallationClient:
        return self.installation_client


class StubPlanner:
    def __init__(self, plan: RemediationPlan) -> None:
        self.plan = plan

    async def build_plan(self, scan: ScanResult) -> RemediationPlan:
        return self.plan


class StubApplier:
    def __init__(self, remediation: RemediationRun) -> None:
        self.remediation = remediation

    def apply_plan(self, root: Path, plan: RemediationPlan, *, apply: bool, max_recommendations: int | None):
        return self.remediation


class StubService:
    def __init__(self, scan: ScanResult, plan: RemediationPlan, remediation: RemediationRun) -> None:
        self.scan = scan
        self.remediation_planner = StubPlanner(plan)
        self.remediation_applier = StubApplier(remediation)

    async def scan_path(self, target_path: str) -> ScanResult:
        return self.scan


@pytest.mark.anyio
async def test_push_webhook_creates_remediation_pull_request(tmp_path: Path) -> None:
    project = tmp_path / "repo"
    project.mkdir()
    (project / "requirements.txt").write_text("requests==2.33.0\n")
    downloaded = DownloadedRepository(workspace=tmp_path / "workspace", root=project)
    downloaded.workspace.mkdir()

    dependency = Dependency("PyPI", "requests", "2.19.0", "requirements.txt")
    scan = ScanResult(
        scan_id=None,
        target_path=str(project),
        generated_at="2026-04-13T00:00:00+00:00",
        dependencies=(dependency,),
        findings=(),
        policy_path=None,
    )
    plan = RemediationPlan(
        target_path=str(project),
        generated_at="2026-04-13T00:00:00+00:00",
        policy_path=None,
        recommendations=(
            RemediationRecommendation(
                ecosystem="PyPI",
                name="requests",
                source_file="requirements.txt",
                current_version="2.19.0",
                target_version="2.33.0",
                latest_version="2.33.0",
                latest_published=None,
                registry_url=None,
                repository_url=None,
                rationale=("Upgrade requests.",),
                advisories=("CVE-2026-0001",),
                urgency_label="high",
                urgency_score=50,
                patch_gap=True,
                action="update-pinned-requirement",
            ),
        ),
    )
    remediation = RemediationRun(
        target_path=str(project),
        generated_at="2026-04-13T00:00:00+00:00",
        policy_path=None,
        apply_mode=True,
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
    installation_client = StubInstallationClient(downloaded)
    settings = Settings(
        db_path=str(tmp_path / "glasswall.db"),
        cache_dir=str(tmp_path / "cache"),
        request_timeout_seconds=5,
        osv_query_ttl_seconds=10,
        osv_vuln_ttl_seconds=10,
        kev_ttl_seconds=10,
        max_concurrent_detail_requests=2,
        github_app_id="1",
        github_private_key="key",
        github_webhook_secret="secret",
        github_api_base_url="https://api.github.com",
        github_api_version="2026-03-10",
        github_comment_mode="upsert",
        github_auto_pr_mode="push",
        github_auto_pr_branch="glasswall/remediation",
        github_auto_pr_max_upgrades=2,
        github_auto_pr_commit_message="glasswall remediation",
        github_auto_pr_title="[glasswall] apply top supported patch-gap remediation",
    )
    processor = GitHubWebhookProcessor(
        settings=settings,
        service=StubService(scan, plan, remediation),
        client=StubAppClient(installation_client),
    )

    await processor.handle_event(
        "push",
        {
            "ref": "refs/heads/main",
            "after": "deadbeef",
            "repository": {
                "name": "glasswall",
                "default_branch": "main",
                "owner": {"login": "sravan27"},
            },
            "installation": {"id": 123},
        },
    )

    assert installation_client.branches == [("sravan27", "glasswall", "glasswall/remediation")]
    assert installation_client.updated_files[0][0] == "requirements.txt"
    assert "2.33.0" in installation_client.updated_files[0][1]
    assert installation_client.pull_requests[0]["base_branch"] == "main"
