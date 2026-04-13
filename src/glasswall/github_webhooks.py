from __future__ import annotations

from typing import Any

from glasswall.github_app import GitHubAppClient, GitHubRepositoryRef
from glasswall.github_render import COMMENT_MARKER, render_pull_request_comment
from glasswall.service import GlasswallService
from glasswall.settings import Settings


class GitHubWebhookProcessor:
    def __init__(
        self,
        settings: Settings,
        service: GlasswallService | None = None,
        client: GitHubAppClient | None = None,
    ) -> None:
        self.settings = settings
        self.service = service or GlasswallService(settings=settings)
        self.client = client or GitHubAppClient(settings)

    async def handle_event(self, event_name: str, payload: dict[str, Any]) -> None:
        if event_name == "pull_request":
            await self._handle_pull_request(payload)

    async def _handle_pull_request(self, payload: dict[str, Any]) -> None:
        action = payload.get("action")
        if action not in {"opened", "reopened", "synchronize", "ready_for_review"}:
            return
        pull_request = payload.get("pull_request")
        repository = payload.get("repository")
        installation = payload.get("installation")
        if not isinstance(pull_request, dict) or not isinstance(repository, dict) or not isinstance(installation, dict):
            return
        if pull_request.get("draft") is True:
            return

        repo_owner = repository["owner"]["login"]
        repo_name = repository["name"]
        issue_number = int(pull_request["number"])
        ref = pull_request["head"]["sha"]
        installation_id = int(installation["id"])
        head_repo = pull_request.get("head", {}).get("repo") or repository
        source_owner = head_repo["owner"]["login"]
        source_repo = head_repo["name"]

        installation_client = await self.client.create_installation_client(installation_id)
        downloaded = await installation_client.download_repository_zip(
            GitHubRepositoryRef(owner=source_owner, repo=source_repo, ref=ref)
        )

        try:
            scan = await self.service.scan_path(str(downloaded.root))
            plan = await self.service.remediation_planner.build_plan(scan)
            if self.settings.github_comment_mode == "off":
                return
            comment_body = render_pull_request_comment(scan, plan)
            if self.settings.github_comment_mode == "create":
                await installation_client.create_issue_comment(
                    owner=repo_owner,
                    repo=repo_name,
                    issue_number=issue_number,
                    body=comment_body,
                )
                return
            await installation_client.upsert_issue_comment(
                owner=repo_owner,
                repo=repo_name,
                issue_number=issue_number,
                marker=COMMENT_MARKER,
                body=comment_body,
            )
        finally:
            downloaded.cleanup()
