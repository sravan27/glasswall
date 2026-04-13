from __future__ import annotations

import hashlib
import hmac
import io
import shutil
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import jwt

from glasswall.settings import Settings


@dataclass(frozen=True, slots=True)
class GitHubRepositoryRef:
    owner: str
    repo: str
    ref: str


@dataclass(frozen=True, slots=True)
class DownloadedRepository:
    workspace: Path
    root: Path

    def cleanup(self) -> None:
        shutil.rmtree(self.workspace, ignore_errors=True)


class GitHubWebhookVerifier:
    def __init__(self, secret: str) -> None:
        self.secret = secret.encode("utf-8")

    def verify(self, body: bytes, signature_header: str | None) -> bool:
        if not signature_header or not signature_header.startswith("sha256="):
            return False
        expected = hmac.new(self.secret, body, hashlib.sha256).hexdigest()
        provided = signature_header.split("=", 1)[1]
        return hmac.compare_digest(expected, provided)


class GitHubAppAuth:
    def __init__(self, settings: Settings) -> None:
        if not settings.github_app_id or not settings.github_private_key:
            raise ValueError("GitHub App credentials are not configured")
        self.settings = settings

    def create_jwt(self) -> str:
        now = datetime.now(UTC)
        payload = {
            "iat": int((now - timedelta(seconds=60)).timestamp()),
            "exp": int((now + timedelta(minutes=9)).timestamp()),
            "iss": self.settings.github_app_id,
        }
        return jwt.encode(payload, self.settings.github_private_key, algorithm="RS256")


class GitHubAppClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.auth = GitHubAppAuth(settings)

    async def create_installation_client(self, installation_id: int) -> "GitHubInstallationClient":
        async with httpx.AsyncClient(timeout=self.settings.request_timeout_seconds) as client:
            response = await client.post(
                f"{self.settings.github_api_base_url}/app/installations/{installation_id}/access_tokens",
                headers=self._app_headers(),
            )
            response.raise_for_status()
            token = response.json()["token"]
        return GitHubInstallationClient(self.settings, token)

    def _app_headers(self) -> dict[str, str]:
        return {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.auth.create_jwt()}",
            "X-GitHub-Api-Version": self.settings.github_api_version,
            "User-Agent": "glasswall/0.1.0",
        }


class GitHubInstallationClient:
    def __init__(self, settings: Settings, token: str) -> None:
        self.settings = settings
        self.token = token

    async def download_repository_zip(self, repository: GitHubRepositoryRef) -> DownloadedRepository:
        archive_url = (
            f"{self.settings.github_api_base_url}/repos/{repository.owner}/{repository.repo}/zipball/{repository.ref}"
        )
        async with httpx.AsyncClient(timeout=self.settings.request_timeout_seconds, follow_redirects=True) as client:
            response = await client.get(archive_url, headers=self._installation_headers())
            response.raise_for_status()
            temp_root = Path(tempfile.mkdtemp(prefix="glasswall-github-"))
            with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
                archive.extractall(temp_root)
            children = [child for child in temp_root.iterdir() if child.is_dir()]
            repo_root = children[0] if children else temp_root
            return DownloadedRepository(workspace=temp_root, root=repo_root)

    async def list_issue_comments(self, owner: str, repo: str, issue_number: int) -> list[dict[str, Any]]:
        url = f"{self.settings.github_api_base_url}/repos/{owner}/{repo}/issues/{issue_number}/comments"
        async with httpx.AsyncClient(timeout=self.settings.request_timeout_seconds) as client:
            response = await client.get(url, headers=self._installation_headers(), params={"per_page": 100})
            response.raise_for_status()
            return response.json()

    async def create_issue_comment(self, owner: str, repo: str, issue_number: int, body: str) -> dict[str, Any]:
        url = f"{self.settings.github_api_base_url}/repos/{owner}/{repo}/issues/{issue_number}/comments"
        async with httpx.AsyncClient(timeout=self.settings.request_timeout_seconds) as client:
            response = await client.post(url, headers=self._installation_headers(), json={"body": body})
            response.raise_for_status()
            return response.json()

    async def update_issue_comment(self, owner: str, repo: str, comment_id: int, body: str) -> dict[str, Any]:
        url = f"{self.settings.github_api_base_url}/repos/{owner}/{repo}/issues/comments/{comment_id}"
        async with httpx.AsyncClient(timeout=self.settings.request_timeout_seconds) as client:
            response = await client.patch(url, headers=self._installation_headers(), json={"body": body})
            response.raise_for_status()
            return response.json()

    async def upsert_issue_comment(
        self,
        owner: str,
        repo: str,
        issue_number: int,
        marker: str,
        body: str,
    ) -> dict[str, Any]:
        comments = await self.list_issue_comments(owner, repo, issue_number)
        existing = next((comment for comment in comments if marker in str(comment.get("body", ""))), None)
        if existing is None:
            return await self.create_issue_comment(owner, repo, issue_number, body)
        return await self.update_issue_comment(owner, repo, int(existing["id"]), body)

    def _installation_headers(self) -> dict[str, str]:
        return {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.token}",
            "X-GitHub-Api-Version": self.settings.github_api_version,
            "User-Agent": "glasswall/0.1.0",
        }
