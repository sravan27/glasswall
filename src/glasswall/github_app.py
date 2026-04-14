from __future__ import annotations

import base64
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


@dataclass(frozen=True, slots=True)
class GitHubFileSnapshot:
    path: str
    sha: str
    content: str


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
            "User-Agent": "glasswall/0.4.0",
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

    async def get_repository(self, owner: str, repo: str) -> dict[str, Any]:
        url = f"{self.settings.github_api_base_url}/repos/{owner}/{repo}"
        async with httpx.AsyncClient(timeout=self.settings.request_timeout_seconds) as client:
            response = await client.get(url, headers=self._installation_headers())
            response.raise_for_status()
            return response.json()

    async def get_branch(self, owner: str, repo: str, branch: str) -> dict[str, Any]:
        url = f"{self.settings.github_api_base_url}/repos/{owner}/{repo}/branches/{branch}"
        async with httpx.AsyncClient(timeout=self.settings.request_timeout_seconds) as client:
            response = await client.get(url, headers=self._installation_headers())
            response.raise_for_status()
            return response.json()

    async def ensure_branch(self, owner: str, repo: str, branch: str, base_sha: str) -> None:
        url = f"{self.settings.github_api_base_url}/repos/{owner}/{repo}/git/refs"
        async with httpx.AsyncClient(timeout=self.settings.request_timeout_seconds) as client:
            response = await client.post(
                url,
                headers=self._installation_headers(),
                json={"ref": f"refs/heads/{branch}", "sha": base_sha},
            )
            if response.status_code in {201, 422}:
                return
            response.raise_for_status()

    async def get_file_snapshot(self, owner: str, repo: str, path: str, ref: str) -> GitHubFileSnapshot | None:
        url = f"{self.settings.github_api_base_url}/repos/{owner}/{repo}/contents/{path}"
        async with httpx.AsyncClient(timeout=self.settings.request_timeout_seconds) as client:
            response = await client.get(url, headers=self._installation_headers(), params={"ref": ref})
            if response.status_code == 404:
                return None
            response.raise_for_status()
            payload = response.json()
        encoded = payload.get("content")
        encoding = payload.get("encoding")
        if not isinstance(encoded, str) or encoding != "base64":
            return None
        content = base64.b64decode(encoded.encode("utf-8")).decode("utf-8")
        return GitHubFileSnapshot(path=path, sha=str(payload["sha"]), content=content)

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

    async def update_file_contents(
        self,
        owner: str,
        repo: str,
        path: str,
        content: str,
        message: str,
        branch: str,
        sha: str,
    ) -> dict[str, Any]:
        url = f"{self.settings.github_api_base_url}/repos/{owner}/{repo}/contents/{path}"
        encoded = base64.b64encode(content.encode("utf-8")).decode("utf-8")
        async with httpx.AsyncClient(timeout=self.settings.request_timeout_seconds) as client:
            response = await client.put(
                url,
                headers=self._installation_headers(),
                json={
                    "message": message,
                    "content": encoded,
                    "branch": branch,
                    "sha": sha,
                },
            )
            response.raise_for_status()
            return response.json()

    async def list_pull_requests(
        self,
        owner: str,
        repo: str,
        *,
        state: str = "open",
        head: str | None = None,
        base: str | None = None,
    ) -> list[dict[str, Any]]:
        url = f"{self.settings.github_api_base_url}/repos/{owner}/{repo}/pulls"
        params: dict[str, Any] = {"state": state, "per_page": 100}
        if head:
            params["head"] = head
        if base:
            params["base"] = base
        async with httpx.AsyncClient(timeout=self.settings.request_timeout_seconds) as client:
            response = await client.get(url, headers=self._installation_headers(), params=params)
            response.raise_for_status()
            return response.json()

    async def create_pull_request(
        self,
        owner: str,
        repo: str,
        title: str,
        body: str,
        head: str,
        base: str,
    ) -> dict[str, Any]:
        url = f"{self.settings.github_api_base_url}/repos/{owner}/{repo}/pulls"
        async with httpx.AsyncClient(timeout=self.settings.request_timeout_seconds) as client:
            response = await client.post(
                url,
                headers=self._installation_headers(),
                json={"title": title, "body": body, "head": head, "base": base},
            )
            response.raise_for_status()
            return response.json()

    async def update_pull_request(
        self,
        owner: str,
        repo: str,
        pull_number: int,
        *,
        title: str | None = None,
        body: str | None = None,
    ) -> dict[str, Any]:
        url = f"{self.settings.github_api_base_url}/repos/{owner}/{repo}/pulls/{pull_number}"
        payload: dict[str, Any] = {}
        if title is not None:
            payload["title"] = title
        if body is not None:
            payload["body"] = body
        async with httpx.AsyncClient(timeout=self.settings.request_timeout_seconds) as client:
            response = await client.patch(url, headers=self._installation_headers(), json=payload)
            response.raise_for_status()
            return response.json()

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
    ) -> dict[str, Any]:
        existing = await self.list_pull_requests(
            owner,
            repo,
            state="open",
            head=f"{head_owner}:{head_branch}",
            base=base_branch,
        )
        if existing:
            return await self.update_pull_request(
                owner,
                repo,
                int(existing[0]["number"]),
                title=title,
                body=body,
            )
        return await self.create_pull_request(
            owner,
            repo,
            title=title,
            body=body,
            head=f"{head_owner}:{head_branch}",
            base=base_branch,
        )

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
            "User-Agent": "glasswall/0.4.0",
        }
