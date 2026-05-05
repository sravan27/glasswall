from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from glasswall.storage import DEFAULT_DB_PATH


@dataclass(frozen=True, slots=True)
class Settings:
    db_path: str
    cache_dir: str
    request_timeout_seconds: float
    osv_query_ttl_seconds: int
    osv_vuln_ttl_seconds: int
    kev_ttl_seconds: int
    max_concurrent_detail_requests: int
    github_app_id: str | None
    github_private_key: str | None
    github_webhook_secret: str | None
    github_api_base_url: str
    github_api_version: str
    github_comment_mode: str
    github_auto_pr_mode: str
    github_auto_pr_branch: str
    github_auto_pr_max_upgrades: int
    github_auto_pr_commit_message: str
    github_auto_pr_title: str
    github_public_base_url: str | None = None


def load_settings() -> Settings:
    return Settings(
        db_path=os.environ.get("GLASSWALL_DB_PATH", DEFAULT_DB_PATH),
        cache_dir=os.environ.get("GLASSWALL_CACHE_DIR", str(Path.cwd() / ".glasswall-cache")),
        request_timeout_seconds=float(os.environ.get("GLASSWALL_HTTP_TIMEOUT_SECONDS", "20")),
        osv_query_ttl_seconds=int(os.environ.get("GLASSWALL_OSV_QUERY_TTL_SECONDS", "21600")),
        osv_vuln_ttl_seconds=int(os.environ.get("GLASSWALL_OSV_VULN_TTL_SECONDS", "86400")),
        kev_ttl_seconds=int(os.environ.get("GLASSWALL_KEV_TTL_SECONDS", "21600")),
        max_concurrent_detail_requests=int(os.environ.get("GLASSWALL_MAX_DETAIL_REQUESTS", "8")),
        github_app_id=os.environ.get("GLASSWALL_GITHUB_APP_ID"),
        github_private_key=os.environ.get("GLASSWALL_GITHUB_PRIVATE_KEY"),
        github_webhook_secret=os.environ.get("GLASSWALL_GITHUB_WEBHOOK_SECRET"),
        github_api_base_url=os.environ.get("GLASSWALL_GITHUB_API_BASE_URL", "https://api.github.com"),
        github_api_version=os.environ.get("GLASSWALL_GITHUB_API_VERSION", "2026-03-10"),
        github_comment_mode=os.environ.get("GLASSWALL_GITHUB_COMMENT_MODE", "upsert"),
        github_auto_pr_mode=os.environ.get("GLASSWALL_GITHUB_AUTO_PR_MODE", "off"),
        github_auto_pr_branch=os.environ.get("GLASSWALL_GITHUB_AUTO_PR_BRANCH", "glasswall/remediation"),
        github_auto_pr_max_upgrades=int(os.environ.get("GLASSWALL_GITHUB_AUTO_PR_MAX_UPGRADES", "3")),
        github_auto_pr_commit_message=os.environ.get(
            "GLASSWALL_GITHUB_AUTO_PR_COMMIT_MESSAGE",
            "glasswall remediation",
        ),
        github_auto_pr_title=os.environ.get(
            "GLASSWALL_GITHUB_AUTO_PR_TITLE",
            "[glasswall] apply top supported patch-gap remediation",
        ),
        github_public_base_url=os.environ.get("GLASSWALL_PUBLIC_BASE_URL"),
    )
