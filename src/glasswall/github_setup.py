from __future__ import annotations

import json
import secrets
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse

import httpx

from glasswall.github_app import GitHubAppAuth
from glasswall.settings import Settings

RECOMMENDED_EVENTS = ("pull_request", "push")
RECOMMENDED_PERMISSIONS = {
    "contents": "write",
    "issues": "write",
    "pull_requests": "write",
}


@dataclass(frozen=True, slots=True)
class GitHubSetupCheck:
    name: str
    ok: bool
    detail: str
    severity: str = "required"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class GitHubSetupReport:
    public_base_url: str | None
    webhook_url: str | None
    redirect_url: str | None
    setup_url: str | None
    account_type: str
    owner: str | None
    app_name: str
    public_app: bool
    action_url: str | None
    manifest: dict[str, Any] | None
    checks: tuple[GitHubSetupCheck, ...]
    env_template: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "public_base_url": self.public_base_url,
            "webhook_url": self.webhook_url,
            "redirect_url": self.redirect_url,
            "setup_url": self.setup_url,
            "account_type": self.account_type,
            "owner": self.owner,
            "app_name": self.app_name,
            "public_app": self.public_app,
            "action_url": self.action_url,
            "manifest": self.manifest,
            "checks": [check.to_dict() for check in self.checks],
            "env_template": self.env_template,
        }


@dataclass(frozen=True, slots=True)
class GitHubManifestLaunch:
    action_url: str
    manifest_json: str
    state: str
    expires_at: str
    report: GitHubSetupReport

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["report"] = self.report.to_dict()
        return payload


@dataclass(frozen=True, slots=True)
class GitHubAppCredentials:
    app_id: str
    app_name: str | None
    app_slug: str | None
    owner_login: str | None
    html_url: str | None
    client_id: str | None
    client_secret: str | None
    webhook_secret: str
    pem: str
    install_url: str | None
    env_snippet: str
    shell_exports: str
    report: GitHubSetupReport

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["report"] = self.report.to_dict()
        return payload


@dataclass(slots=True)
class _SetupState:
    report: GitHubSetupReport
    expires_at: datetime


class GitHubSetupService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._states: dict[str, _SetupState] = {}

    def build_report(
        self,
        *,
        public_base_url: str | None,
        account_type: str = "personal",
        owner: str | None = None,
        app_name: str = "Glasswall Patch Gap Ops",
        public_app: bool = False,
    ) -> GitHubSetupReport:
        normalized_base_url = _normalize_public_base_url(public_base_url)
        normalized_account_type = _normalize_account_type(account_type)
        normalized_owner = owner.strip() if owner else None
        if normalized_account_type == "organization" and not normalized_owner:
            action_url = None
        else:
            action_url = _build_action_url(normalized_account_type, normalized_owner)

        manifest = None
        webhook_url = None
        redirect_url = None
        setup_url = None
        if normalized_base_url is not None:
            webhook_url = f"{normalized_base_url}/github/webhooks"
            redirect_url = f"{normalized_base_url}/github/setup/callback"
            setup_url = f"{normalized_base_url}/github/setup/complete"
            manifest = {
                "name": app_name,
                "url": normalized_base_url,
                "hook_attributes": {
                    "url": webhook_url,
                    "active": True,
                },
                "redirect_url": redirect_url,
                "callback_urls": [setup_url],
                "setup_url": setup_url,
                "description": "GitHub-native patch-gap operations: scan, remediate, and compress time-to-patch after public fixes.",
                "public": public_app,
                "default_events": list(RECOMMENDED_EVENTS),
                "default_permissions": dict(RECOMMENDED_PERMISSIONS),
                "request_oauth_on_install": False,
                "setup_on_update": False,
            }

        checks = self._build_checks(
            normalized_base_url=normalized_base_url,
            account_type=normalized_account_type,
            owner=normalized_owner,
        )
        return GitHubSetupReport(
            public_base_url=normalized_base_url,
            webhook_url=webhook_url,
            redirect_url=redirect_url,
            setup_url=setup_url,
            account_type=normalized_account_type,
            owner=normalized_owner,
            app_name=app_name,
            public_app=public_app,
            action_url=action_url,
            manifest=manifest,
            checks=checks,
            env_template=_env_template(),
        )

    def create_launch(
        self,
        *,
        public_base_url: str,
        account_type: str = "personal",
        owner: str | None = None,
        app_name: str = "Glasswall Patch Gap Ops",
        public_app: bool = False,
    ) -> GitHubManifestLaunch:
        report = self.build_report(
            public_base_url=public_base_url,
            account_type=account_type,
            owner=owner,
            app_name=app_name,
            public_app=public_app,
        )
        if report.manifest is None or report.action_url is None:
            raise ValueError("A public base URL and valid GitHub account target are required.")

        expires_at = datetime.now(UTC) + timedelta(minutes=55)
        state = secrets.token_urlsafe(24)
        self._states[state] = _SetupState(report=report, expires_at=expires_at)
        return GitHubManifestLaunch(
            action_url=f"{report.action_url}?state={state}",
            manifest_json=json.dumps(report.manifest),
            state=state,
            expires_at=expires_at.replace(microsecond=0).isoformat(),
            report=report,
        )

    async def exchange_manifest_code(self, code: str, state: str) -> GitHubAppCredentials:
        setup_state = self._consume_state(state)
        if setup_state is None:
            raise ValueError("Setup state is missing or expired. Start the GitHub App registration again.")

        async with httpx.AsyncClient(timeout=self.settings.request_timeout_seconds) as client:
            response = await client.post(
                f"{self.settings.github_api_base_url}/app-manifests/{code}/conversions",
                headers={
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": self.settings.github_api_version,
                    "User-Agent": "glasswall/0.4.0",
                },
            )
            response.raise_for_status()
            payload = response.json()

        app_id = str(payload["id"])
        pem = str(payload["pem"])
        webhook_secret = str(payload["webhook_secret"])
        app_slug = _optional_str(payload.get("slug"))
        html_url = _optional_str(payload.get("html_url"))
        install_url = f"https://github.com/apps/{app_slug}/installations/new" if app_slug else None
        return GitHubAppCredentials(
            app_id=app_id,
            app_name=_optional_str(payload.get("name")),
            app_slug=app_slug,
            owner_login=_optional_str((payload.get("owner") or {}).get("login") if isinstance(payload.get("owner"), dict) else None),
            html_url=html_url,
            client_id=_optional_str(payload.get("client_id")),
            client_secret=_optional_str(payload.get("client_secret")),
            webhook_secret=webhook_secret,
            pem=pem,
            install_url=install_url,
            env_snippet=_env_snippet(app_id=app_id, webhook_secret=webhook_secret, pem=pem),
            shell_exports=_shell_exports(app_id=app_id, webhook_secret=webhook_secret, pem=pem),
            report=setup_state.report,
        )

    def _build_checks(
        self,
        *,
        normalized_base_url: str | None,
        account_type: str,
        owner: str | None,
    ) -> tuple[GitHubSetupCheck, ...]:
        checks: list[GitHubSetupCheck] = []

        if normalized_base_url is None:
            checks.append(
                GitHubSetupCheck(
                    name="Public base URL",
                    ok=False,
                    detail="Provide an externally reachable base URL. GitHub cannot complete webhooks or callbacks against localhost.",
                )
            )
        else:
            host = urlparse(normalized_base_url).hostname or ""
            if host in {"localhost", "127.0.0.1", "0.0.0.0"}:
                checks.append(
                    GitHubSetupCheck(
                        name="Public base URL",
                        ok=False,
                        detail="The current base URL resolves to localhost. Use an HTTPS tunnel or public deployment URL.",
                    )
                )
            else:
                checks.append(
                    GitHubSetupCheck(
                        name="Public base URL",
                        ok=True,
                        detail=f"GitHub can target {normalized_base_url} for manifest callback and webhook delivery.",
                    )
                )

        if account_type == "organization" and not owner:
            checks.append(
                GitHubSetupCheck(
                    name="Organization target",
                    ok=False,
                    detail="Organization registration requires the organization slug.",
                )
            )
        else:
            checks.append(
                GitHubSetupCheck(
                    name="Registration target",
                    ok=True,
                    detail="Manifest flow is ready for a personal account."
                    if account_type == "personal"
                    else f"Manifest flow is ready for organization `{owner}`.",
                )
            )

        if self.settings.github_app_id and self.settings.github_private_key and self.settings.github_webhook_secret:
            try:
                GitHubAppAuth(self.settings).create_jwt()
            except Exception:
                checks.append(
                    GitHubSetupCheck(
                        name="Installed credentials",
                        ok=False,
                        detail="GitHub App credentials are present but the private key does not validate as a usable JWT signer.",
                    )
                )
            else:
                checks.append(
                    GitHubSetupCheck(
                        name="Installed credentials",
                        ok=True,
                        detail="GitHub App credentials are already configured and the private key validates.",
                    )
                )
        else:
            checks.append(
                GitHubSetupCheck(
                    name="Installed credentials",
                    ok=False,
                    detail="GitHub App credentials are not configured yet. The manifest flow can generate them for you.",
                )
            )

        checks.append(
            GitHubSetupCheck(
                name="Comment mode",
                ok=self.settings.github_comment_mode != "off",
                detail=(
                    f"Comment mode is `{self.settings.github_comment_mode}`."
                    if self.settings.github_comment_mode != "off"
                    else "Comment mode is off. PR visibility will stay local until you enable `GLASSWALL_GITHUB_COMMENT_MODE`."
                ),
                severity="recommended",
            )
        )
        checks.append(
            GitHubSetupCheck(
                name="Auto remediation PRs",
                ok=self.settings.github_auto_pr_mode == "push",
                detail=(
                    f"Auto remediation PR mode is `{self.settings.github_auto_pr_mode}`."
                    if self.settings.github_auto_pr_mode == "push"
                    else "Auto remediation PR mode is off. Enable `GLASSWALL_GITHUB_AUTO_PR_MODE=push` when you want Glasswall to open remediation branches automatically."
                ),
                severity="recommended",
            )
        )
        return tuple(checks)

    def _consume_state(self, state: str) -> _SetupState | None:
        now = datetime.now(UTC)
        expired = [token for token, entry in self._states.items() if entry.expires_at <= now]
        for token in expired:
            self._states.pop(token, None)
        entry = self._states.pop(state, None)
        if entry is None or entry.expires_at <= now:
            return None
        return entry


def _normalize_public_base_url(value: str | None) -> str | None:
    if value is None:
        return None
    trimmed = value.strip().rstrip("/")
    if not trimmed:
        return None
    parsed = urlparse(trimmed)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Public base URL must be a full http(s) URL.")
    return trimmed


def _normalize_account_type(value: str) -> str:
    normalized = value.strip().lower()
    if normalized not in {"personal", "organization"}:
        raise ValueError("Account type must be `personal` or `organization`.")
    return normalized


def _build_action_url(account_type: str, owner: str | None) -> str:
    if account_type == "organization":
        if not owner:
            raise ValueError("Organization registration requires an owner.")
        return f"https://github.com/organizations/{owner}/settings/apps/new"
    return "https://github.com/settings/apps/new"


def _env_template() -> str:
    return "\n".join(
        [
            'GLASSWALL_GITHUB_APP_ID="your-app-id"',
            'GLASSWALL_GITHUB_WEBHOOK_SECRET="your-webhook-secret"',
            'GLASSWALL_GITHUB_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----\\n"',
            'GLASSWALL_GITHUB_COMMENT_MODE="upsert"',
            'GLASSWALL_GITHUB_AUTO_PR_MODE="push"',
        ]
    )


def _env_snippet(*, app_id: str, webhook_secret: str, pem: str) -> str:
    escaped_pem = pem.replace("\\", "\\\\").replace("\n", "\\n")
    return "\n".join(
        [
            f'GLASSWALL_GITHUB_APP_ID="{app_id}"',
            f'GLASSWALL_GITHUB_WEBHOOK_SECRET="{webhook_secret}"',
            f'GLASSWALL_GITHUB_PRIVATE_KEY="{escaped_pem}"',
        ]
    )


def _shell_exports(*, app_id: str, webhook_secret: str, pem: str) -> str:
    return "\n".join(
        [
            f'export GLASSWALL_GITHUB_APP_ID="{app_id}"',
            f'export GLASSWALL_GITHUB_WEBHOOK_SECRET="{webhook_secret}"',
            "export GLASSWALL_GITHUB_PRIVATE_KEY=\"$(cat <<'EOF'",
            pem,
            "EOF",
            ')\"',
        ]
    )


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
