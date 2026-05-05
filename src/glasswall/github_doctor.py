from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

import httpx

from glasswall.github_app import GitHubAppClient
from glasswall.settings import Settings

REQUIRED_EVENTS = ("pull_request", "push")
REQUIRED_PERMISSIONS = {
    "contents": "write",
    "issues": "write",
    "pull_requests": "write",
}
MAX_INSTALLATIONS = 8
MAX_REPOSITORIES_PER_INSTALLATION = 8
MAX_DELIVERIES = 10


@dataclass(frozen=True, slots=True)
class GitHubDoctorCheck:
    name: str
    ok: bool
    detail: str
    severity: str = "required"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class GitHubDoctorRepository:
    full_name: str
    private: bool
    default_branch: str | None
    html_url: str | None
    permissions: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class GitHubDoctorInstallation:
    installation_id: int
    account_login: str | None
    account_type: str | None
    repository_selection: str
    suspended: bool
    html_url: str | None
    events: tuple[str, ...]
    permissions: dict[str, str]
    missing_events: tuple[str, ...]
    permission_gaps: tuple[str, ...]
    repository_count: int
    repositories: tuple[GitHubDoctorRepository, ...]
    error: str | None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["repositories"] = [repository.to_dict() for repository in self.repositories]
        return payload


@dataclass(frozen=True, slots=True)
class GitHubDoctorDelivery:
    delivery_id: int
    event: str
    action: str | None
    status: str | None
    status_code: int | None
    delivered_at: str | None
    duration_seconds: float | None
    redelivery: bool
    installation_id: int | None
    repository_id: int | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class GitHubDoctorWebhook:
    url: str | None
    content_type: str | None
    insecure_ssl: str | None
    recent_delivery_count: int
    recent_success_count: int
    recent_failure_count: int
    last_delivery_at: str | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class GitHubDoctorApp:
    app_id: str
    name: str | None
    slug: str | None
    description: str | None
    html_url: str | None
    external_url: str | None
    install_url: str | None
    installations_count: int | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class GitHubDoctorReport:
    generated_at: str
    configured: bool
    summary: str
    expected_public_base_url: str | None
    app: GitHubDoctorApp | None
    webhook: GitHubDoctorWebhook | None
    checks: tuple[GitHubDoctorCheck, ...]
    installations: tuple[GitHubDoctorInstallation, ...]
    recent_deliveries: tuple[GitHubDoctorDelivery, ...]
    total_installation_count: int
    total_repository_count: int
    api_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "configured": self.configured,
            "summary": self.summary,
            "expected_public_base_url": self.expected_public_base_url,
            "app": self.app.to_dict() if self.app else None,
            "webhook": self.webhook.to_dict() if self.webhook else None,
            "checks": [check.to_dict() for check in self.checks],
            "installations": [installation.to_dict() for installation in self.installations],
            "recent_deliveries": [delivery.to_dict() for delivery in self.recent_deliveries],
            "total_installation_count": self.total_installation_count,
            "total_repository_count": self.total_repository_count,
            "api_error": self.api_error,
        }


class GitHubDoctorService:
    def __init__(self, settings: Settings, client: GitHubAppClient | None = None) -> None:
        self.settings = settings
        self._client = client

    async def diagnose(self) -> GitHubDoctorReport:
        generated_at = datetime.now(UTC).replace(microsecond=0).isoformat()
        expected_public_base_url = _normalize_public_base_url(self.settings.github_public_base_url)
        checks = [self._credentials_check()]
        if not checks[0].ok:
            checks.append(
                GitHubDoctorCheck(
                    name="GitHub API authentication",
                    ok=False,
                    detail="Configure GitHub App credentials before Glasswall can verify live installations or webhook traffic.",
                    severity="required",
                )
            )
            return GitHubDoctorReport(
                generated_at=generated_at,
                configured=False,
                summary="GitHub App credentials are missing, so Glasswall is still running in local-first mode.",
                expected_public_base_url=expected_public_base_url,
                app=None,
                webhook=None,
                checks=tuple(checks),
                installations=(),
                recent_deliveries=(),
                total_installation_count=0,
                total_repository_count=0,
            )

        try:
            app_payload, webhook_payload, delivery_payloads, installation_payloads = await asyncio.gather(
                self.client.get_authenticated_app(),
                self.client.get_webhook_config(),
                self.client.list_webhook_deliveries(per_page=MAX_DELIVERIES),
                self.client.list_installations(per_page=MAX_INSTALLATIONS),
            )
        except (ValueError, httpx.HTTPError) as exc:
            checks.append(
                GitHubDoctorCheck(
                    name="GitHub API authentication",
                    ok=False,
                    detail=f"GitHub rejected the configured app credentials: {exc}",
                    severity="required",
                )
            )
            return GitHubDoctorReport(
                generated_at=generated_at,
                configured=True,
                summary="GitHub App credentials are present, but GitHub did not accept them.",
                expected_public_base_url=expected_public_base_url,
                app=None,
                webhook=None,
                checks=tuple(checks),
                installations=(),
                recent_deliveries=(),
                total_installation_count=0,
                total_repository_count=0,
                api_error=str(exc),
            )

        app = _build_app(app_payload)
        deliveries = tuple(_build_delivery(item) for item in delivery_payloads[:MAX_DELIVERIES])
        webhook = _build_webhook(webhook_payload, deliveries)
        installations = tuple(
            await asyncio.gather(
                *(
                    self._build_installation(item)
                    for item in installation_payloads[:MAX_INSTALLATIONS]
                )
            )
        )

        total_installation_count = int(app.installations_count or len(installations))
        total_repository_count = sum(installation.repository_count for installation in installations)
        checks.extend(
            [
                GitHubDoctorCheck(
                    name="GitHub API authentication",
                    ok=True,
                    detail=f"Authenticated as GitHub App `{app.slug or app.name or app.app_id}`.",
                ),
                self._webhook_url_check(webhook),
                self._public_base_alignment_check(expected_public_base_url, webhook),
                self._installation_check(total_installation_count),
                self._repository_check(total_repository_count),
                self._event_coverage_check(installations),
                self._permission_check(installations),
                self._delivery_activity_check(deliveries),
                self._delivery_outcome_check(deliveries),
            ]
        )

        return GitHubDoctorReport(
            generated_at=generated_at,
            configured=True,
            summary=_build_summary(
                total_installation_count=total_installation_count,
                total_repository_count=total_repository_count,
                recent_deliveries=deliveries,
                checks=tuple(checks),
            ),
            expected_public_base_url=expected_public_base_url,
            app=app,
            webhook=webhook,
            checks=tuple(checks),
            installations=installations,
            recent_deliveries=deliveries,
            total_installation_count=total_installation_count,
            total_repository_count=total_repository_count,
        )

    async def _build_installation(self, payload: dict[str, Any]) -> GitHubDoctorInstallation:
        installation_id = int(payload["id"])
        events = tuple(str(event) for event in payload.get("events") or ())
        permissions = {
            str(name): str(level)
            for name, level in (payload.get("permissions") or {}).items()
            if level is not None
        }
        missing_events = tuple(event for event in REQUIRED_EVENTS if event not in events)
        permission_gaps = tuple(
            f"{name}={permissions.get(name, 'missing')} (need {required})"
            for name, required in REQUIRED_PERMISSIONS.items()
            if permissions.get(name) != required
        )
        repositories: tuple[GitHubDoctorRepository, ...] = ()
        repository_count = 0
        error = None
        try:
            installation_client = await self.client.create_installation_client(installation_id)
            repository_payload = await installation_client.list_repositories(per_page=MAX_REPOSITORIES_PER_INSTALLATION)
            repository_items = repository_payload.get("repositories") or ()
            repository_count = int(repository_payload.get("total_count", len(repository_items)))
            repositories = tuple(_build_repository(item) for item in repository_items[:MAX_REPOSITORIES_PER_INSTALLATION])
        except httpx.HTTPError as exc:
            error = f"Unable to inspect installation repositories: {exc}"

        account = payload.get("account") if isinstance(payload.get("account"), dict) else {}
        return GitHubDoctorInstallation(
            installation_id=installation_id,
            account_login=_optional_str(account.get("login")),
            account_type=_optional_str(account.get("type")),
            repository_selection=str(payload.get("repository_selection") or "unknown"),
            suspended=payload.get("suspended_at") is not None,
            html_url=_optional_str(payload.get("html_url")),
            events=events,
            permissions=permissions,
            missing_events=missing_events,
            permission_gaps=permission_gaps,
            repository_count=repository_count,
            repositories=repositories,
            error=error,
        )

    def _credentials_check(self) -> GitHubDoctorCheck:
        missing: list[str] = []
        if not self.settings.github_app_id:
            missing.append("GLASSWALL_GITHUB_APP_ID")
        if not self.settings.github_private_key:
            missing.append("GLASSWALL_GITHUB_PRIVATE_KEY")
        if not self.settings.github_webhook_secret:
            missing.append("GLASSWALL_GITHUB_WEBHOOK_SECRET")
        if missing:
            return GitHubDoctorCheck(
                name="GitHub App credentials",
                ok=False,
                detail=f"Missing required environment variables: {', '.join(missing)}.",
                severity="required",
            )
        return GitHubDoctorCheck(
            name="GitHub App credentials",
            ok=True,
            detail="App ID, private key, and webhook secret are configured.",
        )

    def _webhook_url_check(self, webhook: GitHubDoctorWebhook) -> GitHubDoctorCheck:
        if not webhook.url:
            return GitHubDoctorCheck(
                name="Webhook URL",
                ok=False,
                detail="The GitHub App webhook URL is empty.",
                severity="required",
            )
        if not webhook.url.startswith("https://"):
            return GitHubDoctorCheck(
                name="Webhook URL",
                ok=False,
                detail=f"Webhook URL `{webhook.url}` is not HTTPS.",
                severity="required",
            )
        return GitHubDoctorCheck(
            name="Webhook URL",
            ok=True,
            detail=f"GitHub will deliver events to `{webhook.url}`.",
        )

    def _public_base_alignment_check(
        self,
        expected_public_base_url: str | None,
        webhook: GitHubDoctorWebhook,
    ) -> GitHubDoctorCheck:
        if expected_public_base_url is None:
            return GitHubDoctorCheck(
                name="Public base URL",
                ok=False,
                detail="Set `GLASSWALL_PUBLIC_BASE_URL` so Glasswall can detect webhook drift and render setup links consistently.",
                severity="recommended",
            )
        expected_webhook_url = f"{expected_public_base_url}/github/webhooks"
        if webhook.url != expected_webhook_url:
            return GitHubDoctorCheck(
                name="Public base URL",
                ok=False,
                detail=f"Expected webhook URL `{expected_webhook_url}`, but GitHub is configured for `{webhook.url or 'missing'}`.",
                severity="warning",
            )
        return GitHubDoctorCheck(
            name="Public base URL",
            ok=True,
            detail=f"Webhook URL matches `GLASSWALL_PUBLIC_BASE_URL` at `{expected_public_base_url}`.",
        )

    def _installation_check(self, total_installation_count: int) -> GitHubDoctorCheck:
        if total_installation_count <= 0:
            return GitHubDoctorCheck(
                name="Installations",
                ok=False,
                detail="The app is authenticated, but it is not installed on any GitHub account or repository yet.",
                severity="required",
            )
        return GitHubDoctorCheck(
            name="Installations",
            ok=True,
            detail=f"GitHub reports {total_installation_count} installation(s) for this app.",
        )

    def _repository_check(self, total_repository_count: int) -> GitHubDoctorCheck:
        if total_repository_count <= 0:
            return GitHubDoctorCheck(
                name="Repository coverage",
                ok=False,
                detail="No repositories are currently accessible to the app installations Glasswall inspected.",
                severity="warning",
            )
        return GitHubDoctorCheck(
            name="Repository coverage",
            ok=True,
            detail=f"Glasswall can inspect {total_repository_count} repository target(s) through current installations.",
        )

    def _event_coverage_check(self, installations: tuple[GitHubDoctorInstallation, ...]) -> GitHubDoctorCheck:
        if not installations:
            return GitHubDoctorCheck(
                name="Required events",
                ok=False,
                detail="Install the app first so Glasswall can verify `pull_request` and `push` event coverage.",
                severity="recommended",
            )
        incomplete = [installation for installation in installations if installation.missing_events]
        if incomplete:
            details = ", ".join(
                f"{installation.account_login or installation.installation_id}: {', '.join(installation.missing_events)}"
                for installation in incomplete
            )
            return GitHubDoctorCheck(
                name="Required events",
                ok=False,
                detail=f"Some installations are missing required GitHub events: {details}.",
                severity="warning",
            )
        return GitHubDoctorCheck(
            name="Required events",
            ok=True,
            detail="All inspected installations include `pull_request` and `push` events.",
        )

    def _permission_check(self, installations: tuple[GitHubDoctorInstallation, ...]) -> GitHubDoctorCheck:
        if not installations:
            return GitHubDoctorCheck(
                name="Required permissions",
                ok=False,
                detail="Install the app first so Glasswall can verify repository permissions.",
                severity="recommended",
            )
        degraded = [installation for installation in installations if installation.permission_gaps]
        if degraded:
            details = ", ".join(
                f"{installation.account_login or installation.installation_id}: {', '.join(installation.permission_gaps)}"
                for installation in degraded
            )
            return GitHubDoctorCheck(
                name="Required permissions",
                ok=False,
                detail=f"Some installations do not expose the permissions Glasswall expects: {details}.",
                severity="warning",
            )
        return GitHubDoctorCheck(
            name="Required permissions",
            ok=True,
            detail="All inspected installations expose the write permissions Glasswall uses for comments and remediation PRs.",
        )

    def _delivery_activity_check(self, deliveries: tuple[GitHubDoctorDelivery, ...]) -> GitHubDoctorCheck:
        if not deliveries:
            return GitHubDoctorCheck(
                name="Webhook traffic",
                ok=False,
                detail="GitHub has not delivered any recent webhook events to this app yet.",
                severity="recommended",
            )
        latest = deliveries[0].delivered_at or "unknown"
        return GitHubDoctorCheck(
            name="Webhook traffic",
            ok=True,
            detail=f"GitHub recorded {len(deliveries)} recent delivery attempt(s). Latest delivery: {latest}.",
        )

    def _delivery_outcome_check(self, deliveries: tuple[GitHubDoctorDelivery, ...]) -> GitHubDoctorCheck:
        if not deliveries:
            return GitHubDoctorCheck(
                name="Webhook outcomes",
                ok=False,
                detail="There are no webhook deliveries yet, so Glasswall cannot verify end-to-end processing.",
                severity="recommended",
            )
        failures = [delivery for delivery in deliveries if _is_failure(delivery.status_code)]
        if failures:
            latest_failure = failures[0]
            return GitHubDoctorCheck(
                name="Webhook outcomes",
                ok=False,
                detail=(
                    f"{len(failures)} recent delivery attempt(s) failed. "
                    f"Latest failure: event `{latest_failure.event}` status `{latest_failure.status_code or 'unknown'}`."
                ),
                severity="warning",
            )
        return GitHubDoctorCheck(
            name="Webhook outcomes",
            ok=True,
            detail="Recent webhook deliveries completed without GitHub-side failures.",
        )

    @property
    def client(self) -> GitHubAppClient:
        if self._client is None:
            self._client = GitHubAppClient(self.settings)
        return self._client


def _build_app(payload: dict[str, Any]) -> GitHubDoctorApp:
    app_id = payload.get("id")
    slug = _optional_str(payload.get("slug"))
    install_url = f"https://github.com/apps/{slug}/installations/new" if slug else None
    return GitHubDoctorApp(
        app_id=str(app_id),
        name=_optional_str(payload.get("name")),
        slug=slug,
        description=_optional_str(payload.get("description")),
        html_url=_optional_str(payload.get("html_url")),
        external_url=_optional_str(payload.get("external_url")),
        install_url=install_url,
        installations_count=_optional_int(payload.get("installations_count")),
    )


def _build_repository(payload: dict[str, Any]) -> GitHubDoctorRepository:
    permissions = {
        str(name): str(level)
        for name, level in (payload.get("permissions") or {}).items()
        if level is not None
    }
    return GitHubDoctorRepository(
        full_name=str(payload.get("full_name") or payload.get("name") or "unknown"),
        private=bool(payload.get("private")),
        default_branch=_optional_str(payload.get("default_branch")),
        html_url=_optional_str(payload.get("html_url")),
        permissions=permissions,
    )


def _build_delivery(payload: dict[str, Any]) -> GitHubDoctorDelivery:
    return GitHubDoctorDelivery(
        delivery_id=int(payload["id"]),
        event=str(payload.get("event") or "unknown"),
        action=_optional_str(payload.get("action")),
        status=_optional_str(payload.get("status")),
        status_code=_optional_int(payload.get("status_code")),
        delivered_at=_optional_str(payload.get("delivered_at")),
        duration_seconds=_optional_float(payload.get("duration")),
        redelivery=bool(payload.get("redelivery")),
        installation_id=_optional_int(payload.get("installation_id")),
        repository_id=_optional_int(payload.get("repository_id")),
    )


def _build_webhook(
    payload: dict[str, Any],
    deliveries: tuple[GitHubDoctorDelivery, ...],
) -> GitHubDoctorWebhook:
    failures = sum(1 for delivery in deliveries if _is_failure(delivery.status_code))
    successes = sum(1 for delivery in deliveries if _is_success(delivery.status_code))
    return GitHubDoctorWebhook(
        url=_optional_str(payload.get("url")),
        content_type=_optional_str(payload.get("content_type")),
        insecure_ssl=_optional_str(payload.get("insecure_ssl")),
        recent_delivery_count=len(deliveries),
        recent_success_count=successes,
        recent_failure_count=failures,
        last_delivery_at=deliveries[0].delivered_at if deliveries else None,
    )


def _build_summary(
    *,
    total_installation_count: int,
    total_repository_count: int,
    recent_deliveries: tuple[GitHubDoctorDelivery, ...],
    checks: tuple[GitHubDoctorCheck, ...],
) -> str:
    blocking = [check for check in checks if not check.ok and check.severity == "required"]
    warnings = [check for check in checks if not check.ok and check.severity in {"warning", "recommended"}]
    if blocking:
        return f"GitHub App mode is not ready yet: {blocking[0].detail}"
    if total_installation_count <= 0:
        return "GitHub App authentication works, but the app still needs its first installation."
    if total_repository_count <= 0:
        return "The app is installed, but Glasswall cannot see any repository targets yet."
    if any(_is_failure(delivery.status_code) for delivery in recent_deliveries):
        return "The app is installed and receiving traffic, but at least one recent webhook delivery failed."
    if not recent_deliveries:
        return "The app is installed and configured. Send a pull request or push event to verify live webhook flow."
    if warnings:
        return f"GitHub App mode is alive, with follow-up cleanup still recommended: {warnings[0].detail}"
    return "GitHub App mode is alive: authenticated, installed, and receiving healthy webhook traffic."


def _normalize_public_base_url(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip().rstrip("/")
    return normalized or None


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _optional_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _is_failure(status_code: int | None) -> bool:
    return status_code is not None and 400 <= status_code <= 599


def _is_success(status_code: int | None) -> bool:
    return status_code is not None and 200 <= status_code <= 399
