from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, Form, Header, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from glasswall.analytics import FleetOverview, build_fleet_overview
from glasswall.diffing import build_scan_delta
from glasswall.github_app import GitHubWebhookVerifier
from glasswall.github_webhooks import GitHubWebhookProcessor
from glasswall.models import Finding, RemediationPlan, ScanResult
from glasswall.policy import load_scan_policy
from glasswall.service import GlasswallService, normalize_target_path
from glasswall.settings import Settings, load_settings
from glasswall.storage import Database

PACKAGE_ROOT = Path(__file__).resolve().parent
TEMPLATES = Jinja2Templates(directory=str(PACKAGE_ROOT / "templates"))


class ScanRequest(BaseModel):
    path: str
    policy_path: str | None = None


class RemediateRequest(ScanRequest):
    apply: bool = False
    max_upgrades: int | None = None


def create_app(
    settings: Settings | None = None,
    service: GlasswallService | None = None,
    database: Database | None = None,
    webhook_processor: GitHubWebhookProcessor | None = None,
) -> FastAPI:
    settings = settings or load_settings()
    app = FastAPI(title="Glasswall", version="0.4.0")
    app.mount("/static", StaticFiles(directory=str(PACKAGE_ROOT / "static")), name="static")

    database = database or Database(settings.db_path)
    service = service or GlasswallService(settings=settings)
    github_status = _github_status(settings)
    github_verifier = GitHubWebhookVerifier(settings.github_webhook_secret) if settings.github_webhook_secret else None
    github_processor = webhook_processor
    if github_processor is None and github_status["configured"]:
        github_processor = GitHubWebhookProcessor(settings=settings, service=service)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/github/status")
    async def github_integration_status() -> JSONResponse:
        return JSONResponse({"github": github_status})

    @app.get("/api/fleet")
    async def fleet_overview() -> JSONResponse:
        overview = _build_fleet_overview(database)
        return JSONResponse({"fleet": overview.to_dict()})

    @app.get("/api/scans")
    async def list_scans(limit: int = 20, target_path: str | None = None) -> JSONResponse:
        normalized_target = normalize_target_path(target_path) if target_path else None
        scans = [scan.to_dict() for scan in database.list_scans(limit=limit, target_path=normalized_target)]
        return JSONResponse({"scans": scans})

    @app.get("/api/scans/latest")
    async def latest_scan(target_path: str | None = None) -> JSONResponse:
        normalized_target = normalize_target_path(target_path) if target_path else None
        latest = database.latest_scan_summary(target_path=normalized_target)
        return JSONResponse({"scan": latest})

    @app.get("/api/scans/latest/delta")
    async def latest_delta(target_path: str | None = None) -> JSONResponse:
        normalized_target = normalize_target_path(target_path) if target_path else None
        latest = database.latest_scan(target_path=normalized_target)
        if latest is None or latest.scan_id is None:
            return JSONResponse({"delta": None})
        previous = database.previous_scan(latest.target_path, latest.scan_id)
        return JSONResponse({"delta": build_scan_delta(latest, previous).to_dict()})

    @app.get("/api/scans/{scan_id}")
    async def get_scan(scan_id: int) -> JSONResponse:
        scan = database.get_scan(scan_id)
        return JSONResponse({"scan": scan.to_dict() if scan else None})

    @app.get("/api/scans/{scan_id}/delta")
    async def get_scan_delta(scan_id: int) -> JSONResponse:
        scan = database.get_scan(scan_id)
        if scan is None or scan.scan_id is None:
            return JSONResponse({"delta": None})
        previous = database.previous_scan(scan.target_path, scan.scan_id)
        return JSONResponse({"delta": build_scan_delta(scan, previous).to_dict()})

    @app.get("/api/scans/{scan_id}/plan")
    async def get_scan_plan(scan_id: int) -> JSONResponse:
        scan = database.get_scan(scan_id)
        plan = await _build_plan(service, scan)
        return JSONResponse({"plan": plan.to_dict() if plan else None})

    @app.get("/api/plans/latest")
    async def latest_plan(target_path: str | None = None) -> JSONResponse:
        normalized_target = normalize_target_path(target_path) if target_path else None
        latest = database.latest_scan(target_path=normalized_target)
        plan = await _build_plan(service, latest)
        return JSONResponse({"plan": plan.to_dict() if plan else None})

    @app.post("/api/scans")
    async def create_scan(payload: ScanRequest) -> JSONResponse:
        try:
            policy = None
            if payload.policy_path:
                policy = load_scan_policy(Path(normalize_target_path(payload.path)), payload.policy_path)
            result = await service.scan_path(payload.path, policy=policy)
        except (FileNotFoundError, NotADirectoryError, ValueError) as exc:
            return JSONResponse({"detail": str(exc)}, status_code=400)
        scan_id = database.save_scan(result)
        saved = replace(result, scan_id=scan_id)
        previous = database.previous_scan(saved.target_path, scan_id)
        return JSONResponse(
            {
                "scan": saved.to_dict(),
                "delta": build_scan_delta(saved, previous).to_dict(),
            },
            status_code=201,
        )

    @app.post("/api/plans")
    async def create_plan(payload: ScanRequest) -> JSONResponse:
        try:
            policy = None
            if payload.policy_path:
                policy = load_scan_policy(Path(normalize_target_path(payload.path)), payload.policy_path)
            plan = await service.plan_path(payload.path, policy=policy)
        except (FileNotFoundError, NotADirectoryError, ValueError) as exc:
            return JSONResponse({"detail": str(exc)}, status_code=400)
        return JSONResponse({"plan": plan.to_dict()}, status_code=201)

    @app.post("/api/remediate")
    async def remediate(payload: RemediateRequest) -> JSONResponse:
        try:
            policy = None
            if payload.policy_path:
                policy = load_scan_policy(Path(normalize_target_path(payload.path)), payload.policy_path)
            result = await service.remediate_path(
                payload.path,
                policy=policy,
                apply=payload.apply,
                max_recommendations=payload.max_upgrades,
            )
        except (FileNotFoundError, NotADirectoryError, ValueError) as exc:
            return JSONResponse({"detail": str(exc)}, status_code=400)
        return JSONResponse({"remediation": result.to_dict()}, status_code=201)

    @app.post("/github/webhooks")
    async def receive_github_webhook(
        request: Request,
        background_tasks: BackgroundTasks,
        x_github_event: str | None = Header(default=None, alias="X-GitHub-Event"),
        x_hub_signature_256: str | None = Header(default=None, alias="X-Hub-Signature-256"),
    ) -> JSONResponse:
        if not github_status["configured"] or github_processor is None or github_verifier is None:
            return JSONResponse(
                {"detail": "GitHub App integration is not configured."},
                status_code=503,
            )
        if not x_github_event:
            return JSONResponse({"detail": "X-GitHub-Event header is required."}, status_code=400)

        body = await request.body()
        if not github_verifier.verify(body, x_hub_signature_256):
            return JSONResponse({"detail": "Webhook signature verification failed."}, status_code=401)
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            return JSONResponse({"detail": "Webhook payload must be valid JSON."}, status_code=400)

        background_tasks.add_task(github_processor.handle_event, x_github_event, payload)
        return JSONResponse({"accepted": True, "event": x_github_event}, status_code=202)

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request, scan_id: int | None = None) -> HTMLResponse:
        latest = database.get_scan(scan_id) if scan_id is not None else database.latest_scan()
        fleet = _build_fleet_overview(database)
        delta = None
        plan = None
        plan_error = None
        if latest is not None and latest.scan_id is not None:
            previous = database.previous_scan(latest.target_path, latest.scan_id)
            delta = build_scan_delta(latest, previous)
        if latest is not None:
            try:
                plan = await _build_plan(service, latest)
            except Exception as exc:
                plan_error = str(exc)
        return _render_index(
            request=request,
            latest=latest,
            fleet=fleet,
            plan=plan,
            delta=delta,
            history=database.list_scans(limit=8, target_path=latest.target_path if latest else None),
            default_path=str(Path.cwd()),
            default_policy_path=latest.policy_path if latest else None,
            error=None,
            plan_error=plan_error,
            github_status=github_status,
        )

    @app.post("/scan")
    async def scan(
        request: Request,
        path: str = Form(...),
        policy_path: str | None = Form(default=None),
    ) -> Response:
        try:
            policy = load_scan_policy(Path(normalize_target_path(path)), policy_path)
            result = await service.scan_path(path, policy=policy)
        except (FileNotFoundError, NotADirectoryError, ValueError) as exc:
            latest = database.latest_scan()
            fleet = _build_fleet_overview(database)
            delta = None
            plan = None
            plan_error = None
            if latest is not None and latest.scan_id is not None:
                previous = database.previous_scan(latest.target_path, latest.scan_id)
                delta = build_scan_delta(latest, previous)
            if latest is not None:
                try:
                    plan = await _build_plan(service, latest)
                except Exception as plan_exc:
                    plan_error = str(plan_exc)
            return _render_index(
                request=request,
                latest=latest,
                fleet=fleet,
                plan=plan,
                delta=delta,
                history=database.list_scans(limit=8, target_path=latest.target_path if latest else None),
                default_path=path,
                default_policy_path=policy_path,
                error=str(exc),
                plan_error=plan_error,
                github_status=github_status,
                status_code=400,
            )
        scan_id = database.save_scan(result)
        return RedirectResponse(url=f"/?scan_id={scan_id}", status_code=303)

    return app


def _stats_for(findings: tuple[Finding, ...] | list[Finding]) -> dict[str, int]:
    stats = {
        "critical_now": 0,
        "urgent": 0,
        "high": 0,
        "watch": 0,
        "patch_gap": 0,
    }
    for finding in findings:
        if finding.urgency_label == "critical-now":
            stats["critical_now"] += 1
        elif finding.urgency_label == "urgent":
            stats["urgent"] += 1
        elif finding.urgency_label == "high":
            stats["high"] += 1
        else:
            stats["watch"] += 1
        if finding.patch_gap:
            stats["patch_gap"] += 1
    return stats


def _render_index(
    request: Request,
    latest: ScanResult | None,
    fleet: FleetOverview,
    plan: RemediationPlan | None,
    delta,
    history,
    default_path: str,
    default_policy_path: str | None,
    error: str | None,
    plan_error: str | None,
    github_status: dict[str, object],
    status_code: int = 200,
) -> HTMLResponse:
    return TEMPLATES.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "latest": latest,
            "fleet": fleet,
            "fleet_targets": list(fleet.targets[:5]),
            "fleet_signals": list(fleet.signals[:8]),
            "plan": plan,
            "top_recommendation": plan.recommendations[0] if plan and plan.recommendations else None,
            "remaining_recommendations": list(plan.recommendations[1:6]) if plan else [],
            "findings": list(latest.findings) if latest else [],
            "stats": _stats_for(latest.findings if latest else ()),
            "delta": delta,
            "history": history,
            "default_path": default_path,
            "default_policy_path": default_policy_path,
            "error": error,
            "active_policy_path": latest.policy_path if latest else None,
            "plan_error": plan_error,
            "github_status": github_status,
        },
        status_code=status_code,
    )


async def _build_plan(service: GlasswallService, scan: ScanResult | None) -> RemediationPlan | None:
    if scan is None:
        return None
    return await service.remediation_planner.build_plan(scan)


def _build_fleet_overview(database: Database) -> FleetOverview:
    histories = tuple(database.scan_history(target_path) for target_path in database.list_target_paths())
    return build_fleet_overview(histories)


def _github_status(settings: Settings) -> dict[str, object]:
    app_id_configured = bool(settings.github_app_id)
    private_key_configured = bool(settings.github_private_key)
    webhook_secret_configured = bool(settings.github_webhook_secret)
    configured = all((app_id_configured, private_key_configured, webhook_secret_configured))
    return {
        "configured": configured,
        "mode": "armed" if configured else "local-first",
        "summary": (
            "GitHub App webhooks can scan pull requests and update patch-gap comments."
            if configured
            else "Set GitHub App credentials to push patch-gap reports directly into pull requests."
        ),
        "app_id_configured": app_id_configured,
        "private_key_configured": private_key_configured,
        "webhook_secret_configured": webhook_secret_configured,
        "comment_mode": settings.github_comment_mode,
        "auto_pr_mode": settings.github_auto_pr_mode,
        "auto_pr_branch": settings.github_auto_pr_branch,
        "auto_pr_max_upgrades": settings.github_auto_pr_max_upgrades,
        "api_base_url": settings.github_api_base_url,
        "api_version": settings.github_api_version,
    }


app = create_app()
