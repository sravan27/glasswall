from __future__ import annotations

from pathlib import Path

from glasswall.advisories import AdvisoryClient
from glasswall.cache import JsonFileCache
from glasswall.models import RemediationPlan, RemediationRun, ScanResult, utc_now_iso
from glasswall.parsers import parse_dependencies
from glasswall.planner import RemediationPlanner
from glasswall.policy import ScanPolicy, apply_scan_policy, load_scan_policy
from glasswall.remediator import RemediationApplier
from glasswall.registry import RegistryClient
from glasswall.risk import assess_findings
from glasswall.settings import Settings, load_settings


def normalize_target_path(target_path: str) -> str:
    return str(Path(target_path).expanduser().resolve())


class GlasswallService:
    def __init__(self, settings: Settings | None = None, advisory_client: AdvisoryClient | None = None) -> None:
        self.settings = settings or load_settings()
        cache = JsonFileCache(self.settings.cache_dir)
        self.advisory_client = advisory_client or AdvisoryClient(
            timeout_seconds=self.settings.request_timeout_seconds,
            cache=cache,
            osv_query_ttl_seconds=self.settings.osv_query_ttl_seconds,
            osv_vuln_ttl_seconds=self.settings.osv_vuln_ttl_seconds,
            kev_ttl_seconds=self.settings.kev_ttl_seconds,
            max_concurrent_detail_requests=self.settings.max_concurrent_detail_requests,
        )
        self.remediation_planner = RemediationPlanner(
            registry_client=RegistryClient(
                timeout_seconds=self.settings.request_timeout_seconds,
                cache=cache,
            )
        )
        self.remediation_applier = RemediationApplier()

    async def scan_path(self, target_path: str, policy: ScanPolicy | None = None) -> ScanResult:
        root = Path(normalize_target_path(target_path))
        if not root.exists():
            raise FileNotFoundError(f"Target path does not exist: {root}")
        if not root.is_dir():
            raise NotADirectoryError(f"Target path is not a directory: {root}")
        policy = policy or load_scan_policy(root)
        dependencies = parse_dependencies(root)
        vulnerability_index = await self.advisory_client.lookup(dependencies)
        findings = assess_findings(dependencies, vulnerability_index)
        result = ScanResult(
            scan_id=None,
            target_path=str(root),
            generated_at=utc_now_iso(),
            dependencies=dependencies,
            findings=findings,
        )
        return apply_scan_policy(result, policy)

    async def plan_path(self, target_path: str, policy: ScanPolicy | None = None) -> RemediationPlan:
        scan_result = await self.scan_path(target_path, policy=policy)
        return await self.remediation_planner.build_plan(scan_result)

    async def remediate_path(
        self,
        target_path: str,
        policy: ScanPolicy | None = None,
        *,
        apply: bool = False,
        max_recommendations: int | None = None,
    ) -> RemediationRun:
        root = Path(normalize_target_path(target_path))
        plan = await self.plan_path(str(root), policy=policy)
        return self.remediation_applier.apply_plan(
            root,
            plan,
            apply=apply,
            max_recommendations=max_recommendations,
        )
