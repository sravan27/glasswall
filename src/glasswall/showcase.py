from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from glasswall.analytics import FleetOverview, build_fleet_overview
from glasswall.models import Finding, RemediationPlan, RemediationRun, ScanResult, utc_now_iso, urgency_rank
from glasswall.service import GlasswallService, normalize_target_path


@dataclass(frozen=True, slots=True)
class ShowcaseTarget:
    label: str
    target_path: str
    scan: ScanResult
    plan: RemediationPlan
    remediation_preview: RemediationRun

    @property
    def urgent_finding_count(self) -> int:
        return sum(1 for finding in self.scan.findings if urgency_rank(finding.urgency_label) >= urgency_rank("urgent"))

    @property
    def patch_gap_finding_count(self) -> int:
        return sum(1 for finding in self.scan.findings if finding.patch_gap)

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "target_path": self.target_path,
            "scan": _serialize_scan(self.scan),
            "plan": self.plan.to_dict(),
            "remediation_preview": self.remediation_preview.to_dict(),
            "urgent_finding_count": self.urgent_finding_count,
            "patch_gap_finding_count": self.patch_gap_finding_count,
        }


@dataclass(frozen=True, slots=True)
class ShowcaseBundle:
    title: str
    generated_at: str
    fleet: FleetOverview
    targets: tuple[ShowcaseTarget, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "generated_at": self.generated_at,
            "fleet": self.fleet.to_dict(),
            "targets": [target.to_dict() for target in self.targets],
        }


async def build_showcase(
    target_paths: list[str] | tuple[str, ...],
    *,
    title: str = "Glasswall Showcase",
    service: GlasswallService | None = None,
    max_recommendations: int | None = None,
) -> ShowcaseBundle:
    if not target_paths:
        raise ValueError("At least one showcase target path is required.")

    service = service or GlasswallService()
    showcase_targets: list[ShowcaseTarget] = []
    histories: list[tuple[ScanResult, ...]] = []

    for raw_path in target_paths:
        normalized_path = normalize_target_path(raw_path)
        root = Path(normalized_path)
        scan = await service.scan_path(str(root))
        plan = await service.remediation_planner.build_plan(scan)
        remediation_preview = service.remediation_applier.apply_plan(
            root,
            plan,
            apply=False,
            max_recommendations=max_recommendations,
        )
        showcase_targets.append(
            ShowcaseTarget(
                label=_derive_label(root),
                target_path=str(root),
                scan=scan,
                plan=plan,
                remediation_preview=remediation_preview,
            )
        )
        histories.append((scan,))

    return ShowcaseBundle(
        title=title,
        generated_at=utc_now_iso(),
        fleet=build_fleet_overview(tuple(histories)),
        targets=tuple(sorted(showcase_targets, key=_showcase_target_sort_key)),
    )


def _derive_label(root: Path) -> str:
    if root.name:
        return root.name.replace("-", " ").replace("_", " ").title()
    return str(root)


def _showcase_target_sort_key(target: ShowcaseTarget) -> tuple[int, int, int, str]:
    return (
        -urgency_rank(target.scan.top_urgency_label),
        -target.urgent_finding_count,
        -target.patch_gap_finding_count,
        target.label.lower(),
    )


def _serialize_scan(scan: ScanResult) -> dict[str, Any]:
    payload = scan.to_dict()
    payload["dependencies"] = [asdict(dependency) for dependency in scan.dependencies]
    payload["findings"] = [_serialize_finding(finding) for finding in scan.findings]
    return payload


def _serialize_finding(finding: Finding) -> dict[str, Any]:
    vulnerability = asdict(finding.vulnerability)
    vulnerability["canonical_id"] = finding.vulnerability.canonical_id
    return {
        "dependency": asdict(finding.dependency),
        "vulnerability": vulnerability,
        "urgency_score": finding.urgency_score,
        "urgency_label": finding.urgency_label,
        "patch_gap": finding.patch_gap,
        "rationale": list(finding.rationale),
    }
