from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from glasswall.analytics import FleetOverview
from glasswall.diffing import ScanDelta
from glasswall.models import (
    Finding,
    RemediationFileChange,
    RemediationPlan,
    RemediationRecommendation,
    RemediationRun,
    RemediationSkip,
    ScanResult,
)


def render_scan_output(result: ScanResult, output_format: str, delta: ScanDelta | None = None) -> str:
    if output_format == "json":
        payload = result.to_dict()
        if delta is not None:
            payload["delta"] = delta.to_dict()
        return json.dumps(payload, indent=2)
    if output_format == "markdown":
        return render_markdown(result, delta)
    if output_format == "sarif":
        return json.dumps(render_sarif(result), indent=2)
    return render_summary(result, delta)


def render_plan_output(plan: RemediationPlan, output_format: str) -> str:
    if output_format == "json":
        return json.dumps(plan.to_dict(), indent=2)
    if output_format == "markdown":
        return render_plan_markdown(plan)
    return render_plan_summary(plan)


def render_remediation_output(result: RemediationRun, output_format: str) -> str:
    if output_format == "json":
        return json.dumps(result.to_dict(), indent=2)
    if output_format == "markdown":
        return render_remediation_markdown(result)
    return render_remediation_summary(result)


def render_fleet_output(overview: FleetOverview, output_format: str) -> str:
    if output_format == "json":
        return json.dumps(overview.to_dict(), indent=2)
    if output_format == "markdown":
        return render_fleet_markdown(overview)
    return render_fleet_summary(overview)


def write_output(text: str, output_path: str | None) -> None:
    if output_path is None:
        print(text)
        return
    path = Path(output_path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def render_summary(result: ScanResult, delta: ScanDelta | None = None) -> str:
    lines = [
        f"Scan: {result.target_path}",
        f"Generated: {result.generated_at}",
        f"Dependencies: {result.dependency_count}",
        f"Findings: {result.finding_count}",
        f"Top urgency: {result.top_urgency_label or 'none'}",
    ]
    if result.policy_path:
        lines.append(f"Policy: {result.policy_path}")
    if delta is not None:
        lines.extend(
            [
                f"New findings: {len(delta.new_findings)}",
                f"Resolved findings: {len(delta.resolved_findings)}",
                f"Escalated findings: {len(delta.escalated_findings)}",
                f"De-escalated findings: {len(delta.deescalated_findings)}",
            ]
        )
    if result.findings:
        lines.append("")
        lines.append("Top findings:")
        for finding in result.findings[:10]:
            lines.append(_summary_line(finding))
    return "\n".join(lines)


def render_markdown(result: ScanResult, delta: ScanDelta | None = None) -> str:
    lines = [
        "# Glasswall Scan",
        "",
        f"- Target: `{result.target_path}`",
        f"- Generated: `{result.generated_at}`",
        f"- Dependencies: `{result.dependency_count}`",
        f"- Findings: `{result.finding_count}`",
        f"- Top urgency: `{result.top_urgency_label or 'none'}`",
    ]
    if result.policy_path:
        lines.append(f"- Policy: `{result.policy_path}`")
    if delta is not None:
        lines.extend(
            [
                "",
                "## Delta",
                f"- New findings: `{len(delta.new_findings)}`",
                f"- Resolved findings: `{len(delta.resolved_findings)}`",
                f"- Escalated findings: `{len(delta.escalated_findings)}`",
                f"- De-escalated findings: `{len(delta.deescalated_findings)}`",
            ]
        )
    if result.findings:
        lines.extend(["", "## Findings"])
        for finding in result.findings[:20]:
            lines.append(
                f"- `{finding.urgency_label}` `{finding.dependency.name}@{finding.dependency.version}` "
                f"`{finding.vulnerability.canonical_id}` score={finding.urgency_score}"
            )
    return "\n".join(lines)


def render_plan_summary(plan: RemediationPlan) -> str:
    lines = [
        f"Plan: {plan.target_path}",
        f"Generated: {plan.generated_at}",
        f"Recommendations: {plan.recommendation_count}",
    ]
    if plan.policy_path:
        lines.append(f"Policy: {plan.policy_path}")
    if plan.recommendations:
        lines.extend(["", "Recommended upgrades:"])
        for recommendation in plan.recommendations[:10]:
            lines.append(_plan_summary_line(recommendation))
    return "\n".join(lines)


def render_plan_markdown(plan: RemediationPlan) -> str:
    lines = [
        "# Glasswall Remediation Plan",
        "",
        f"- Target: `{plan.target_path}`",
        f"- Generated: `{plan.generated_at}`",
        f"- Recommendations: `{plan.recommendation_count}`",
    ]
    if plan.policy_path:
        lines.append(f"- Policy: `{plan.policy_path}`")
    if plan.recommendations:
        lines.extend(["", "## Upgrade Queue"])
        for recommendation in plan.recommendations:
            lines.append(
                f"- `{recommendation.urgency_label}` `{recommendation.name}` "
                f"`{recommendation.current_version} -> {recommendation.target_version or 'manual'}` "
                f"via `{recommendation.source_file}`"
            )
            lines.append(
                f"  action=`{recommendation.action}` advisories=`{', '.join(recommendation.advisories[:4])}`"
            )
    return "\n".join(lines)


def render_remediation_summary(result: RemediationRun) -> str:
    mode = "apply" if result.apply_mode else "dry-run"
    lines = [
        f"Remediation: {result.target_path}",
        f"Generated: {result.generated_at}",
        f"Mode: {mode}",
        f"Changed files: {result.changed_file_count}",
        f"Applied recommendations: {result.applied_recommendation_count}",
        f"Skipped: {result.skipped_count}",
    ]
    if result.policy_path:
        lines.append(f"Policy: {result.policy_path}")
    if result.changed_files:
        lines.extend(["", "Updated files:"])
        for change in result.changed_files:
            lines.append(_remediation_change_summary_line(change))
    if result.skipped:
        lines.extend(["", "Skipped:"])
        for skip in result.skipped[:10]:
            lines.append(_remediation_skip_summary_line(skip))
    return "\n".join(lines)


def render_remediation_markdown(result: RemediationRun) -> str:
    mode = "apply" if result.apply_mode else "dry-run"
    lines = [
        "# Glasswall Remediation Run",
        "",
        f"- Target: `{result.target_path}`",
        f"- Generated: `{result.generated_at}`",
        f"- Mode: `{mode}`",
        f"- Changed files: `{result.changed_file_count}`",
        f"- Applied recommendations: `{result.applied_recommendation_count}`",
        f"- Skipped: `{result.skipped_count}`",
    ]
    if result.policy_path:
        lines.append(f"- Policy: `{result.policy_path}`")
    if result.changed_files:
        lines.extend(["", "## Updated files"])
        for change in result.changed_files:
            lines.append(_remediation_change_summary_line(change))
    if result.skipped:
        lines.extend(["", "## Skipped recommendations"])
        for skip in result.skipped:
            lines.append(_remediation_skip_summary_line(skip))
    return "\n".join(lines)


def render_fleet_summary(overview: FleetOverview) -> str:
    lines = [
        f"Fleet generated: {overview.generated_at}",
        f"Targets: {overview.target_count}",
        f"Open findings: {overview.total_open_findings}",
        f"Urgent findings: {overview.total_urgent_findings}",
        f"Patch-gap findings: {overview.total_patch_gap_findings}",
        f"Average resolved patch-gap MTTP (days): {overview.average_resolved_mttp_days if overview.average_resolved_mttp_days is not None else 'n/a'}",
        f"Hottest target: {overview.hottest_target_path or 'n/a'}",
    ]
    if overview.targets:
        lines.extend(["", "Top targets:"])
        for target in overview.targets[:10]:
            lines.append(_fleet_target_summary_line(target))
    return "\n".join(lines)


def render_fleet_markdown(overview: FleetOverview) -> str:
    lines = [
        "# Glasswall Fleet Overview",
        "",
        f"- Generated: `{overview.generated_at}`",
        f"- Targets: `{overview.target_count}`",
        f"- Open findings: `{overview.total_open_findings}`",
        f"- Urgent findings: `{overview.total_urgent_findings}`",
        f"- Patch-gap findings: `{overview.total_patch_gap_findings}`",
        f"- Average resolved patch-gap MTTP (days): `{overview.average_resolved_mttp_days if overview.average_resolved_mttp_days is not None else 'n/a'}`",
        f"- Hottest target: `{overview.hottest_target_path or 'n/a'}`",
    ]
    if overview.targets:
        lines.extend(["", "## Target pressure"])
        for target in overview.targets:
            lines.append(_fleet_target_summary_line(target))
    return "\n".join(lines)


def render_sarif(result: ScanResult) -> dict[str, Any]:
    rules = {}
    results: list[dict[str, Any]] = []
    for finding in result.findings:
        rule_id = finding.vulnerability.canonical_id
        rules.setdefault(rule_id, _sarif_rule(finding))
        results.append(_sarif_result(result, finding))

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Glasswall",
                        "rules": list(rules.values()),
                    }
                },
                "automationDetails": {
                    "id": "glasswall/patch-gap",
                },
                "originalUriBaseIds": {
                    "%SRCROOT%": {
                        "uri": f"file://{result.target_path.rstrip('/')}/"
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                    }
                ],
                "results": results,
            }
        ],
    }


def _sarif_rule(finding: Finding) -> dict[str, Any]:
    help_uri = finding.vulnerability.references[0] if finding.vulnerability.references else None
    short_description = finding.vulnerability.summary or finding.vulnerability.details or "Dependency vulnerability"
    rule: dict[str, Any] = {
        "id": finding.vulnerability.canonical_id,
        "name": finding.vulnerability.canonical_id,
        "shortDescription": {
            "text": short_description[:160],
        },
        "fullDescription": {
            "text": (
                finding.vulnerability.details
                or finding.vulnerability.summary
                or f"{finding.dependency.name} is affected by {finding.vulnerability.canonical_id}."
            )[:4000],
        },
        "properties": {
            "security-severity": _sarif_security_severity(finding.urgency_label),
            "tags": [
                "supply-chain",
                "dependency",
                "patch-gap" if finding.patch_gap else "advisory",
                finding.urgency_label,
            ]
        },
    }
    if help_uri:
        rule["helpUri"] = help_uri
    return rule


def _sarif_result(result: ScanResult, finding: Finding) -> dict[str, Any]:
    fixed_versions = ", ".join(finding.vulnerability.fixed_versions[:5]) if finding.vulnerability.fixed_versions else "none advertised"
    message = (
        f"{finding.dependency.name}@{finding.dependency.version} is affected by "
        f"{finding.vulnerability.canonical_id}. Urgency={finding.urgency_label}. Fixes={fixed_versions}."
    )
    return {
        "ruleId": finding.vulnerability.canonical_id,
        "level": _sarif_level(finding.urgency_label),
        "message": {
            "text": message,
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.dependency.source_file,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": 1,
                    },
                }
            }
        ],
        "partialFingerprints": {
            "glasswall/finding/v1": _fingerprint_for_finding(finding),
        },
        "properties": {
            "package": finding.dependency.name,
            "version": finding.dependency.version,
            "ecosystem": finding.dependency.ecosystem,
            "urgencyScore": finding.urgency_score,
            "urgencyLabel": finding.urgency_label,
            "patchGap": finding.patch_gap,
            "references": list(finding.vulnerability.references),
            "aliases": list(finding.vulnerability.aliases),
            "fixedVersions": list(finding.vulnerability.fixed_versions),
            "policyPath": result.policy_path,
        },
    }


def _sarif_level(label: str) -> str:
    if label in {"critical-now", "urgent"}:
        return "error"
    if label == "high":
        return "warning"
    return "note"


def _sarif_security_severity(label: str) -> str:
    if label == "critical-now":
        return "9.5"
    if label == "urgent":
        return "8.0"
    if label == "high":
        return "6.5"
    return "3.0"


def _fingerprint_for_finding(finding: Finding) -> str:
    digest = hashlib.sha256(
        "|".join(
            [
                finding.dependency.source_file,
                finding.dependency.ecosystem,
                finding.dependency.name.lower(),
                finding.dependency.version,
                finding.vulnerability.canonical_id,
            ]
        ).encode("utf-8")
    ).hexdigest()
    return digest


def _summary_line(finding: Finding) -> str:
    return (
        f"- [{finding.urgency_label}] {finding.dependency.name}@{finding.dependency.version} "
        f"{finding.vulnerability.canonical_id} score={finding.urgency_score}"
    )


def _plan_summary_line(recommendation: RemediationRecommendation) -> str:
    return (
        f"- [{recommendation.urgency_label}] {recommendation.name}@{recommendation.current_version} "
        f"-> {recommendation.target_version or 'manual'} action={recommendation.action}"
    )


def _remediation_change_summary_line(change: RemediationFileChange) -> str:
    packages = ", ".join(change.package_names)
    return f"- {change.source_file} packages={packages} action={change.action}"


def _remediation_skip_summary_line(skip: RemediationSkip) -> str:
    return (
        f"- [{skip.urgency_label}] {skip.name}@{skip.current_version} -> {skip.target_version or 'manual'} "
        f"via {skip.source_file}: {skip.reason}"
    )


def _fleet_target_summary_line(target) -> str:
    return (
        f"- [{target.top_urgency_label or 'none'}] {target.target_path} "
        f"open={target.open_finding_count} urgent={target.urgent_open_finding_count} "
        f"patch-gap={target.patch_gap_open_finding_count} "
        f"oldest-open-days={target.oldest_open_public_days if target.oldest_open_public_days is not None else 'n/a'} "
        f"avg-resolved-mttp={target.average_resolved_mttp_days if target.average_resolved_mttp_days is not None else 'n/a'}"
    )
