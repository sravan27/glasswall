from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from glasswall.analytics import FleetOverview, FleetScorecard, FleetSignal, TargetScorecard
from glasswall.github_setup import GitHubSetupReport
from glasswall.github_doctor import GitHubDoctorReport
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
from glasswall.showcase import ShowcaseBundle


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


def render_scorecard_output(scorecard: FleetScorecard, output_format: str) -> str:
    if output_format == "json":
        return json.dumps(scorecard.to_dict(), indent=2)
    if output_format == "markdown":
        return render_scorecard_markdown(scorecard)
    return render_scorecard_summary(scorecard)


def render_showcase_output(bundle: ShowcaseBundle, output_format: str) -> str:
    if output_format == "json":
        return json.dumps(bundle.to_dict(), indent=2)
    if output_format == "markdown":
        return render_showcase_markdown(bundle)
    return render_showcase_summary(bundle)


def render_github_setup_output(report: GitHubSetupReport, output_format: str) -> str:
    if output_format == "json":
        return json.dumps(report.to_dict(), indent=2)
    if output_format == "markdown":
        return render_github_setup_markdown(report)
    return render_github_setup_summary(report)


def render_github_doctor_output(report: GitHubDoctorReport, output_format: str) -> str:
    if output_format == "json":
        return json.dumps(report.to_dict(), indent=2)
    if output_format == "markdown":
        return render_github_doctor_markdown(report)
    return render_github_doctor_summary(report)


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
        f"Newly dangerous findings: {overview.newly_dangerous_count}",
        f"Recently cleared findings: {overview.recently_resolved_count}",
        f"Average resolved patch-gap MTTP (days): {overview.average_resolved_mttp_days if overview.average_resolved_mttp_days is not None else 'n/a'}",
        f"Hottest target: {overview.hottest_target_path or 'n/a'}",
    ]
    if overview.signals:
        lines.extend(["", "Recent change feed:"])
        for signal in overview.signals[:10]:
            lines.append(_fleet_signal_summary_line(signal))
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
        f"- Newly dangerous findings: `{overview.newly_dangerous_count}`",
        f"- Recently cleared findings: `{overview.recently_resolved_count}`",
        f"- Average resolved patch-gap MTTP (days): `{overview.average_resolved_mttp_days if overview.average_resolved_mttp_days is not None else 'n/a'}`",
        f"- Hottest target: `{overview.hottest_target_path or 'n/a'}`",
    ]
    if overview.signals:
        lines.extend(["", "## Recent change feed"])
        for signal in overview.signals[:10]:
            lines.append(_fleet_signal_summary_line(signal))
    if overview.targets:
        lines.extend(["", "## Target pressure"])
        for target in overview.targets:
            lines.append(_fleet_target_summary_line(target))
    return "\n".join(lines)


def render_showcase_summary(bundle: ShowcaseBundle) -> str:
    lines = [
        f"Showcase: {bundle.title}",
        f"Generated: {bundle.generated_at}",
        f"Fleet score: {bundle.scorecard.grade} ({bundle.scorecard.fleet_score})",
        f"Targets: {bundle.fleet.target_count}",
        f"Open findings: {bundle.fleet.total_open_findings}",
        f"Urgent findings: {bundle.fleet.total_urgent_findings}",
        f"Patch-gap findings: {bundle.fleet.total_patch_gap_findings}",
        f"Average resolved patch-gap MTTP (days): {bundle.fleet.average_resolved_mttp_days if bundle.fleet.average_resolved_mttp_days is not None else 'n/a'}",
    ]
    if bundle.targets:
        lines.extend(["", "Target snapshots:"])
        for target in bundle.targets:
            lines.append(
                f"{target.label}: grade={target.scorecard.grade} score={target.scorecard.score} "
                f"findings={target.scan.finding_count} urgent={target.urgent_finding_count} "
                f"patch-gap={target.patch_gap_finding_count} recommendations={target.plan.recommendation_count}"
            )
    return "\n".join(lines)


def render_showcase_markdown(bundle: ShowcaseBundle) -> str:
    lines = [
        "# Glasswall Showcase",
        "",
        f"- Title: `{bundle.title}`",
        f"- Generated: `{bundle.generated_at}`",
        f"- Fleet score: `{bundle.scorecard.grade} / {bundle.scorecard.fleet_score}`",
        f"- Targets: `{bundle.fleet.target_count}`",
        f"- Open findings: `{bundle.fleet.total_open_findings}`",
        f"- Urgent findings: `{bundle.fleet.total_urgent_findings}`",
        f"- Patch-gap findings: `{bundle.fleet.total_patch_gap_findings}`",
        f"- Average resolved patch-gap MTTP (days): `{bundle.fleet.average_resolved_mttp_days if bundle.fleet.average_resolved_mttp_days is not None else 'n/a'}`",
    ]
    for target in bundle.targets:
        lines.extend(
            [
                "",
                f"## {target.label}",
                f"- Target: `{target.target_path}`",
                f"- Score: `{target.scorecard.grade} / {target.scorecard.score}`",
                f"- Trend: `{target.scorecard.trend_label}`",
                f"- Findings: `{target.scan.finding_count}`",
                f"- Urgent findings: `{target.urgent_finding_count}`",
                f"- Patch-gap findings: `{target.patch_gap_finding_count}`",
                f"- Recommendations: `{target.plan.recommendation_count}`",
                f"- Dry-run changed files: `{target.remediation_preview.changed_file_count}`",
            ]
        )
        if target.scorecard.reasons:
            lines.append("")
            lines.append("### Scorecard reasons")
            for reason in target.scorecard.reasons:
                lines.append(f"- {reason}")
        if target.scan.findings:
            lines.append("")
            lines.append("### Top findings")
            for finding in target.scan.findings[:5]:
                lines.append(_summary_line(finding))
        if target.plan.recommendations:
            lines.append("")
            lines.append("### Top remediation queue")
            for recommendation in target.plan.recommendations[:5]:
                lines.append(_plan_summary_line(recommendation))
    return "\n".join(lines)


def render_scorecard_summary(scorecard: FleetScorecard) -> str:
    lines = [
        f"Fleet scorecard generated: {scorecard.generated_at}",
        f"Fleet score: {scorecard.grade} ({scorecard.fleet_score})",
        f"Status: {scorecard.status_label}",
        f"Trend: {scorecard.trend_label}",
        f"Average target score: {scorecard.average_target_score if scorecard.average_target_score is not None else 'n/a'}",
        f"Healthy targets: {scorecard.healthy_target_count}",
        f"Exposed targets: {scorecard.exposed_target_count}",
        f"Strongest target: {scorecard.strongest_target_path or 'n/a'}",
        f"Weakest target: {scorecard.weakest_target_path or 'n/a'}",
        f"Summary: {scorecard.summary}",
    ]
    if scorecard.targets:
        lines.extend(["", "Target grades:"])
        for target in scorecard.targets:
            lines.append(_scorecard_target_summary_line(target))
    return "\n".join(lines)


def render_scorecard_markdown(scorecard: FleetScorecard) -> str:
    lines = [
        "# Glasswall Fleet Scorecard",
        "",
        f"- Generated: `{scorecard.generated_at}`",
        f"- Fleet score: `{scorecard.grade} / {scorecard.fleet_score}`",
        f"- Status: `{scorecard.status_label}`",
        f"- Trend: `{scorecard.trend_label}`",
        f"- Average target score: `{scorecard.average_target_score if scorecard.average_target_score is not None else 'n/a'}`",
        f"- Healthy targets: `{scorecard.healthy_target_count}`",
        f"- Exposed targets: `{scorecard.exposed_target_count}`",
        f"- Strongest target: `{scorecard.strongest_target_path or 'n/a'}`",
        f"- Weakest target: `{scorecard.weakest_target_path or 'n/a'}`",
        f"- Summary: `{scorecard.summary}`",
    ]
    if scorecard.targets:
        lines.extend(["", "## Target grades"])
        for target in scorecard.targets:
            lines.append(_scorecard_target_summary_line(target))
    return "\n".join(lines)


def render_github_setup_summary(report: GitHubSetupReport) -> str:
    lines = [
        "GitHub App setup",
        f"Public base URL: {report.public_base_url or 'missing'}",
        f"Registration target: {report.account_type}{f'/{report.owner}' if report.owner else ''}",
        f"Action URL: {report.action_url or 'unavailable'}",
        f"Webhook URL: {report.webhook_url or 'unavailable'}",
    ]
    if report.checks:
        lines.extend(["", "Checks:"])
        for check in report.checks:
            status = "ok" if check.ok else check.severity
            lines.append(f"- {check.name}: {status} - {check.detail}")
    return "\n".join(lines)


def render_github_setup_markdown(report: GitHubSetupReport) -> str:
    lines = [
        "# Glasswall GitHub App Setup",
        "",
        f"- Public base URL: `{report.public_base_url or 'missing'}`",
        f"- Registration target: `{report.account_type}{f'/{report.owner}' if report.owner else ''}`",
        f"- Action URL: `{report.action_url or 'unavailable'}`",
        f"- Webhook URL: `{report.webhook_url or 'unavailable'}`",
    ]
    if report.manifest is not None:
        lines.extend(["", "## Manifest preview", "```json", json.dumps(report.manifest, indent=2), "```"])
    if report.checks:
        lines.extend(["", "## Checks"])
        for check in report.checks:
            status = "ok" if check.ok else check.severity
            lines.append(f"- **{check.name}**: `{status}` {check.detail}")
    lines.extend(["", "## Environment template", "```dotenv", report.env_template, "```"])
    return "\n".join(lines)


def render_github_doctor_summary(report: GitHubDoctorReport) -> str:
    lines = [
        "GitHub App doctor",
        f"Generated: {report.generated_at}",
        f"Configured: {'yes' if report.configured else 'no'}",
        f"Summary: {report.summary}",
        f"Installations: {report.total_installation_count}",
        f"Repositories: {report.total_repository_count}",
        f"Recent deliveries: {len(report.recent_deliveries)}",
    ]
    if report.app is not None:
        lines.append(f"App: {report.app.slug or report.app.name or report.app.app_id}")
    if report.webhook is not None:
        lines.append(f"Webhook URL: {report.webhook.url or 'missing'}")
    if report.checks:
        lines.extend(["", "Checks:"])
        for check in report.checks:
            status = "ok" if check.ok else check.severity
            lines.append(f"- {check.name}: {status} - {check.detail}")
    if report.installations:
        lines.extend(["", "Installations:"])
        for installation in report.installations:
            status = "ok"
            if installation.error or installation.missing_events or installation.permission_gaps:
                status = "warning"
            lines.append(
                f"- {installation.account_login or installation.installation_id}: {status} "
                f"repos={installation.repository_count} selection={installation.repository_selection}"
            )
    if report.recent_deliveries:
        lines.extend(["", "Recent deliveries:"])
        for delivery in report.recent_deliveries[:5]:
            lines.append(
                f"- #{delivery.delivery_id} {delivery.event}"
                f"{f'/{delivery.action}' if delivery.action else ''} "
                f"status={delivery.status_code or 'unknown'} at {delivery.delivered_at or 'unknown'}"
            )
    return "\n".join(lines)


def render_github_doctor_markdown(report: GitHubDoctorReport) -> str:
    lines = [
        "# Glasswall GitHub App Doctor",
        "",
        f"- Generated: `{report.generated_at}`",
        f"- Configured: `{'yes' if report.configured else 'no'}`",
        f"- Summary: `{report.summary}`",
        f"- Installations: `{report.total_installation_count}`",
        f"- Repositories: `{report.total_repository_count}`",
        f"- Recent deliveries: `{len(report.recent_deliveries)}`",
    ]
    if report.expected_public_base_url:
        lines.append(f"- Expected public base URL: `{report.expected_public_base_url}`")
    if report.app is not None:
        lines.extend(
            [
                "",
                "## App",
                f"- App: `{report.app.slug or report.app.name or report.app.app_id}`",
                f"- Install URL: `{report.app.install_url or 'n/a'}`",
                f"- Settings URL: `{report.app.html_url or 'n/a'}`",
            ]
        )
    if report.webhook is not None:
        lines.extend(
            [
                "",
                "## Webhook",
                f"- URL: `{report.webhook.url or 'missing'}`",
                f"- Content type: `{report.webhook.content_type or 'unknown'}`",
                f"- Recent successes: `{report.webhook.recent_success_count}`",
                f"- Recent failures: `{report.webhook.recent_failure_count}`",
            ]
        )
    if report.checks:
        lines.extend(["", "## Checks"])
        for check in report.checks:
            status = "ok" if check.ok else check.severity
            lines.append(f"- **{check.name}**: `{status}` {check.detail}")
    if report.installations:
        lines.extend(["", "## Installations"])
        for installation in report.installations:
            lines.append(
                f"- `{installation.account_login or installation.installation_id}` "
                f"repos=`{installation.repository_count}` selection=`{installation.repository_selection}`"
            )
            if installation.missing_events:
                lines.append(f"  missing-events=`{', '.join(installation.missing_events)}`")
            if installation.permission_gaps:
                lines.append(f"  permission-gaps=`{', '.join(installation.permission_gaps)}`")
            if installation.error:
                lines.append(f"  error=`{installation.error}`")
    if report.recent_deliveries:
        lines.extend(["", "## Recent deliveries"])
        for delivery in report.recent_deliveries:
            lines.append(
                f"- `#{delivery.delivery_id}` `{delivery.event}`"
                f"{f'/{delivery.action}' if delivery.action else ''} "
                f"status=`{delivery.status_code or 'unknown'}` at `{delivery.delivered_at or 'unknown'}`"
            )
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


def _fleet_signal_summary_line(signal: FleetSignal) -> str:
    return (
        f"- [{signal.kind_label}] {signal.target_path} {signal.dependency_name}@{signal.current_version} "
        f"{signal.vulnerability_id} urgency={signal.urgency_label} "
        f"patch-gap={'yes' if signal.patch_gap else 'no'} "
        f"public-days={signal.days_since_public if signal.days_since_public is not None else 'n/a'}"
    )


def _scorecard_target_summary_line(target: TargetScorecard) -> str:
    return (
        f"- [{target.grade}] {target.target_path} score={target.score} "
        f"status={target.status_label} trend={target.trend_label} "
        f"open={target.open_finding_count} urgent={target.urgent_open_finding_count} "
        f"patch-gap={target.patch_gap_open_finding_count}"
    )
