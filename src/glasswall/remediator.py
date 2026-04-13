from __future__ import annotations

import hashlib
import re
from pathlib import Path

from glasswall.models import (
    RemediationFileChange,
    RemediationPlan,
    RemediationRecommendation,
    RemediationRun,
    RemediationSkip,
    utc_now_iso,
)
from glasswall.parsers import normalize_python_name

REQUIREMENT_PIN_RE = re.compile(r"^(\s*)([A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?)(==)([^\s;#]+)(.*)$")


class RemediationApplier:
    def apply_plan(
        self,
        root: Path,
        plan: RemediationPlan,
        *,
        apply: bool = False,
        max_recommendations: int | None = None,
    ) -> RemediationRun:
        root = root.expanduser().resolve()
        selected = plan.recommendations if max_recommendations is None else plan.recommendations[:max_recommendations]
        grouped = _group_recommendations(selected)

        changed_files: list[RemediationFileChange] = []
        skipped: list[RemediationSkip] = []

        for source_file, recommendations in grouped.items():
            source_path = root / source_file
            if not source_path.exists():
                skipped.extend(_skip_for_group(recommendations, "Source file no longer exists."))
                continue

            if source_file.endswith("requirements.txt"):
                change, group_skips = _apply_requirements_txt(
                    source_file,
                    source_path,
                    recommendations,
                    apply=apply,
                )
                if change is not None:
                    changed_files.append(change)
                skipped.extend(group_skips)
                continue

            skipped.extend(_skip_for_group(recommendations, "Automatic remediation is not yet supported for this manifest."))

        return RemediationRun(
            target_path=str(root),
            generated_at=utc_now_iso(),
            policy_path=plan.policy_path,
            apply_mode=apply,
            changed_files=tuple(changed_files),
            skipped=tuple(skipped),
        )


def _group_recommendations(
    recommendations: tuple[RemediationRecommendation, ...],
) -> dict[str, list[RemediationRecommendation]]:
    grouped: dict[str, list[RemediationRecommendation]] = {}
    for recommendation in recommendations:
        grouped.setdefault(recommendation.source_file, []).append(recommendation)
    return grouped


def _apply_requirements_txt(
    source_file: str,
    source_path: Path,
    recommendations: list[RemediationRecommendation],
    *,
    apply: bool,
) -> tuple[RemediationFileChange | None, list[RemediationSkip]]:
    updatable = {
        normalize_python_name(recommendation.name): recommendation
        for recommendation in recommendations
        if recommendation.target_version is not None
    }
    skipped = [
        _skip_for_recommendation(recommendation, "No machine-readable target version is available.")
        for recommendation in recommendations
        if recommendation.target_version is None
    ]
    if not updatable:
        return None, skipped

    original_text = source_path.read_text()
    updated_lines: list[str] = []
    applied_names: list[str] = []
    seen_names: set[str] = set()

    for line in original_text.splitlines():
        match = REQUIREMENT_PIN_RE.match(line)
        if match is None:
            updated_lines.append(line)
            continue

        prefix, requirement_name, operator, current_version, suffix = match.groups()
        package_name = normalize_python_name(requirement_name.split("[", 1)[0])
        recommendation = updatable.get(package_name)
        if recommendation is None or recommendation.target_version == current_version:
            updated_lines.append(line)
            continue

        updated_lines.append(f"{prefix}{requirement_name}{operator}{recommendation.target_version}{suffix}")
        applied_names.append(recommendation.name)
        seen_names.add(package_name)

    for package_name, recommendation in updatable.items():
        if package_name not in seen_names:
            skipped.append(_skip_for_recommendation(recommendation, "Pinned requirement line was not found in requirements.txt."))

    updated_text = "\n".join(updated_lines)
    if original_text.endswith("\n"):
        updated_text += "\n"
    changed = updated_text != original_text
    if apply and changed:
        source_path.write_text(updated_text)

    if not changed:
        return None, skipped

    return (
        RemediationFileChange(
            source_file=source_file,
            ecosystem="PyPI",
            action="update-pinned-requirement",
            package_names=tuple(sorted(set(applied_names))),
            changed=True,
            before_digest=_digest_text(original_text),
            after_digest=_digest_text(updated_text),
        ),
        skipped,
    )


def _skip_for_group(
    recommendations: list[RemediationRecommendation],
    reason: str,
) -> list[RemediationSkip]:
    return [_skip_for_recommendation(recommendation, reason) for recommendation in recommendations]


def _skip_for_recommendation(recommendation: RemediationRecommendation, reason: str) -> RemediationSkip:
    return RemediationSkip(
        name=recommendation.name,
        source_file=recommendation.source_file,
        current_version=recommendation.current_version,
        target_version=recommendation.target_version,
        action=recommendation.action,
        urgency_label=recommendation.urgency_label,
        reason=reason,
    )


def _digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
