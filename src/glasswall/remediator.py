from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Callable

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
PACKAGE_JSON_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies")
CommandRunner = Callable[[list[str], Path], None]


class RemediationApplier:
    def __init__(self, command_runner: CommandRunner | None = None) -> None:
        self.command_runner = command_runner or _run_command

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

            if source_file.endswith(("package-lock.json", "npm-shrinkwrap.json")):
                group_changes, group_skips = _apply_npm_lockfile(
                    source_file,
                    source_path,
                    recommendations,
                    apply=apply,
                    command_runner=self.command_runner,
                )
                changed_files.extend(group_changes)
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


def _apply_npm_lockfile(
    source_file: str,
    source_path: Path,
    recommendations: list[RemediationRecommendation],
    *,
    apply: bool,
    command_runner: CommandRunner,
) -> tuple[tuple[RemediationFileChange, ...], list[RemediationSkip]]:
    if shutil.which("npm") is None:
        return (), _skip_for_group(recommendations, "npm is not available in PATH.")

    package_dir = source_path.parent
    package_json_path = package_dir / "package.json"
    if not package_json_path.exists():
        return (), _skip_for_group(recommendations, "Adjacent package.json was not found for this lockfile.")

    try:
        package_payload = json.loads(package_json_path.read_text())
    except json.JSONDecodeError:
        return (), _skip_for_group(recommendations, "package.json is not valid JSON.")

    if not isinstance(package_payload, dict):
        return (), _skip_for_group(recommendations, "package.json must contain a JSON object.")

    skipped = [
        _skip_for_recommendation(recommendation, "No machine-readable target version is available.")
        for recommendation in recommendations
        if recommendation.target_version is None
    ]

    updated_payload = json.loads(json.dumps(package_payload))
    applied_names: list[str] = []
    supported_recommendations: list[RemediationRecommendation] = []

    for recommendation in recommendations:
        if recommendation.target_version is None:
            continue
        section, package_name, reason = _find_exact_npm_dependency(updated_payload, recommendation)
        if section is None or package_name is None:
            skipped.append(_skip_for_recommendation(recommendation, reason))
            continue
        section_payload = updated_payload[section]
        section_payload[package_name] = recommendation.target_version
        applied_names.append(recommendation.name)
        supported_recommendations.append(recommendation)

    if not supported_recommendations:
        return (), skipped

    original_package_json = package_json_path.read_text()
    original_lock_text = source_path.read_text()
    package_json_updated = _dump_json_with_trailing_newline(updated_payload, original_package_json)
    original_files = {
        package_json_path: original_package_json,
        source_path: original_lock_text,
    }

    package_json_path.write_text(package_json_updated)
    try:
        command_runner(
            ["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"],
            package_dir,
        )
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        _restore_files(original_files)
        reason = _command_failure_reason(exc)
        skipped.extend(_skip_for_group(supported_recommendations, reason))
        return (), skipped

    updated_package_json = package_json_path.read_text()
    updated_lock_text = source_path.read_text()

    changes: list[RemediationFileChange] = []
    package_names = tuple(sorted(set(applied_names)))
    if updated_package_json != original_package_json:
        changes.append(
            RemediationFileChange(
                source_file=str(Path(source_file).with_name("package.json")),
                ecosystem="npm",
                action="update-pinned-package-json",
                package_names=package_names,
                changed=True,
                before_digest=_digest_text(original_package_json),
                after_digest=_digest_text(updated_package_json),
            )
        )
    if updated_lock_text != original_lock_text:
        changes.append(
            RemediationFileChange(
                source_file=source_file,
                ecosystem="npm",
                action="refresh-node-lockfile",
                package_names=package_names,
                changed=True,
                before_digest=_digest_text(original_lock_text),
                after_digest=_digest_text(updated_lock_text),
            )
        )

    if not apply:
        _restore_files(original_files)

    return tuple(changes), skipped


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


def _find_exact_npm_dependency(
    payload: dict,
    recommendation: RemediationRecommendation,
) -> tuple[str | None, str | None, str]:
    normalized_name = recommendation.name.lower()
    reason = "Direct dependency entry was not found in package.json."
    for section in PACKAGE_JSON_SECTIONS:
        section_payload = payload.get(section)
        if not isinstance(section_payload, dict):
            continue
        for package_name, spec in section_payload.items():
            if not isinstance(package_name, str) or package_name.lower() != normalized_name:
                continue
            if not isinstance(spec, str) or spec.strip() != recommendation.current_version:
                reason = "Automatic npm remediation currently supports exact-pinned package.json entries only."
                continue
            return section, package_name, ""
    return None, None, reason


def _dump_json_with_trailing_newline(payload: dict, original_text: str) -> str:
    rendered = json.dumps(payload, indent=2)
    if original_text.endswith("\n"):
        rendered += "\n"
    return rendered


def _restore_files(files: dict[Path, str]) -> None:
    for path, content in files.items():
        path.write_text(content)


def _command_failure_reason(exc: FileNotFoundError | subprocess.CalledProcessError) -> str:
    if isinstance(exc, FileNotFoundError):
        return "npm is not available in PATH."
    stderr = (exc.stderr or "").strip()
    stdout = (exc.stdout or "").strip()
    detail = stderr or stdout or str(exc)
    detail = detail.splitlines()[0][:180]
    return f"npm lockfile refresh failed: {detail}"


def _run_command(args: list[str], cwd: Path) -> None:
    subprocess.run(
        args,
        cwd=cwd,
        check=True,
        text=True,
        capture_output=True,
        timeout=120,
    )
