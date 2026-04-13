from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

import yaml

from glasswall.models import Finding, ScanResult, urgency_rank


@dataclass(frozen=True, slots=True)
class ScanPolicy:
    path: str | None
    minimum_urgency: str
    fail_on: str | None
    patch_gap_only: bool
    max_findings: int | None
    ignore_advisories: frozenset[str]
    ignore_packages: frozenset[str]
    ignore_paths: tuple[str, ...]
    ignore_ecosystems: frozenset[str]


def default_scan_policy() -> ScanPolicy:
    return ScanPolicy(
        path=None,
        minimum_urgency="watch",
        fail_on=None,
        patch_gap_only=False,
        max_findings=None,
        ignore_advisories=frozenset(),
        ignore_packages=frozenset(),
        ignore_paths=(),
        ignore_ecosystems=frozenset(),
    )


def load_scan_policy(root: Path, explicit_path: str | None = None) -> ScanPolicy:
    candidate = _resolve_policy_path(root, explicit_path)
    if candidate is None:
        return default_scan_policy()

    payload = yaml.safe_load(candidate.read_text()) or {}
    if not isinstance(payload, dict):
        raise ValueError(f"Policy file must contain a mapping: {candidate}")

    ignore = payload.get("ignore", {})
    if ignore is None:
        ignore = {}
    if not isinstance(ignore, dict):
        raise ValueError(f"'ignore' must be a mapping in {candidate}")

    return ScanPolicy(
        path=str(candidate),
        minimum_urgency=_normalize_urgency(payload.get("minimum_urgency", "watch")),
        fail_on=_normalize_optional_urgency(payload.get("fail_on")),
        patch_gap_only=bool(payload.get("patch_gap_only", False)),
        max_findings=_normalize_positive_int(payload.get("max_findings")),
        ignore_advisories=frozenset(_normalize_identifier_list(ignore.get("advisories", []))),
        ignore_packages=frozenset(_normalize_package_list(ignore.get("packages", []))),
        ignore_paths=tuple(_normalize_string_list(ignore.get("paths", []))),
        ignore_ecosystems=frozenset(_normalize_string_list(ignore.get("ecosystems", []))),
    )


def apply_scan_policy(result: ScanResult, policy: ScanPolicy) -> ScanResult:
    findings = tuple(
        finding
        for finding in result.findings
        if _passes_policy(finding, policy)
    )
    if policy.max_findings is not None:
        findings = findings[: policy.max_findings]
    return ScanResult(
        scan_id=result.scan_id,
        target_path=result.target_path,
        generated_at=result.generated_at,
        dependencies=result.dependencies,
        findings=findings,
        policy_path=policy.path,
    )


def _passes_policy(finding: Finding, policy: ScanPolicy) -> bool:
    if urgency_rank(finding.urgency_label) < urgency_rank(policy.minimum_urgency):
        return False
    if policy.patch_gap_only and not finding.patch_gap:
        return False
    if finding.dependency.name.lower() in policy.ignore_packages:
        return False
    if finding.dependency.ecosystem in policy.ignore_ecosystems:
        return False
    if any(fnmatch(finding.dependency.source_file, pattern) for pattern in policy.ignore_paths):
        return False
    advisory_tokens = {
        finding.vulnerability.canonical_id.upper(),
        finding.vulnerability.osv_id.upper(),
        *(source_id.upper() for source_id in finding.vulnerability.source_ids),
        *(alias.upper() for alias in finding.vulnerability.aliases),
    }
    if advisory_tokens & policy.ignore_advisories:
        return False
    return True


def _resolve_policy_path(root: Path, explicit_path: str | None) -> Path | None:
    if explicit_path is not None:
        candidate = Path(explicit_path).expanduser().resolve()
        if not candidate.exists():
            raise FileNotFoundError(f"Policy file does not exist: {candidate}")
        return candidate

    for name in (".glasswall.yml", ".glasswall.yaml"):
        candidate = root / name
        if candidate.exists():
            return candidate
    return None


def _normalize_urgency(value: Any) -> str:
    normalized = str(value or "watch")
    if normalized not in {"watch", "high", "urgent", "critical-now"}:
        raise ValueError(f"Unsupported urgency label in policy: {normalized}")
    return normalized


def _normalize_optional_urgency(value: Any) -> str | None:
    if value in (None, ""):
        return None
    return _normalize_urgency(value)


def _normalize_positive_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    number = int(value)
    if number <= 0:
        raise ValueError("max_findings must be greater than 0")
    return number


def _normalize_identifier_list(values: Any) -> list[str]:
    return [value.upper() for value in _normalize_string_list(values)]


def _normalize_package_list(values: Any) -> list[str]:
    return [value.lower() for value in _normalize_string_list(values)]


def _normalize_string_list(values: Any) -> list[str]:
    if values in (None, ""):
        return []
    if not isinstance(values, list):
        raise ValueError("Expected a list in policy configuration")
    cleaned: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise ValueError("Policy lists must only contain strings")
        stripped = value.strip()
        if stripped:
            cleaned.append(stripped)
    return cleaned
