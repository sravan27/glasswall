from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

URGENCY_RANKS = {
    "watch": 0,
    "high": 1,
    "urgent": 2,
    "critical-now": 3,
}


def utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


@dataclass(frozen=True, slots=True)
class Dependency:
    ecosystem: str
    name: str
    version: str
    source_file: str

    def key(self) -> tuple[str, str, str]:
        return (self.ecosystem, self.name.lower(), self.version)


@dataclass(frozen=True, slots=True)
class Vulnerability:
    osv_id: str
    source_ids: tuple[str, ...]
    aliases: tuple[str, ...]
    summary: str | None
    details: str | None
    published: str | None
    modified: str | None
    fixed_versions: tuple[str, ...]
    references: tuple[str, ...]
    kev: bool = False
    kev_due_date: str | None = None
    kev_ransomware: str | None = None

    @property
    def canonical_id(self) -> str:
        for alias in self.aliases:
            if alias.startswith("CVE-"):
                return alias
        for alias in self.aliases:
            if alias.startswith("GHSA-"):
                return alias
        for source_id in self.source_ids:
            if source_id.startswith("GHSA-"):
                return source_id
        return self.osv_id


@dataclass(frozen=True, slots=True)
class Finding:
    dependency: Dependency
    vulnerability: Vulnerability
    urgency_score: int
    urgency_label: str
    patch_gap: bool
    rationale: tuple[str, ...]

    @property
    def identity_key(self) -> str:
        return "|".join(
            (
                self.dependency.source_file,
                self.dependency.ecosystem,
                self.dependency.name.lower(),
                self.dependency.version,
                self.vulnerability.canonical_id,
            )
        )


@dataclass(frozen=True, slots=True)
class ScanResult:
    scan_id: int | None
    target_path: str
    generated_at: str
    dependencies: tuple[Dependency, ...]
    findings: tuple[Finding, ...]
    policy_path: str | None = None

    @property
    def dependency_count(self) -> int:
        return len(self.dependencies)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def top_urgency_label(self) -> str | None:
        if not self.findings:
            return None
        return max(self.findings, key=lambda finding: urgency_rank(finding.urgency_label)).urgency_label

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["dependency_count"] = self.dependency_count
        payload["finding_count"] = self.finding_count
        payload["top_urgency_label"] = self.top_urgency_label
        return payload


@dataclass(frozen=True, slots=True)
class ScanOverview:
    scan_id: int
    target_path: str
    generated_at: str
    dependency_count: int
    finding_count: int
    top_urgency_label: str | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def urgency_rank(label: str | None) -> int:
    if label is None:
        return -1
    return URGENCY_RANKS.get(label, -1)


@dataclass(frozen=True, slots=True)
class PackageMetadata:
    ecosystem: str
    name: str
    latest_version: str | None
    latest_published: str | None
    registry_url: str | None
    repository_url: str | None


@dataclass(frozen=True, slots=True)
class RemediationRecommendation:
    ecosystem: str
    name: str
    source_file: str
    current_version: str
    target_version: str | None
    latest_version: str | None
    latest_published: str | None
    registry_url: str | None
    repository_url: str | None
    rationale: tuple[str, ...]
    advisories: tuple[str, ...]
    urgency_label: str
    urgency_score: int
    patch_gap: bool
    action: str


@dataclass(frozen=True, slots=True)
class RemediationPlan:
    target_path: str
    generated_at: str
    policy_path: str | None
    recommendations: tuple[RemediationRecommendation, ...]

    @property
    def recommendation_count(self) -> int:
        return len(self.recommendations)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["recommendation_count"] = self.recommendation_count
        return payload


@dataclass(frozen=True, slots=True)
class RemediationFileChange:
    source_file: str
    ecosystem: str
    action: str
    package_names: tuple[str, ...]
    changed: bool
    before_digest: str | None
    after_digest: str | None


@dataclass(frozen=True, slots=True)
class RemediationSkip:
    name: str
    source_file: str
    current_version: str
    target_version: str | None
    action: str
    urgency_label: str
    reason: str


@dataclass(frozen=True, slots=True)
class RemediationRun:
    target_path: str
    generated_at: str
    policy_path: str | None
    apply_mode: bool
    changed_files: tuple[RemediationFileChange, ...]
    skipped: tuple[RemediationSkip, ...]

    @property
    def changed_file_count(self) -> int:
        return len(self.changed_files)

    @property
    def applied_recommendation_count(self) -> int:
        applied = {
            (change.ecosystem, str(Path(change.source_file).parent), package_name)
            for change in self.changed_files
            for package_name in change.package_names
        }
        return len(applied)

    @property
    def skipped_count(self) -> int:
        return len(self.skipped)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["changed_file_count"] = self.changed_file_count
        payload["applied_recommendation_count"] = self.applied_recommendation_count
        payload["skipped_count"] = self.skipped_count
        return payload
