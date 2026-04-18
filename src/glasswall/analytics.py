from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from statistics import mean
from typing import Any

from glasswall.diffing import build_scan_delta
from glasswall.models import ScanResult, urgency_rank, utc_now_iso


@dataclass(frozen=True, slots=True)
class TargetPressure:
    target_path: str
    latest_scan_id: int | None
    latest_generated_at: str | None
    dependency_count: int
    open_finding_count: int
    urgent_open_finding_count: int
    patch_gap_open_finding_count: int
    top_urgency_label: str | None
    oldest_open_public_days: float | None
    average_resolved_mttp_days: float | None
    average_resolved_detection_days: float | None
    resolved_finding_count: int
    newly_dangerous_count: int = 0
    recently_resolved_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class FleetSignal:
    kind: str
    target_path: str
    scan_id: int | None
    generated_at: str
    dependency_name: str
    current_version: str
    source_file: str
    vulnerability_id: str
    urgency_label: str
    urgency_score: int
    patch_gap: bool
    previous_urgency_label: str | None = None
    days_since_public: float | None = None

    @property
    def kind_label(self) -> str:
        if self.kind == "new":
            return "Newly dangerous"
        if self.kind == "escalated":
            return "Escalated"
        if self.kind == "resolved":
            return "Recently cleared"
        return self.kind.replace("-", " ").title()

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["kind_label"] = self.kind_label
        return payload


@dataclass(frozen=True, slots=True)
class FleetOverview:
    generated_at: str
    target_count: int
    total_open_findings: int
    total_urgent_findings: int
    total_patch_gap_findings: int
    average_resolved_mttp_days: float | None
    hottest_target_path: str | None
    targets: tuple[TargetPressure, ...]
    newly_dangerous_count: int = 0
    recently_resolved_count: int = 0
    signals: tuple[FleetSignal, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "target_count": self.target_count,
            "total_open_findings": self.total_open_findings,
            "total_urgent_findings": self.total_urgent_findings,
            "total_patch_gap_findings": self.total_patch_gap_findings,
            "average_resolved_mttp_days": self.average_resolved_mttp_days,
            "hottest_target_path": self.hottest_target_path,
            "targets": [target.to_dict() for target in self.targets],
            "newly_dangerous_count": self.newly_dangerous_count,
            "recently_resolved_count": self.recently_resolved_count,
            "signals": [signal.to_dict() for signal in self.signals],
        }


@dataclass(frozen=True, slots=True)
class TargetScorecard:
    target_path: str
    latest_scan_id: int | None
    latest_generated_at: str | None
    score: int
    grade: str
    status_label: str
    trend_label: str
    summary: str
    reasons: tuple[str, ...]
    open_finding_count: int
    urgent_open_finding_count: int
    patch_gap_open_finding_count: int
    newly_dangerous_count: int
    recently_resolved_count: int
    oldest_open_public_days: float | None
    average_resolved_mttp_days: float | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class FleetScorecard:
    generated_at: str
    fleet_score: int
    grade: str
    status_label: str
    trend_label: str
    summary: str
    average_target_score: float | None
    strongest_target_path: str | None
    weakest_target_path: str | None
    healthy_target_count: int
    exposed_target_count: int
    targets: tuple[TargetScorecard, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "fleet_score": self.fleet_score,
            "grade": self.grade,
            "status_label": self.status_label,
            "trend_label": self.trend_label,
            "summary": self.summary,
            "average_target_score": self.average_target_score,
            "strongest_target_path": self.strongest_target_path,
            "weakest_target_path": self.weakest_target_path,
            "healthy_target_count": self.healthy_target_count,
            "exposed_target_count": self.exposed_target_count,
            "targets": [target.to_dict() for target in self.targets],
        }


def build_target_pressure(history: tuple[ScanResult, ...]) -> TargetPressure:
    if not history:
        raise ValueError("Target history must contain at least one scan")

    scans = tuple(sorted(history, key=lambda scan: scan.scan_id or 0))
    latest = scans[-1]
    current_findings = latest.findings
    urgent_open_finding_count = sum(
        1 for finding in current_findings if finding.urgency_label in {"urgent", "critical-now"}
    )
    patch_gap_open_finding_count = sum(1 for finding in current_findings if finding.patch_gap)
    oldest_open_public_days = _max_or_none(
        _days_between(_published_or_modified(finding), latest.generated_at)
        for finding in current_findings
    )

    active: dict[str, tuple[str, str | None, bool]] = {}
    resolved_mttp_days: list[float] = []
    resolved_detection_days: list[float] = []
    for scan in scans:
        current_map = {finding.identity_key: finding for finding in scan.findings}
        for identity_key, finding in current_map.items():
            active.setdefault(identity_key, (scan.generated_at, _published_or_modified(finding), finding.patch_gap))

        resolved_ids = [identity_key for identity_key in active if identity_key not in current_map]
        for identity_key in resolved_ids:
            first_seen_at, published_at, was_patch_gap = active.pop(identity_key)
            detection_days = _days_between(first_seen_at, scan.generated_at)
            if detection_days is not None:
                resolved_detection_days.append(detection_days)
            public_days = _days_between(published_at or first_seen_at, scan.generated_at)
            if was_patch_gap and public_days is not None:
                resolved_mttp_days.append(public_days)
    signals = _signals_for_history(scans)

    return TargetPressure(
        target_path=latest.target_path,
        latest_scan_id=latest.scan_id,
        latest_generated_at=latest.generated_at,
        dependency_count=latest.dependency_count,
        open_finding_count=latest.finding_count,
        urgent_open_finding_count=urgent_open_finding_count,
        patch_gap_open_finding_count=patch_gap_open_finding_count,
        top_urgency_label=latest.top_urgency_label,
        oldest_open_public_days=oldest_open_public_days,
        average_resolved_mttp_days=_round_or_none(_mean_or_none(resolved_mttp_days)),
        average_resolved_detection_days=_round_or_none(_mean_or_none(resolved_detection_days)),
        resolved_finding_count=len(resolved_mttp_days),
        newly_dangerous_count=sum(1 for signal in signals if signal.kind in {"new", "escalated"}),
        recently_resolved_count=sum(1 for signal in signals if signal.kind == "resolved"),
    )


def build_fleet_overview(histories: tuple[tuple[ScanResult, ...], ...]) -> FleetOverview:
    targets = tuple(build_target_pressure(history) for history in histories if history)
    ranked_targets = tuple(sorted(targets, key=_target_sort_key))
    signals = tuple(sorted((signal for history in histories for signal in _signals_for_history(history)), key=_signal_sort_key))
    all_resolved_mttp_days = [
        target.average_resolved_mttp_days
        for target in ranked_targets
        if target.average_resolved_mttp_days is not None
    ]
    return FleetOverview(
        generated_at=utc_now_iso(),
        target_count=len(ranked_targets),
        total_open_findings=sum(target.open_finding_count for target in ranked_targets),
        total_urgent_findings=sum(target.urgent_open_finding_count for target in ranked_targets),
        total_patch_gap_findings=sum(target.patch_gap_open_finding_count for target in ranked_targets),
        average_resolved_mttp_days=_round_or_none(_mean_or_none(all_resolved_mttp_days)),
        hottest_target_path=ranked_targets[0].target_path if ranked_targets else None,
        targets=ranked_targets,
        newly_dangerous_count=sum(1 for signal in signals if signal.kind in {"new", "escalated"}),
        recently_resolved_count=sum(1 for signal in signals if signal.kind == "resolved"),
        signals=signals,
    )


def build_target_scorecard(target: TargetPressure) -> TargetScorecard:
    score, reasons = _score_target(target)
    grade, status_label = _grade_for_score(score)
    trend_label = _trend_label(target.newly_dangerous_count, target.recently_resolved_count, target.open_finding_count)
    summary = reasons[0] if reasons else "No meaningful patch-gap history yet."
    return TargetScorecard(
        target_path=target.target_path,
        latest_scan_id=target.latest_scan_id,
        latest_generated_at=target.latest_generated_at,
        score=score,
        grade=grade,
        status_label=status_label,
        trend_label=trend_label,
        summary=summary,
        reasons=tuple(reasons[:4]),
        open_finding_count=target.open_finding_count,
        urgent_open_finding_count=target.urgent_open_finding_count,
        patch_gap_open_finding_count=target.patch_gap_open_finding_count,
        newly_dangerous_count=target.newly_dangerous_count,
        recently_resolved_count=target.recently_resolved_count,
        oldest_open_public_days=target.oldest_open_public_days,
        average_resolved_mttp_days=target.average_resolved_mttp_days,
    )


def build_fleet_scorecard(overview: FleetOverview) -> FleetScorecard:
    target_cards = tuple(sorted((build_target_scorecard(target) for target in overview.targets), key=_scorecard_sort_key, reverse=True))
    if not target_cards:
        return FleetScorecard(
            generated_at=utc_now_iso(),
            fleet_score=0,
            grade="n/a",
            status_label="bootstrapping",
            trend_label="steady",
            summary="No fleet history is available yet.",
            average_target_score=None,
            strongest_target_path=None,
            weakest_target_path=None,
            healthy_target_count=0,
            exposed_target_count=0,
            targets=(),
        )
    average_target_score = _round_or_none(_mean_or_none([float(target.score) for target in target_cards]))
    fleet_score = int(round(average_target_score or 0.0))
    grade, status_label = _grade_for_score(fleet_score)
    strongest = target_cards[0].target_path if target_cards else None
    weakest = target_cards[-1].target_path if target_cards else None
    healthy_target_count = sum(1 for target in target_cards if target.score >= 75)
    exposed_target_count = sum(1 for target in target_cards if target.score < 60)
    summary = _fleet_summary(target_cards, overview)
    return FleetScorecard(
        generated_at=utc_now_iso(),
        fleet_score=fleet_score,
        grade=grade,
        status_label=status_label,
        trend_label=_trend_label(overview.newly_dangerous_count, overview.recently_resolved_count, overview.total_open_findings),
        summary=summary,
        average_target_score=average_target_score,
        strongest_target_path=strongest,
        weakest_target_path=weakest,
        healthy_target_count=healthy_target_count,
        exposed_target_count=exposed_target_count,
        targets=target_cards,
    )


def _target_sort_key(target: TargetPressure) -> tuple[int, int, int, float, str]:
    return (
        -urgency_rank(target.top_urgency_label),
        -target.urgent_open_finding_count,
        -target.patch_gap_open_finding_count,
        -(target.oldest_open_public_days or -1.0),
        target.target_path,
    )


def _signal_sort_key(signal: FleetSignal) -> tuple[int, int, int, float, str, str]:
    return (
        _signal_priority(signal.kind),
        -urgency_rank(signal.urgency_label),
        -signal.urgency_score,
        -_timestamp_or_zero(signal.generated_at),
        signal.target_path,
        signal.dependency_name,
    )


def _signal_priority(kind: str) -> int:
    if kind == "new":
        return 0
    if kind == "escalated":
        return 1
    if kind == "resolved":
        return 2
    return 3


def _scorecard_sort_key(target: TargetScorecard) -> tuple[int, int, int, str]:
    return (
        target.score,
        -target.open_finding_count,
        -target.newly_dangerous_count,
        target.target_path,
    )


def _signals_for_history(history: tuple[ScanResult, ...]) -> tuple[FleetSignal, ...]:
    if len(history) < 2:
        return ()

    scans = tuple(sorted(history, key=lambda scan: scan.scan_id or 0))
    latest = scans[-1]
    previous = scans[-2]
    delta = build_scan_delta(latest, previous)
    signals: list[FleetSignal] = []

    for finding in delta.new_findings:
        if _finding_is_dangerous(finding):
            signals.append(_build_signal("new", latest, finding))

    for change in delta.escalated_findings:
        if _finding_is_dangerous(change.current) or (not change.previous.patch_gap and change.current.patch_gap):
            signals.append(
                _build_signal(
                    "escalated",
                    latest,
                    change.current,
                    previous_urgency_label=change.previous.urgency_label,
                )
            )

    for finding in delta.resolved_findings:
        if _finding_is_dangerous(finding):
            signals.append(_build_signal("resolved", latest, finding, previous_urgency_label=finding.urgency_label))

    return tuple(signals)


def _build_signal(
    kind: str,
    scan: ScanResult,
    finding,
    *,
    previous_urgency_label: str | None = None,
) -> FleetSignal:
    return FleetSignal(
        kind=kind,
        target_path=scan.target_path,
        scan_id=scan.scan_id,
        generated_at=scan.generated_at,
        dependency_name=finding.dependency.name,
        current_version=finding.dependency.version,
        source_file=finding.dependency.source_file,
        vulnerability_id=finding.vulnerability.canonical_id,
        urgency_label=finding.urgency_label,
        urgency_score=finding.urgency_score,
        patch_gap=finding.patch_gap,
        previous_urgency_label=previous_urgency_label,
        days_since_public=_round_or_none(_days_between(_published_or_modified(finding), scan.generated_at)),
    )


def _finding_is_dangerous(finding) -> bool:
    return finding.patch_gap or urgency_rank(finding.urgency_label) >= urgency_rank("urgent")


def _published_or_modified(finding) -> str | None:
    return finding.vulnerability.published or finding.vulnerability.modified


def _score_target(target: TargetPressure) -> tuple[int, list[str]]:
    score = 100.0
    reasons: list[str] = []

    top_penalty = {
        "critical-now": 32.0,
        "urgent": 22.0,
        "high": 10.0,
    }.get(target.top_urgency_label or "", 0.0)
    if top_penalty:
        score -= top_penalty
        reasons.append(f"Top live urgency is {target.top_urgency_label}.")

    if target.urgent_open_finding_count:
        score -= min(target.urgent_open_finding_count * 4.5, 18.0)
        reasons.append(f"{target.urgent_open_finding_count} urgent findings are still open.")

    if target.patch_gap_open_finding_count:
        score -= min(target.patch_gap_open_finding_count * 3.5, 18.0)
        reasons.append(f"{target.patch_gap_open_finding_count} public-fix findings remain unpatched.")

    if target.oldest_open_public_days is not None and target.open_finding_count:
        score -= min(target.oldest_open_public_days * 1.1, 14.0)
        reasons.append(f"Oldest open public fix has been exposed for {target.oldest_open_public_days:.1f} days.")

    if target.newly_dangerous_count:
        score -= min(target.newly_dangerous_count * 4.0, 12.0)
        reasons.append(f"{target.newly_dangerous_count} dangerous findings appeared or escalated since the previous scan.")

    if target.recently_resolved_count:
        score += min(target.recently_resolved_count * 2.5, 10.0)
        reasons.append(f"{target.recently_resolved_count} dangerous findings were recently cleared.")

    if target.average_resolved_mttp_days is not None:
        if target.average_resolved_mttp_days <= 3:
            score += 12.0
            reasons.append(f"Resolved patch-gap MTTP is fast at {target.average_resolved_mttp_days:.1f} days.")
        elif target.average_resolved_mttp_days <= 7:
            score += 7.0
            reasons.append(f"Resolved patch-gap MTTP is healthy at {target.average_resolved_mttp_days:.1f} days.")
        elif target.average_resolved_mttp_days <= 14:
            reasons.append(f"Resolved patch-gap MTTP is moderate at {target.average_resolved_mttp_days:.1f} days.")
        elif target.average_resolved_mttp_days <= 21:
            score -= 6.0
            reasons.append(f"Resolved patch-gap MTTP is slowing down at {target.average_resolved_mttp_days:.1f} days.")
        else:
            score -= 12.0
            reasons.append(f"Resolved patch-gap MTTP is too slow at {target.average_resolved_mttp_days:.1f} days.")

    if target.open_finding_count == 0:
        score += 8.0
        reasons.insert(0, "Latest scan is clear of open findings.")

    if target.open_finding_count == 0 and target.resolved_finding_count == 0:
        score += 4.0

    return _clamp_score(score), reasons


def _grade_for_score(score: int) -> tuple[str, str]:
    if score >= 90:
        return ("A", "hardened")
    if score >= 75:
        return ("B", "stable")
    if score >= 60:
        return ("C", "exposed")
    if score >= 40:
        return ("D", "lagging")
    return ("F", "critical")


def _trend_label(newly_dangerous_count: int, recently_resolved_count: int, open_finding_count: int) -> str:
    if recently_resolved_count > newly_dangerous_count:
        return "recovering"
    if newly_dangerous_count > recently_resolved_count:
        return "backsliding"
    if open_finding_count == 0:
        return "steady"
    return "holding"


def _fleet_summary(targets: tuple[TargetScorecard, ...], overview: FleetOverview) -> str:
    if not targets:
        return "No fleet history is available yet."
    weakest = targets[-1]
    if weakest.score < 60:
        return f"{weakest.target_path} is dragging the fleet score down and needs patch-gap attention first."
    if overview.newly_dangerous_count > overview.recently_resolved_count:
        return "Newly dangerous findings are arriving faster than the fleet is clearing them."
    if overview.total_open_findings == 0:
        return "The fleet is currently clear of open findings."
    return "The fleet is holding, but patch-gap pressure is still active."


def _clamp_score(score: float) -> int:
    return max(0, min(100, int(round(score))))


def _days_between(start: str | None, end: str | None) -> float | None:
    if start is None or end is None:
        return None
    try:
        start_dt = datetime.fromisoformat(start.replace("Z", "+00:00")).astimezone(UTC)
        end_dt = datetime.fromisoformat(end.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None
    return max((end_dt - start_dt).total_seconds() / 86400.0, 0.0)


def _timestamp_or_zero(value: str | None) -> float:
    if value is None:
        return 0.0
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC).timestamp()
    except ValueError:
        return 0.0


def _mean_or_none(values: list[float]) -> float | None:
    if not values:
        return None
    return float(mean(values))


def _max_or_none(values) -> float | None:
    filtered = [value for value in values if value is not None]
    if not filtered:
        return None
    return _round_or_none(max(filtered))


def _round_or_none(value: float | None) -> float | None:
    if value is None:
        return None
    return round(value, 2)
