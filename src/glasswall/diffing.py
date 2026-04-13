from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from glasswall.models import Finding, ScanResult, urgency_rank


@dataclass(frozen=True, slots=True)
class SeverityChange:
    previous: Finding
    current: Finding


@dataclass(frozen=True, slots=True)
class ScanDelta:
    current_scan_id: int | None
    previous_scan_id: int | None
    new_findings: tuple[Finding, ...]
    resolved_findings: tuple[Finding, ...]
    escalated_findings: tuple[SeverityChange, ...]
    deescalated_findings: tuple[SeverityChange, ...]
    unchanged_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "current_scan_id": self.current_scan_id,
            "previous_scan_id": self.previous_scan_id,
            "new_findings": [asdict(finding) for finding in self.new_findings],
            "resolved_findings": [asdict(finding) for finding in self.resolved_findings],
            "escalated_findings": [
                {"previous": asdict(change.previous), "current": asdict(change.current)}
                for change in self.escalated_findings
            ],
            "deescalated_findings": [
                {"previous": asdict(change.previous), "current": asdict(change.current)}
                for change in self.deescalated_findings
            ],
            "unchanged_count": self.unchanged_count,
        }


def build_scan_delta(current: ScanResult, previous: ScanResult | None) -> ScanDelta:
    if previous is None:
        return ScanDelta(
            current_scan_id=current.scan_id,
            previous_scan_id=None,
            new_findings=current.findings,
            resolved_findings=(),
            escalated_findings=(),
            deescalated_findings=(),
            unchanged_count=0,
        )

    current_map = {finding.identity_key: finding for finding in current.findings}
    previous_map = {finding.identity_key: finding for finding in previous.findings}

    new_findings = tuple(
        sorted(
            (finding for key, finding in current_map.items() if key not in previous_map),
            key=lambda finding: (-urgency_rank(finding.urgency_label), -finding.urgency_score, finding.dependency.name),
        )
    )
    resolved_findings = tuple(
        sorted(
            (finding for key, finding in previous_map.items() if key not in current_map),
            key=lambda finding: (-urgency_rank(finding.urgency_label), -finding.urgency_score, finding.dependency.name),
        )
    )

    escalated: list[SeverityChange] = []
    deescalated: list[SeverityChange] = []
    unchanged_count = 0
    for key, current_finding in current_map.items():
        previous_finding = previous_map.get(key)
        if previous_finding is None:
            continue
        current_rank = urgency_rank(current_finding.urgency_label)
        previous_rank = urgency_rank(previous_finding.urgency_label)
        if current_rank > previous_rank or (
            current_rank == previous_rank and current_finding.urgency_score > previous_finding.urgency_score
        ):
            escalated.append(SeverityChange(previous=previous_finding, current=current_finding))
        elif current_rank < previous_rank or (
            current_rank == previous_rank and current_finding.urgency_score < previous_finding.urgency_score
        ):
            deescalated.append(SeverityChange(previous=previous_finding, current=current_finding))
        else:
            unchanged_count += 1

    escalated_findings = tuple(
        sorted(
            escalated,
            key=lambda change: (
                -urgency_rank(change.current.urgency_label),
                -change.current.urgency_score,
                change.current.dependency.name,
            ),
        )
    )
    deescalated_findings = tuple(
        sorted(
            deescalated,
            key=lambda change: (
                -urgency_rank(change.previous.urgency_label),
                -change.previous.urgency_score,
                change.previous.dependency.name,
            ),
        )
    )

    return ScanDelta(
        current_scan_id=current.scan_id,
        previous_scan_id=previous.scan_id,
        new_findings=new_findings,
        resolved_findings=resolved_findings,
        escalated_findings=escalated_findings,
        deescalated_findings=deescalated_findings,
        unchanged_count=unchanged_count,
    )

