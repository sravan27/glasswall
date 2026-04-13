from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from glasswall.models import Dependency, Finding, ScanOverview, ScanResult, Vulnerability

DEFAULT_DB_PATH = "glasswall.db"


class Database:
    def __init__(self, path: str | Path = DEFAULT_DB_PATH) -> None:
        self.path = str(path)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS scan_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_path TEXT NOT NULL,
                    generated_at TEXT NOT NULL,
                    dependency_count INTEGER NOT NULL,
                    finding_count INTEGER NOT NULL,
                    top_urgency_label TEXT,
                    policy_path TEXT
                );

                CREATE TABLE IF NOT EXISTS scan_dependencies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_run_id INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
                    ecosystem TEXT NOT NULL,
                    name TEXT NOT NULL,
                    version TEXT NOT NULL,
                    source_file TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_run_id INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
                    dependency_ecosystem TEXT NOT NULL,
                    dependency_name TEXT NOT NULL,
                    dependency_version TEXT NOT NULL,
                    source_file TEXT NOT NULL,
                    identity_key TEXT NOT NULL,
                    osv_id TEXT NOT NULL,
                    source_ids_json TEXT NOT NULL DEFAULT '[]',
                    aliases_json TEXT NOT NULL,
                    summary TEXT,
                    details TEXT,
                    published TEXT,
                    modified TEXT,
                    fixed_versions_json TEXT NOT NULL,
                    references_json TEXT NOT NULL,
                    kev INTEGER NOT NULL,
                    kev_due_date TEXT,
                    kev_ransomware TEXT,
                    urgency_score INTEGER NOT NULL,
                    urgency_label TEXT NOT NULL,
                    patch_gap INTEGER NOT NULL,
                    rationale_json TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_scan_runs_target_path ON scan_runs(target_path, id DESC);
                CREATE INDEX IF NOT EXISTS idx_scan_dependencies_scan_run_id ON scan_dependencies(scan_run_id);
                CREATE INDEX IF NOT EXISTS idx_findings_scan_run_id ON findings(scan_run_id);
                CREATE INDEX IF NOT EXISTS idx_findings_identity_key ON findings(identity_key);
                """
            )
            self._ensure_column(connection, "scan_runs", "top_urgency_label", "TEXT")
            self._ensure_column(connection, "scan_runs", "policy_path", "TEXT")
            self._ensure_column(connection, "findings", "identity_key", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(connection, "findings", "source_ids_json", "TEXT NOT NULL DEFAULT '[]'")

    def save_scan(self, result: ScanResult) -> int:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO scan_runs (
                    target_path,
                    generated_at,
                    dependency_count,
                    finding_count,
                    top_urgency_label,
                    policy_path
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    result.target_path,
                    result.generated_at,
                    result.dependency_count,
                    result.finding_count,
                    result.top_urgency_label,
                    result.policy_path,
                ),
            )
            scan_run_id = int(cursor.lastrowid)
            for dependency in result.dependencies:
                connection.execute(
                    """
                    INSERT INTO scan_dependencies (scan_run_id, ecosystem, name, version, source_file)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        scan_run_id,
                        dependency.ecosystem,
                        dependency.name,
                        dependency.version,
                        dependency.source_file,
                    ),
                )
            for finding in result.findings:
                connection.execute(
                    """
                    INSERT INTO findings (
                        scan_run_id,
                        dependency_ecosystem,
                        dependency_name,
                        dependency_version,
                        source_file,
                        identity_key,
                        osv_id,
                        source_ids_json,
                        aliases_json,
                        summary,
                        details,
                        published,
                        modified,
                        fixed_versions_json,
                        references_json,
                        kev,
                        kev_due_date,
                        kev_ransomware,
                        urgency_score,
                        urgency_label,
                        patch_gap,
                        rationale_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_run_id,
                        finding.dependency.ecosystem,
                        finding.dependency.name,
                        finding.dependency.version,
                        finding.dependency.source_file,
                        finding.identity_key,
                        finding.vulnerability.osv_id,
                        json.dumps(list(finding.vulnerability.source_ids)),
                        json.dumps(list(finding.vulnerability.aliases)),
                        finding.vulnerability.summary,
                        finding.vulnerability.details,
                        finding.vulnerability.published,
                        finding.vulnerability.modified,
                        json.dumps(list(finding.vulnerability.fixed_versions)),
                        json.dumps(list(finding.vulnerability.references)),
                        1 if finding.vulnerability.kev else 0,
                        finding.vulnerability.kev_due_date,
                        finding.vulnerability.kev_ransomware,
                        finding.urgency_score,
                        finding.urgency_label,
                        1 if finding.patch_gap else 0,
                        json.dumps(list(finding.rationale)),
                    ),
                )
            return scan_run_id

    def latest_scan(self, target_path: str | None = None) -> ScanResult | None:
        with self._connect() as connection:
            if target_path is None:
                run_row = connection.execute(
                    """
                    SELECT *
                    FROM scan_runs
                    ORDER BY id DESC
                    LIMIT 1
                    """
                ).fetchone()
            else:
                run_row = connection.execute(
                    """
                    SELECT *
                    FROM scan_runs
                    WHERE target_path = ?
                    ORDER BY id DESC
                    LIMIT 1
                    """,
                    (target_path,),
                ).fetchone()
            if run_row is None:
                return None
        return self.get_scan(int(run_row["id"]))

    def previous_scan(self, target_path: str, before_scan_id: int) -> ScanResult | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT *
                FROM scan_runs
                WHERE target_path = ? AND id < ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (target_path, before_scan_id),
            ).fetchone()
            if row is None:
                return None
        return self.get_scan(int(row["id"]))

    def get_scan(self, scan_id: int) -> ScanResult | None:
        with self._connect() as connection:
            run_row = connection.execute(
                """
                SELECT *
                FROM scan_runs
                WHERE id = ?
                """,
                (scan_id,),
            ).fetchone()
            if run_row is None:
                return None

            dependency_rows = connection.execute(
                """
                SELECT ecosystem, name, version, source_file
                FROM scan_dependencies
                WHERE scan_run_id = ?
                ORDER BY ecosystem ASC, name ASC, version ASC
                """,
                (scan_id,),
            ).fetchall()
            findings_rows = connection.execute(
                """
                SELECT *
                FROM findings
                WHERE scan_run_id = ?
                ORDER BY urgency_score DESC, dependency_name ASC, dependency_version ASC
                """,
                (scan_id,),
            ).fetchall()

        dependencies = tuple(
            Dependency(
                ecosystem=row["ecosystem"],
                name=row["name"],
                version=row["version"],
                source_file=row["source_file"],
            )
            for row in dependency_rows
        )
        findings = tuple(self._finding_from_row(row) for row in findings_rows)
        return ScanResult(
            scan_id=int(run_row["id"]),
            target_path=run_row["target_path"],
            generated_at=run_row["generated_at"],
            dependencies=dependencies,
            findings=findings,
            policy_path=run_row["policy_path"],
        )

    def list_scans(self, limit: int = 20, target_path: str | None = None) -> tuple[ScanOverview, ...]:
        with self._connect() as connection:
            if target_path is None:
                rows = connection.execute(
                    """
                    SELECT id, target_path, generated_at, dependency_count, finding_count, top_urgency_label
                    FROM scan_runs
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT id, target_path, generated_at, dependency_count, finding_count, top_urgency_label
                    FROM scan_runs
                    WHERE target_path = ?
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (target_path, limit),
                ).fetchall()
        return tuple(
            ScanOverview(
                scan_id=int(row["id"]),
                target_path=row["target_path"],
                generated_at=row["generated_at"],
                dependency_count=int(row["dependency_count"]),
                finding_count=int(row["finding_count"]),
                top_urgency_label=row["top_urgency_label"],
            )
            for row in rows
        )

    def latest_scan_summary(self, target_path: str | None = None) -> dict[str, Any] | None:
        latest = self.latest_scan(target_path=target_path)
        if latest is None:
            return None
        return latest.to_dict()

    def _finding_from_row(self, row: sqlite3.Row) -> Finding:
        dependency = Dependency(
            ecosystem=row["dependency_ecosystem"],
            name=row["dependency_name"],
            version=row["dependency_version"],
            source_file=row["source_file"],
        )
        vulnerability = Vulnerability(
            osv_id=row["osv_id"],
            source_ids=tuple(json.loads(row["source_ids_json"])),
            aliases=tuple(json.loads(row["aliases_json"])),
            summary=row["summary"],
            details=row["details"],
            published=row["published"],
            modified=row["modified"],
            fixed_versions=tuple(json.loads(row["fixed_versions_json"])),
            references=tuple(json.loads(row["references_json"])),
            kev=bool(row["kev"]),
            kev_due_date=row["kev_due_date"],
            kev_ransomware=row["kev_ransomware"],
        )
        return Finding(
            dependency=dependency,
            vulnerability=vulnerability,
            urgency_score=row["urgency_score"],
            urgency_label=row["urgency_label"],
            patch_gap=bool(row["patch_gap"]),
            rationale=tuple(json.loads(row["rationale_json"])),
        )

    def _ensure_column(self, connection: sqlite3.Connection, table: str, column: str, column_definition: str) -> None:
        columns = {
            row["name"]
            for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
        }
        if column in columns:
            return
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {column_definition}")
