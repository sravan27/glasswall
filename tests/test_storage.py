from glasswall.models import Dependency, ScanResult
from glasswall.storage import Database


def test_database_round_trips_dependencies_without_findings(tmp_path) -> None:
    database = Database(tmp_path / "glasswall.db")
    result = ScanResult(
        scan_id=None,
        target_path="/tmp/repo",
        generated_at="2026-04-09T00:00:00+00:00",
        dependencies=(
            Dependency("PyPI", "requests", "2.31.0", "requirements.txt"),
            Dependency("npm", "lodash", "4.17.21", "package-lock.json"),
        ),
        findings=(),
    )

    scan_id = database.save_scan(result)
    loaded = database.get_scan(scan_id)

    assert loaded is not None
    assert loaded.dependency_count == 2
    assert {dependency.name for dependency in loaded.dependencies} == {"requests", "lodash"}
    assert loaded.to_dict()["finding_count"] == 0
