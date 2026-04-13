from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

import httpx
from packaging.version import InvalidVersion as InvalidPythonVersion
from packaging.version import Version as PythonVersion
from semantic_version import Version as SemverVersion

from glasswall.cache import JsonFileCache
from glasswall.models import PackageMetadata

PYPI_PROJECT_URL = "https://pypi.org/pypi/{name}/json"
NPM_PACKAGE_URL = "https://registry.npmjs.org/{name}"


class RegistryClient:
    def __init__(
        self,
        timeout_seconds: float = 20.0,
        cache: JsonFileCache | None = None,
        metadata_ttl_seconds: int = 21600,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.cache = cache
        self.metadata_ttl_seconds = metadata_ttl_seconds

    async def fetch_metadata(self, ecosystem: str, name: str) -> PackageMetadata | None:
        if ecosystem not in {"PyPI", "npm"}:
            return None
        cache_key = f"registry:metadata:v1:{ecosystem}:{name.lower()}"
        cached = self.cache.get_json(cache_key) if self.cache is not None else None
        if isinstance(cached, dict):
            return _metadata_from_payload(cached)

        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            try:
                if ecosystem == "PyPI":
                    metadata = await self._fetch_pypi_metadata(client, name)
                else:
                    metadata = await self._fetch_npm_metadata(client, name)
            except httpx.HTTPError:
                return None

        if self.cache is not None and metadata is not None:
            self.cache.set_json(cache_key, _metadata_to_payload(metadata), self.metadata_ttl_seconds)
        return metadata

    async def _fetch_pypi_metadata(self, client: httpx.AsyncClient, name: str) -> PackageMetadata | None:
        response = await client.get(PYPI_PROJECT_URL.format(name=quote(name, safe="")))
        response.raise_for_status()
        body = response.json()
        info = body.get("info", {})
        latest_version = info.get("version") if isinstance(info.get("version"), str) else None
        releases = body.get("releases", {})
        latest_published = None
        if latest_version and isinstance(releases, dict):
            published_candidates = []
            for file_info in releases.get(latest_version, []):
                if not isinstance(file_info, dict):
                    continue
                upload_time = file_info.get("upload_time_iso_8601") or file_info.get("upload_time")
                normalized = _normalize_datetime(upload_time)
                if normalized:
                    published_candidates.append(normalized)
            if published_candidates:
                latest_published = min(published_candidates)
        return PackageMetadata(
            ecosystem="PyPI",
            name=name,
            latest_version=latest_version,
            latest_published=latest_published,
            registry_url=f"https://pypi.org/project/{name}/",
            repository_url=_extract_repository_url(info),
        )

    async def _fetch_npm_metadata(self, client: httpx.AsyncClient, name: str) -> PackageMetadata | None:
        response = await client.get(NPM_PACKAGE_URL.format(name=quote(name, safe="@/")))
        response.raise_for_status()
        body = response.json()
        dist_tags = body.get("dist-tags", {})
        latest_version = dist_tags.get("latest") if isinstance(dist_tags, dict) and isinstance(dist_tags.get("latest"), str) else None
        latest_published = None
        time_map = body.get("time", {})
        if latest_version and isinstance(time_map, dict):
            latest_published = _normalize_datetime(time_map.get(latest_version))
        repository_url = _extract_npm_repository_url(body)
        return PackageMetadata(
            ecosystem="npm",
            name=name,
            latest_version=latest_version,
            latest_published=latest_published,
            registry_url=f"https://www.npmjs.com/package/{name}",
            repository_url=repository_url,
        )


def choose_target_version(ecosystem: str, current_version: str, fixed_versions: tuple[str, ...]) -> str | None:
    candidates = [version for version in fixed_versions if version]
    if ecosystem == "PyPI":
        return _choose_python_target(current_version, candidates)
    if ecosystem == "npm":
        return _choose_npm_target(current_version, candidates)
    return candidates[0] if candidates else None


def choose_group_target_version(ecosystem: str, current_version: str, advisory_fixed_versions: tuple[tuple[str, ...], ...]) -> str | None:
    per_advisory: list[str] = []
    for fixed_versions in advisory_fixed_versions:
        target = choose_target_version(ecosystem, current_version, fixed_versions)
        if target is not None:
            per_advisory.append(target)
    if not per_advisory:
        return None
    if ecosystem == "PyPI":
        return _max_python_version(per_advisory)
    if ecosystem == "npm":
        return _max_npm_version(per_advisory)
    return sorted(per_advisory)[-1]


def _choose_python_target(current_version: str, fixed_versions: list[str]) -> str | None:
    try:
        current = PythonVersion(current_version)
    except InvalidPythonVersion:
        return sorted(fixed_versions)[0] if fixed_versions else None
    parsed: list[tuple[PythonVersion, str]] = []
    for version in fixed_versions:
        try:
            parsed.append((PythonVersion(version), version))
        except InvalidPythonVersion:
            continue
    parsed.sort(key=lambda item: item[0])
    same_major = [item for item in parsed if item[0].major == current.major]
    for version, raw in same_major:
        if version >= current:
            return raw
    for version, raw in parsed:
        if version >= current:
            return raw
    return parsed[0][1] if parsed else None


def _choose_npm_target(current_version: str, fixed_versions: list[str]) -> str | None:
    current = _coerce_npm_version(current_version)
    parsed: list[tuple[SemverVersion, str]] = []
    for version in fixed_versions:
        coerced = _coerce_npm_version(version)
        if coerced is not None:
            parsed.append((coerced, version))
    parsed.sort(key=lambda item: item[0])
    if current is not None:
        same_major = [item for item in parsed if item[0].major == current.major]
        for version, raw in same_major:
            if version >= current:
                return raw
    for version, raw in parsed:
        if current is None or version >= current:
            return raw
    return parsed[0][1] if parsed else None


def _max_python_version(versions: list[str]) -> str:
    parsed = []
    for version in versions:
        try:
            parsed.append((PythonVersion(version), version))
        except InvalidPythonVersion:
            continue
    if not parsed:
        return sorted(versions)[-1]
    parsed.sort(key=lambda item: item[0])
    return parsed[-1][1]


def _max_npm_version(versions: list[str]) -> str:
    parsed = [(coerced, version) for version in versions if (coerced := _coerce_npm_version(version)) is not None]
    if not parsed:
        return sorted(versions)[-1]
    parsed.sort(key=lambda item: item[0])
    return parsed[-1][1]


def _coerce_npm_version(value: str) -> SemverVersion | None:
    cleaned = value.lstrip("v")
    try:
        return SemverVersion.coerce(cleaned, partial=False)
    except ValueError:
        return None


def _metadata_to_payload(metadata: PackageMetadata) -> dict[str, Any]:
    return {
        "ecosystem": metadata.ecosystem,
        "name": metadata.name,
        "latest_version": metadata.latest_version,
        "latest_published": metadata.latest_published,
        "registry_url": metadata.registry_url,
        "repository_url": metadata.repository_url,
    }


def _metadata_from_payload(payload: dict[str, Any]) -> PackageMetadata:
    return PackageMetadata(
        ecosystem=str(payload.get("ecosystem")),
        name=str(payload.get("name")),
        latest_version=payload.get("latest_version"),
        latest_published=payload.get("latest_published"),
        registry_url=payload.get("registry_url"),
        repository_url=payload.get("repository_url"),
    )


def _extract_repository_url(info: dict[str, Any]) -> str | None:
    project_urls = info.get("project_urls")
    if isinstance(project_urls, dict):
        for key in ("Source", "Source Code", "Repository", "Homepage", "Home"):
            value = project_urls.get(key)
            if isinstance(value, str) and value:
                return value
    home_page = info.get("home_page")
    if isinstance(home_page, str) and home_page:
        return home_page
    package_url = info.get("package_url")
    if isinstance(package_url, str) and package_url:
        return package_url
    return None


def _extract_npm_repository_url(body: dict[str, Any]) -> str | None:
    repository = body.get("repository")
    if isinstance(repository, dict):
        url = repository.get("url")
        if isinstance(url, str) and url:
            return url
    if isinstance(repository, str) and repository:
        return repository
    homepage = body.get("homepage")
    if isinstance(homepage, str) and homepage:
        return homepage
    return None


def _normalize_datetime(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(UTC).replace(microsecond=0).isoformat()
