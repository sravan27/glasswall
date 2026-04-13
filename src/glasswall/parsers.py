from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

import yaml

from glasswall.models import Dependency


SUPPORTED_FILES = (
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "requirements.txt",
    "poetry.lock",
    "uv.lock",
    "Pipfile.lock",
    "Cargo.lock",
    "go.sum",
    "Gemfile.lock",
    "composer.lock",
)


def discover_manifests(root: Path) -> list[Path]:
    manifests: list[Path] = []
    for pattern in SUPPORTED_FILES:
        manifests.extend(root.rglob(pattern))
    return sorted(path for path in manifests if path.is_file())


def parse_dependencies(root: Path) -> tuple[Dependency, ...]:
    discovered = discover_manifests(root)
    seen: dict[tuple[str, str, str], Dependency] = {}
    for manifest in discovered:
        for dependency in parse_manifest(root, manifest):
            seen.setdefault(dependency.key(), dependency)
    return tuple(sorted(seen.values(), key=lambda item: (item.ecosystem, item.name, item.version)))


def parse_manifest(root: Path, manifest: Path) -> tuple[Dependency, ...]:
    name = manifest.name
    if name == "package-lock.json":
        return parse_package_lock(root, manifest)
    if name == "npm-shrinkwrap.json":
        return parse_package_lock(root, manifest)
    if name == "pnpm-lock.yaml":
        return parse_pnpm_lock(root, manifest)
    if name == "requirements.txt":
        return parse_requirements(root, manifest)
    if name == "poetry.lock":
        return parse_poetry_lock(root, manifest)
    if name == "uv.lock":
        return parse_uv_lock(root, manifest)
    if name == "Pipfile.lock":
        return parse_pipfile_lock(root, manifest)
    if name == "Cargo.lock":
        return parse_cargo_lock(root, manifest)
    if name == "go.sum":
        return parse_go_sum(root, manifest)
    if name == "Gemfile.lock":
        return parse_gemfile_lock(root, manifest)
    if name == "composer.lock":
        return parse_composer_lock(root, manifest)
    return ()


def _relative_source(root: Path, manifest: Path) -> str:
    return str(manifest.relative_to(root))


def parse_package_lock(root: Path, manifest: Path) -> tuple[Dependency, ...]:
    payload = json.loads(manifest.read_text())
    relative = _relative_source(root, manifest)
    found: dict[tuple[str, str, str], Dependency] = {}

    packages = payload.get("packages")
    if isinstance(packages, dict):
        for path, metadata in packages.items():
            if not path.startswith("node_modules/"):
                continue
            version = metadata.get("version")
            if not isinstance(version, str) or not version:
                continue
            name = path.removeprefix("node_modules/")
            dependency = Dependency("npm", name, version, relative)
            found[dependency.key()] = dependency
        return tuple(found.values())

    def walk(dependencies: dict[str, object]) -> None:
        for name, value in dependencies.items():
            if not isinstance(value, dict):
                continue
            version = value.get("version")
            if isinstance(version, str) and version:
                dependency = Dependency("npm", name, version, relative)
                found[dependency.key()] = dependency
            nested = value.get("dependencies")
            if isinstance(nested, dict):
                walk(nested)

    dependencies = payload.get("dependencies")
    if isinstance(dependencies, dict):
        walk(dependencies)
    return tuple(found.values())


def parse_requirements(root: Path, manifest: Path) -> tuple[Dependency, ...]:
    relative = _relative_source(root, manifest)
    dependencies: list[Dependency] = []
    pattern = re.compile(r"^\s*([A-Za-z0-9_.-]+)(?:\[[A-Za-z0-9_,.-]+\])?==([^\s;]+)")
    for raw_line in manifest.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = pattern.match(line)
        if match is None:
            continue
        name, version = match.groups()
        dependencies.append(Dependency("PyPI", normalize_python_name(name), version, relative))
    return tuple(dependencies)


def parse_poetry_lock(root: Path, manifest: Path) -> tuple[Dependency, ...]:
    return parse_poetry_like_lock(root, manifest)


def parse_uv_lock(root: Path, manifest: Path) -> tuple[Dependency, ...]:
    return parse_poetry_like_lock(root, manifest)


def parse_poetry_like_lock(root: Path, manifest: Path) -> tuple[Dependency, ...]:
    relative = _relative_source(root, manifest)
    payload = tomllib.loads(manifest.read_text())
    packages = payload.get("package", [])
    dependencies: list[Dependency] = []
    if not isinstance(packages, list):
        return ()
    for package in packages:
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        version = package.get("version")
        if isinstance(name, str) and isinstance(version, str):
            dependencies.append(Dependency("PyPI", normalize_python_name(name), version, relative))
    return tuple(dependencies)


def parse_pipfile_lock(root: Path, manifest: Path) -> tuple[Dependency, ...]:
    relative = _relative_source(root, manifest)
    payload = json.loads(manifest.read_text())
    dependencies: list[Dependency] = []
    for section in ("default", "develop"):
        values = payload.get(section, {})
        if not isinstance(values, dict):
            continue
        for name, metadata in values.items():
            if not isinstance(metadata, dict):
                continue
            version = metadata.get("version")
            if not isinstance(version, str):
                continue
            cleaned = version.removeprefix("==")
            if cleaned:
                dependencies.append(Dependency("PyPI", normalize_python_name(name), cleaned, relative))
    return tuple(dependencies)


def parse_cargo_lock(root: Path, manifest: Path) -> tuple[Dependency, ...]:
    relative = _relative_source(root, manifest)
    payload = tomllib.loads(manifest.read_text())
    packages = payload.get("package", [])
    dependencies: list[Dependency] = []
    if not isinstance(packages, list):
        return ()
    for package in packages:
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        version = package.get("version")
        if isinstance(name, str) and isinstance(version, str):
            dependencies.append(Dependency("crates.io", name, version, relative))
    return tuple(dependencies)


def parse_go_sum(root: Path, manifest: Path) -> tuple[Dependency, ...]:
    relative = _relative_source(root, manifest)
    dependencies: dict[tuple[str, str, str], Dependency] = {}
    for raw_line in manifest.read_text().splitlines():
        parts = raw_line.split()
        if len(parts) < 2:
            continue
        name, version = parts[:2]
        if version.endswith("/go.mod"):
            version = version.removesuffix("/go.mod")
        dependency = Dependency("Go", name, version, relative)
        dependencies[dependency.key()] = dependency
    return tuple(dependencies.values())


def parse_pnpm_lock(root: Path, manifest: Path) -> tuple[Dependency, ...]:
    relative = _relative_source(root, manifest)
    payload = yaml.safe_load(manifest.read_text())
    if not isinstance(payload, dict):
        return ()

    dependencies: dict[tuple[str, str, str], Dependency] = {}
    packages = payload.get("packages", {})
    if isinstance(packages, dict):
        for key, metadata in packages.items():
            if not isinstance(metadata, dict):
                continue
            name, version = parse_pnpm_package_key(str(key))
            if not name or not version:
                continue
            dependency = Dependency("npm", name, version, relative)
            dependencies[dependency.key()] = dependency
    return tuple(dependencies.values())


def parse_gemfile_lock(root: Path, manifest: Path) -> tuple[Dependency, ...]:
    relative = _relative_source(root, manifest)
    dependencies: dict[tuple[str, str, str], Dependency] = {}
    in_specs = False
    for raw_line in manifest.read_text().splitlines():
        if raw_line.startswith("GEM"):
            continue
        if raw_line.startswith("  specs:"):
            in_specs = True
            continue
        if in_specs and raw_line and not raw_line.startswith("    "):
            in_specs = False
        if not in_specs:
            continue
        match = re.match(r"^\s{4}([A-Za-z0-9_.-]+) \(([^)]+)\)$", raw_line)
        if match is None:
            continue
        name, version = match.groups()
        dependency = Dependency("RubyGems", name, version.strip(), relative)
        dependencies[dependency.key()] = dependency
    return tuple(dependencies.values())


def parse_composer_lock(root: Path, manifest: Path) -> tuple[Dependency, ...]:
    relative = _relative_source(root, manifest)
    payload = json.loads(manifest.read_text())
    dependencies: dict[tuple[str, str, str], Dependency] = {}
    for section in ("packages", "packages-dev"):
        packages = payload.get(section, [])
        if not isinstance(packages, list):
            continue
        for package in packages:
            if not isinstance(package, dict):
                continue
            name = package.get("name")
            version = package.get("version")
            if isinstance(name, str) and isinstance(version, str):
                cleaned_version = version.lstrip("v")
                dependency = Dependency("Packagist", name, cleaned_version, relative)
                dependencies[dependency.key()] = dependency
    return tuple(dependencies.values())


def parse_pnpm_package_key(key: str) -> tuple[str | None, str | None]:
    cleaned = key.lstrip("/")
    if not cleaned:
        return None, None
    if "(" in cleaned:
        cleaned = cleaned.split("(", 1)[0]
    if "@" not in cleaned:
        return None, None
    if cleaned.startswith("@"):
        split_at = cleaned.rfind("@")
        if split_at <= 0:
            return None, None
        return cleaned[:split_at], cleaned[split_at + 1 :]
    name, version = cleaned.rsplit("@", 1)
    return name, version


def normalize_python_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()
