from __future__ import annotations

import asyncio
from collections.abc import Iterable
from datetime import UTC, datetime
import re
from typing import Any

import httpx

from glasswall.cache import JsonFileCache
from glasswall.models import Dependency, Vulnerability

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class AdvisoryClient:
    def __init__(
        self,
        timeout_seconds: float = 20.0,
        cache: JsonFileCache | None = None,
        osv_query_ttl_seconds: int = 21600,
        osv_vuln_ttl_seconds: int = 86400,
        kev_ttl_seconds: int = 21600,
        max_concurrent_detail_requests: int = 8,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.cache = cache
        self.osv_query_ttl_seconds = osv_query_ttl_seconds
        self.osv_vuln_ttl_seconds = osv_vuln_ttl_seconds
        self.kev_ttl_seconds = kev_ttl_seconds
        self.max_concurrent_detail_requests = max_concurrent_detail_requests

    async def lookup(self, dependencies: Iterable[Dependency]) -> dict[tuple[str, str, str], tuple[Vulnerability, ...]]:
        dependency_list = list(dependencies)
        if not dependency_list:
            return {}

        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            kev_index = await self.fetch_kev_index(client)
            matches = await self.fetch_vulnerability_matches(client, dependency_list)
            vulnerability_ids = {
                vuln_id
                for vuln_ids in matches.values()
                for vuln_id in vuln_ids
            }
            vulnerability_details = await self.fetch_vulnerability_details(client, vulnerability_ids)

        results: dict[tuple[str, str, str], tuple[Vulnerability, ...]] = {}
        for dependency in dependency_list:
            ids = matches.get(dependency.key(), ())
            parsed = tuple(
                self._parse_vulnerability(vulnerability_details[vuln_id], kev_index)
                for vuln_id in ids
                if vuln_id in vulnerability_details
            )
            parsed = self._deduplicate_vulnerabilities(parsed)
            if parsed:
                results[dependency.key()] = parsed
        return results

    async def fetch_kev_index(self, client: httpx.AsyncClient) -> dict[str, dict[str, Any]]:
        cache_key = "kev:index:v1"
        cached = self.cache.get_json(cache_key) if self.cache is not None else None
        if isinstance(cached, dict):
            return cached

        response = await client.get(CISA_KEV_URL)
        response.raise_for_status()
        body = response.json()

        vulnerabilities = body.get("vulnerabilities", [])
        index: dict[str, dict[str, Any]] = {}
        for item in vulnerabilities:
            if not isinstance(item, dict):
                continue
            cve = item.get("cveID")
            if isinstance(cve, str) and cve:
                index[cve] = item
        if self.cache is not None:
            self.cache.set_json(cache_key, index, self.kev_ttl_seconds)
        return index

    async def fetch_vulnerability_matches(
        self,
        client: httpx.AsyncClient,
        dependencies: list[Dependency],
    ) -> dict[tuple[str, str, str], tuple[str, ...]]:
        matches: dict[tuple[str, str, str], tuple[str, ...]] = {}
        uncached: list[Dependency] = []
        for dependency in dependencies:
            cache_key = self._query_cache_key(dependency)
            cached = self.cache.get_json(cache_key) if self.cache is not None else None
            if isinstance(cached, list) and all(isinstance(item, str) for item in cached):
                matches[dependency.key()] = tuple(cached)
                continue
            uncached.append(dependency)

        if not uncached:
            return matches

        payload = {
            "queries": [
                {
                    "package": {
                        "ecosystem": dependency.ecosystem,
                        "name": dependency.name,
                    },
                    "version": dependency.version,
                }
                for dependency in uncached
            ]
        }
        response = await client.post(OSV_BATCH_URL, json=payload)
        response.raise_for_status()
        body = response.json()
        for dependency, item in zip(uncached, body.get("results", []), strict=False):
            vuln_ids = tuple(
                vuln.get("id")
                for vuln in item.get("vulns", [])
                if isinstance(vuln, dict) and isinstance(vuln.get("id"), str)
            ) if isinstance(item, dict) else ()
            matches[dependency.key()] = vuln_ids
            if self.cache is not None:
                self.cache.set_json(self._query_cache_key(dependency), list(vuln_ids), self.osv_query_ttl_seconds)
        return matches

    async def fetch_vulnerability_details(
        self,
        client: httpx.AsyncClient,
        vulnerability_ids: set[str],
    ) -> dict[str, dict[str, Any]]:
        if not vulnerability_ids:
            return {}

        cached_results: dict[str, dict[str, Any]] = {}
        uncached_ids: list[str] = []
        for vuln_id in sorted(vulnerability_ids):
            cache_key = self._vulnerability_cache_key(vuln_id)
            cached = self.cache.get_json(cache_key) if self.cache is not None else None
            if isinstance(cached, dict):
                cached_results[vuln_id] = cached
            else:
                uncached_ids.append(vuln_id)

        async def fetch_one(vuln_id: str) -> tuple[str, dict[str, Any] | None]:
            response = await client.get(OSV_VULN_URL.format(vuln_id=vuln_id))
            response.raise_for_status()
            payload = response.json()
            if self.cache is not None:
                self.cache.set_json(self._vulnerability_cache_key(vuln_id), payload, self.osv_vuln_ttl_seconds)
            return vuln_id, payload

        semaphore = asyncio.Semaphore(self.max_concurrent_detail_requests)

        async def guarded_fetch(vuln_id: str) -> tuple[str, dict[str, Any] | None]:
            async with semaphore:
                try:
                    return await fetch_one(vuln_id)
                except httpx.HTTPError:
                    return vuln_id, None

        responses = await asyncio.gather(*(guarded_fetch(vuln_id) for vuln_id in uncached_ids))
        fetched_results = {
            vuln_id: payload
            for vuln_id, payload in responses
            if isinstance(payload, dict)
        }
        cached_results.update(fetched_results)
        return cached_results

    def _parse_vulnerability(
        self,
        payload: dict[str, Any],
        kev_index: dict[str, dict[str, Any]],
    ) -> Vulnerability:
        aliases = tuple(sorted({alias for alias in payload.get("aliases", []) if isinstance(alias, str)}))
        kev_record = next((kev_index[alias] for alias in aliases if alias in kev_index), None)
        references = tuple(
            reference.get("url")
            for reference in payload.get("references", [])
            if isinstance(reference, dict) and isinstance(reference.get("url"), str)
        )
        fixed_versions = self._extract_fixed_versions(payload)
        return Vulnerability(
            osv_id=str(payload.get("id", "")),
            source_ids=(str(payload.get("id", "")),),
            aliases=aliases,
            summary=_clean_text(payload.get("summary")),
            details=_clean_text(payload.get("details")),
            published=_normalize_datetime(payload.get("published")),
            modified=_normalize_datetime(payload.get("modified")),
            fixed_versions=fixed_versions,
            references=references,
            kev=kev_record is not None,
            kev_due_date=kev_record.get("dueDate") if kev_record else None,
            kev_ransomware=kev_record.get("knownRansomwareCampaignUse") if kev_record else None,
        )

    def _extract_fixed_versions(self, payload: dict[str, Any]) -> tuple[str, ...]:
        fixed_versions: set[str] = set()
        affected = payload.get("affected", [])
        for package in affected:
            if not isinstance(package, dict):
                continue
            ranges = package.get("ranges", [])
            for range_item in ranges:
                if not isinstance(range_item, dict):
                    continue
                events = range_item.get("events", [])
                for event in events:
                    if not isinstance(event, dict):
                        continue
                    fixed = event.get("fixed")
                    if isinstance(fixed, str) and fixed and not _looks_like_commitish(fixed):
                        fixed_versions.add(fixed)
            database_specific = package.get("database_specific", {})
            if isinstance(database_specific, dict):
                fixed = database_specific.get("fixed_version")
                if isinstance(fixed, str) and fixed and not _looks_like_commitish(fixed):
                    fixed_versions.add(fixed)
        return tuple(sorted(fixed_versions))

    def _query_cache_key(self, dependency: Dependency) -> str:
        return f"osv:query:v1:{dependency.ecosystem}:{dependency.name.lower()}:{dependency.version}"

    def _vulnerability_cache_key(self, vuln_id: str) -> str:
        return f"osv:vuln:v1:{vuln_id}"

    def _deduplicate_vulnerabilities(self, vulnerabilities: tuple[Vulnerability, ...]) -> tuple[Vulnerability, ...]:
        if len(vulnerabilities) < 2:
            return vulnerabilities

        clusters: list[list[Vulnerability]] = []
        cluster_tokens: list[set[str]] = []
        for vulnerability in vulnerabilities:
            tokens = _vulnerability_tokens(vulnerability)
            matching = [index for index, existing in enumerate(cluster_tokens) if tokens & existing]
            if not matching:
                clusters.append([vulnerability])
                cluster_tokens.append(set(tokens))
                continue

            first = matching[0]
            clusters[first].append(vulnerability)
            cluster_tokens[first].update(tokens)
            for index in reversed(matching[1:]):
                clusters[first].extend(clusters.pop(index))
                cluster_tokens[first].update(cluster_tokens.pop(index))

        merged = [self._merge_cluster(cluster) for cluster in clusters]
        return tuple(sorted(merged, key=lambda vulnerability: vulnerability.canonical_id))

    def _merge_cluster(self, cluster: list[Vulnerability]) -> Vulnerability:
        source_ids = tuple(sorted({source_id for vulnerability in cluster for source_id in vulnerability.source_ids}))
        aliases = tuple(sorted({alias for vulnerability in cluster for alias in vulnerability.aliases}))
        references = tuple(sorted({reference for vulnerability in cluster for reference in vulnerability.references}))
        fixed_versions = tuple(
            sorted({version for vulnerability in cluster for version in vulnerability.fixed_versions})
        )
        summary = _longest_text(vulnerability.summary for vulnerability in cluster)
        details = _longest_text(vulnerability.details for vulnerability in cluster)
        published = _pick_datetime(
            (vulnerability.published for vulnerability in cluster if vulnerability.published is not None),
            prefer_latest=False,
        )
        modified = _pick_datetime(
            (vulnerability.modified for vulnerability in cluster if vulnerability.modified is not None),
            prefer_latest=True,
        )
        kev = any(vulnerability.kev for vulnerability in cluster)
        kev_due_date = _pick_string(
            (vulnerability.kev_due_date for vulnerability in cluster if vulnerability.kev_due_date is not None),
            prefer_latest=False,
        )
        kev_ransomware = "Known" if any(
            vulnerability.kev_ransomware and vulnerability.kev_ransomware.lower() == "known"
            for vulnerability in cluster
        ) else next(
            (vulnerability.kev_ransomware for vulnerability in cluster if vulnerability.kev_ransomware),
            None,
        )
        preferred_id = _pick_preferred_identifier(source_ids)
        return Vulnerability(
            osv_id=preferred_id,
            source_ids=source_ids,
            aliases=aliases,
            summary=summary,
            details=details,
            published=published,
            modified=modified,
            fixed_versions=fixed_versions,
            references=references,
            kev=kev,
            kev_due_date=kev_due_date,
            kev_ransomware=kev_ransomware,
        )


def days_since(iso_timestamp: str | None) -> int | None:
    if iso_timestamp is None:
        return None
    instant = datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00"))
    delta = datetime.now(UTC) - instant.astimezone(UTC)
    return max(0, delta.days)


def _normalize_datetime(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(UTC).replace(microsecond=0).isoformat()


def _clean_text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _looks_like_commitish(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-f]{7,64}", value.lower()))


def _vulnerability_tokens(vulnerability: Vulnerability) -> set[str]:
    return {vulnerability.osv_id, *vulnerability.source_ids, *vulnerability.aliases}


def _longest_text(values: Iterable[str | None]) -> str | None:
    present = [value for value in values if isinstance(value, str) and value.strip()]
    if not present:
        return None
    return max(present, key=len)


def _pick_datetime(values: Iterable[str], prefer_latest: bool) -> str | None:
    timestamps = list(values)
    if not timestamps:
        return None
    try:
        parsed = [datetime.fromisoformat(value.replace("Z", "+00:00")) for value in timestamps]
    except ValueError:
        return timestamps[0]
    picked = max(parsed) if prefer_latest else min(parsed)
    return picked.astimezone(UTC).replace(microsecond=0).isoformat()


def _pick_preferred_identifier(source_ids: tuple[str, ...]) -> str:
    ordered = [
        *sorted(source_id for source_id in source_ids if source_id.startswith("GHSA-")),
        *sorted(source_id for source_id in source_ids if source_id.startswith("PYSEC-")),
        *sorted(source_ids),
    ]
    return ordered[0]


def _pick_string(values: Iterable[str], prefer_latest: bool) -> str | None:
    items = sorted(values)
    if not items:
        return None
    return items[-1] if prefer_latest else items[0]
