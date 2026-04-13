from __future__ import annotations

import argparse
import asyncio
from dataclasses import replace
import json
from pathlib import Path

import uvicorn

from glasswall.diffing import build_scan_delta
from glasswall.models import ScanOverview, urgency_rank
from glasswall.policy import load_scan_policy
from glasswall.render import render_plan_output, render_remediation_output, render_scan_output, write_output
from glasswall.service import GlasswallService, normalize_target_path
from glasswall.settings import load_settings
from glasswall.storage import Database


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="glasswall")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a repository path")
    scan_parser.add_argument("path", help="Local repository path to scan")
    scan_parser.add_argument("--format", choices=("summary", "json", "markdown", "sarif"), default="summary")
    scan_parser.add_argument("--fail-on", choices=("watch", "high", "urgent", "critical-now"))
    scan_parser.add_argument("--policy", help="Optional path to a Glasswall policy file")
    scan_parser.add_argument("--output", help="Optional file path for rendered output")
    scan_parser.add_argument("--no-save", action="store_true", help="Do not persist scan results")

    history_parser = subparsers.add_parser("history", help="Show recent scan history")
    history_parser.add_argument("path", nargs="?", help="Optional repository path to filter by")
    history_parser.add_argument("--limit", type=int, default=10)
    history_parser.add_argument("--format", choices=("summary", "json"), default="summary")

    plan_parser = subparsers.add_parser("plan", help="Build a remediation plan for a repository path")
    plan_parser.add_argument("path", help="Local repository path to plan")
    plan_parser.add_argument("--format", choices=("summary", "json", "markdown"), default="summary")
    plan_parser.add_argument("--policy", help="Optional path to a Glasswall policy file")
    plan_parser.add_argument("--output", help="Optional file path for rendered output")

    remediate_parser = subparsers.add_parser("remediate", help="Apply or preview supported remediation changes")
    remediate_parser.add_argument("path", help="Local repository path to remediate")
    remediate_parser.add_argument("--format", choices=("summary", "json", "markdown"), default="summary")
    remediate_parser.add_argument("--policy", help="Optional path to a Glasswall policy file")
    remediate_parser.add_argument("--output", help="Optional file path for rendered output")
    remediate_parser.add_argument("--apply", action="store_true", help="Write supported remediation changes to disk")
    remediate_parser.add_argument("--max-upgrades", type=int, help="Limit the number of top recommendations considered")

    serve_parser = subparsers.add_parser("serve", help="Run the Glasswall web UI")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", default=8080, type=int)
    return parser


async def run_scan(
    target_path: str,
    output_format: str,
    fail_on: str | None,
    save: bool,
    output_path: str | None,
    policy_path: str | None,
) -> int:
    settings = load_settings()
    service = GlasswallService(settings=settings)
    database = Database(settings.db_path)
    normalized_path = normalize_target_path(target_path)
    policy = load_scan_policy(Path(normalized_path), policy_path)
    result = await service.scan_path(target_path, policy=policy)
    delta = None
    if save:
        scan_id = database.save_scan(result)
        result = replace(result, scan_id=scan_id)
        previous = database.previous_scan(result.target_path, scan_id)
        delta = build_scan_delta(result, previous)
    write_output(render_scan_output(result, output_format, delta), output_path)
    return exit_code_for_threshold(result, fail_on or policy.fail_on)


def run_history(path: str | None, limit: int, output_format: str) -> int:
    settings = load_settings()
    database = Database(settings.db_path)
    normalized_path = normalize_target_path(path) if path is not None else None
    entries = database.list_scans(limit=limit, target_path=normalized_path)
    if output_format == "json":
        print(json.dumps([entry.to_dict() for entry in entries], indent=2))
        return 0
    if not entries:
        print("No scans found.")
        return 0
    for entry in entries:
        print(_render_history_entry(entry))
    return 0


async def run_plan(target_path: str, output_format: str, output_path: str | None, policy_path: str | None) -> int:
    settings = load_settings()
    service = GlasswallService(settings=settings)
    normalized_path = normalize_target_path(target_path)
    policy = load_scan_policy(Path(normalized_path), policy_path)
    plan = await service.plan_path(target_path, policy=policy)
    write_output(render_plan_output(plan, output_format), output_path)
    return 0


async def run_remediate(
    target_path: str,
    output_format: str,
    output_path: str | None,
    policy_path: str | None,
    apply: bool,
    max_upgrades: int | None,
) -> int:
    settings = load_settings()
    service = GlasswallService(settings=settings)
    normalized_path = normalize_target_path(target_path)
    policy = load_scan_policy(Path(normalized_path), policy_path)
    result = await service.remediate_path(
        target_path,
        policy=policy,
        apply=apply,
        max_recommendations=max_upgrades,
    )
    write_output(render_remediation_output(result, output_format), output_path)
    return 0


def exit_code_for_threshold(result, fail_on: str | None) -> int:
    if fail_on is None:
        return 0
    threshold = urgency_rank(fail_on)
    for finding in result.findings:
        if urgency_rank(finding.urgency_label) >= threshold:
            return 1
    return 0


def _render_history_entry(entry: ScanOverview) -> str:
    return (
        f"{entry.scan_id}\t{entry.generated_at}\t{entry.top_urgency_label or 'none'}\t"
        f"deps={entry.dependency_count}\tfindings={entry.finding_count}\t{entry.target_path}"
    )


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        return asyncio.run(
            run_scan(
                target_path=args.path,
                output_format=args.format,
                fail_on=args.fail_on,
                save=not args.no_save,
                output_path=args.output,
                policy_path=args.policy,
            )
        )

    if args.command == "history":
        return run_history(args.path, args.limit, args.format)

    if args.command == "plan":
        return asyncio.run(
            run_plan(
                target_path=args.path,
                output_format=args.format,
                output_path=args.output,
                policy_path=args.policy,
            )
        )

    if args.command == "serve":
        from glasswall.app import create_app

        uvicorn.run(create_app(), host=args.host, port=args.port)
        return 0

    if args.command == "remediate":
        return asyncio.run(
            run_remediate(
                target_path=args.path,
                output_format=args.format,
                output_path=args.output,
                policy_path=args.policy,
                apply=args.apply,
                max_upgrades=args.max_upgrades,
            )
        )

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
