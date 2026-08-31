"""Command-line interface for validation, execution, recovery, and collection."""

from __future__ import annotations

import argparse
import sys
from dataclasses import replace
from pathlib import Path

from simcairn.api import Runner, compile_plan, load_manifest
from simcairn.fingerprints import stable_json
from simcairn.journal import JournalError, clear_run_lock
from simcairn.manifest import ManifestError
from simcairn.store import StoreError


def _runner(args: argparse.Namespace) -> Runner:
    return Runner(args.store)


def _validate(args: argparse.Namespace) -> int:
    manifest = load_manifest(args.manifest)
    plan = compile_plan(manifest)
    print(f"valid manifest: {len(plan.activities)} activities, plan {plan.id[:12]}")
    return 0


def _plan(args: argparse.Namespace) -> int:
    plan = compile_plan(load_manifest(args.manifest))
    sys.stdout.write(stable_json(plan.as_dict()))
    return 0


def _run(args: argparse.Namespace) -> int:
    manifest = load_manifest(args.manifest)
    if args.jobs is not None:
        if args.jobs < 1:
            raise ManifestError("--jobs must be a positive integer")
        manifest = replace(manifest, run=replace(manifest.run, jobs=args.jobs))
    report = _runner(args).run(manifest)
    sys.stdout.write(stable_json(report.as_dict()))
    return 0 if report.status == "succeeded" else 1


def _resume(args: argparse.Namespace) -> int:
    report = _runner(args).resume(args.run_id)
    sys.stdout.write(stable_json(report.as_dict()))
    return 0 if report.status == "succeeded" else 1


def _status(args: argparse.Namespace) -> int:
    sys.stdout.write(stable_json(_runner(args).status(args.run_id)))
    return 0


def _collect(args: argparse.Namespace) -> int:
    text = _runner(args).collect_text(args.run_id)
    if args.output:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    else:
        sys.stdout.write(text)
    return 0


def _explain(args: argparse.Namespace) -> int:
    result = _runner(args).explain(args.activity_id)
    sys.stdout.write(stable_json(result))
    return 0 if result["cached"] else 1


def _unlock(args: argparse.Namespace) -> int:
    runner = _runner(args)
    directory = runner.store.run_directory(args.run_id)
    sys.stdout.write(stable_json(clear_run_lock(directory, force=args.force)))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="simcairn")
    parser.add_argument("--version", action="version", version="simcairn 0.1.0")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate", help="validate and fingerprint a manifest")
    validate.add_argument("manifest")
    validate.set_defaults(handler=_validate)

    plan = subparsers.add_parser("plan", help="print the immutable activity plan")
    plan.add_argument("manifest")
    plan.set_defaults(handler=_plan)

    run = subparsers.add_parser("run", help="start a new cached run")
    run.add_argument("manifest")
    run.add_argument("--jobs", type=int)
    run.add_argument("--store", default=".simcairn")
    run.set_defaults(handler=_run)

    resume = subparsers.add_parser("resume", help="resume an interrupted or failed run")
    resume.add_argument("run_id")
    resume.add_argument("--store", default=".simcairn")
    resume.set_defaults(handler=_resume)

    status = subparsers.add_parser("status", help="summarize an append-only run journal")
    status.add_argument("run_id")
    status.add_argument("--store", default=".simcairn")
    status.set_defaults(handler=_status)

    collect = subparsers.add_parser("collect", help="emit aggregated result rows as JSON")
    collect.add_argument("run_id")
    collect.add_argument("--store", default=".simcairn")
    collect.add_argument("-o", "--output")
    collect.set_defaults(handler=_collect)

    explain = subparsers.add_parser("explain", help="explain a cache hit or miss")
    explain.add_argument("activity_id")
    explain.add_argument("--store", default=".simcairn")
    explain.set_defaults(handler=_explain)

    unlock = subparsers.add_parser("unlock", help="inspect and remove a stale run lock")
    unlock.add_argument("run_id")
    unlock.add_argument("--store", default=".simcairn")
    unlock.add_argument("--force", action="store_true")
    unlock.set_defaults(handler=_unlock)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return int(args.handler(args))
    except (ManifestError, StoreError, JournalError, OSError, ValueError) as error:
        print(f"simcairn: {error}", file=sys.stderr)
        return 2


def entrypoint() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    entrypoint()
