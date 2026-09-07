"""Command-line interface for validation, execution, recovery, and collection."""

from __future__ import annotations

import argparse
import sys
from dataclasses import replace
from pathlib import Path

from simcairn import maintenance
from simcairn._version import __version__
from simcairn.api import Runner, compile_plan, configure_gf180, configure_sky130, load_manifest
from simcairn.fingerprints import stable_json
from simcairn.gf180 import GF180ConfigurationError
from simcairn.journal import JournalError, clear_run_lock
from simcairn.manifest import ManifestError
from simcairn.sky130 import Sky130ConfigurationError
from simcairn.store import ArtifactStore, StoreError


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


def _store_status(args: argparse.Namespace) -> int:
    survey = maintenance.survey(ArtifactStore(args.store))
    sys.stdout.write(stable_json(survey.as_dict()))
    return 0


def _store_verify(args: argparse.Namespace) -> int:
    broken = maintenance.verify_all(ArtifactStore(args.store))
    sys.stdout.write(
        stable_json(
            {
                "checked": True,
                "failed": len(broken),
                "entries": [entry.as_dict() for entry in broken],
            }
        )
    )
    # A store holding a cairn that no longer matches its manifest is a failure
    # a caller has to notice, so it leaves through the exit status too.
    return 0 if not broken else 3


def _store_gc(args: argparse.Namespace) -> int:
    store = ArtifactStore(args.store)
    plan = maintenance.plan_collection(
        store,
        keep_runs=args.keep_runs,
        include_unreadable=args.include_unreadable,
        include_work=not args.keep_work,
    )
    payload: dict[str, object] = {"applied": False, "plan": plan.as_dict()}
    if args.apply:
        report = maintenance.apply_collection(store, plan)
        payload = {"applied": True, "plan": plan.as_dict(), "result": report.as_dict()}
        if report.failures:
            sys.stdout.write(stable_json(payload))
            return 3
    sys.stdout.write(stable_json(payload))
    return 0


def _unlock(args: argparse.Namespace) -> int:
    runner = _runner(args)
    directory = runner.store.run_directory(args.run_id)
    sys.stdout.write(stable_json(clear_run_lock(directory, force=args.force)))
    return 0


def _configure_sky130(args: argparse.Namespace) -> int:
    manifest = configure_sky130(
        args.decision,
        args.output,
        expected_topology=args.expected_topology,
        expected_signature=args.expected_signature,
        expected_decision_sha256=args.expected_decision_sha256,
        expected_benchmark_sha256=args.expected_benchmark_sha256,
        expected_comparison_sha256=args.expected_comparison_sha256,
        pdk_root=args.pdk_root,
    )
    print(manifest)
    return 0


def _configure_gf180(args: argparse.Namespace) -> int:
    manifest = configure_gf180(
        args.decision,
        args.output,
        expected_topology=args.expected_topology,
        expected_signature=args.expected_signature,
        expected_decision_sha256=args.expected_decision_sha256,
        expected_benchmark_sha256=args.expected_benchmark_sha256,
        expected_comparison_sha256=args.expected_comparison_sha256,
        pdk_root=args.pdk_root,
    )
    print(manifest)
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="simcairn")
    parser.add_argument("--version", action="version", version=f"simcairn {__version__}")
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

    store_status = subparsers.add_parser("store-status", help="summarize what the store holds")
    store_status.add_argument("--store", default=".simcairn")
    store_status.set_defaults(handler=_store_status)

    store_verify = subparsers.add_parser(
        "store-verify", help="re-check every cached cairn against its manifest"
    )
    store_verify.add_argument("--store", default=".simcairn")
    store_verify.set_defaults(handler=_store_verify)

    store_gc = subparsers.add_parser(
        "store-gc", help="report what could be reclaimed, and reclaim it with --apply"
    )
    store_gc.add_argument("--store", default=".simcairn")
    store_gc.add_argument(
        "--keep-runs",
        type=int,
        default=maintenance.DEFAULT_KEEP_RUNS,
        help="most recent runs to retain; a locked run is retained whatever its age",
    )
    store_gc.add_argument(
        "--include-unreadable",
        action="store_true",
        help="also remove entries and runs that cannot be read, which are kept "
        "as evidence by default",
    )
    store_gc.add_argument("--keep-work", action="store_true", help="leave work sandboxes alone")
    store_gc.add_argument(
        "--apply",
        action="store_true",
        help="actually remove what the plan names; without it nothing is deleted",
    )
    store_gc.set_defaults(handler=_store_gc)

    unlock = subparsers.add_parser("unlock", help="inspect and remove a stale run lock")
    unlock.add_argument("run_id")
    unlock.add_argument("--store", default=".simcairn")
    unlock.add_argument("--force", action="store_true")
    unlock.set_defaults(handler=_unlock)

    sky130 = subparsers.add_parser(
        "configure-sky130", help="create a content-bound SKY130 benchmark"
    )
    sky130.add_argument("decision")
    sky130.add_argument("output")
    sky130.add_argument("--expected-topology", required=True)
    sky130.add_argument("--expected-signature", required=True)
    sky130.add_argument("--expected-decision-sha256", required=True)
    sky130.add_argument("--expected-benchmark-sha256", required=True)
    sky130.add_argument("--expected-comparison-sha256", required=True)
    sky130.add_argument("--pdk-root", required=True)
    sky130.set_defaults(handler=_configure_sky130)

    gf180 = subparsers.add_parser(
        "configure-gf180", help="create a content-bound GF180MCU benchmark"
    )
    gf180.add_argument("decision")
    gf180.add_argument("output")
    gf180.add_argument("--expected-topology", required=True)
    gf180.add_argument("--expected-signature", required=True)
    gf180.add_argument("--expected-decision-sha256", required=True)
    gf180.add_argument("--expected-benchmark-sha256", required=True)
    gf180.add_argument("--expected-comparison-sha256", required=True)
    gf180.add_argument("--pdk-root", required=True)
    gf180.set_defaults(handler=_configure_gf180)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return int(args.handler(args))
    except (
        ManifestError,
        StoreError,
        JournalError,
        Sky130ConfigurationError,
        GF180ConfigurationError,
        OSError,
        ValueError,
    ) as error:
        print(f"simcairn: {error}", file=sys.stderr)
        return 2


def entrypoint() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    entrypoint()
