"""Bind a fresh RC bundle to the current fixed plan, then compare its numbers."""

from __future__ import annotations

import argparse
from pathlib import Path

from simcairn import compile_plan, load_manifest
from simcairn.reference import verify_reference

ROOT = Path(__file__).parents[1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("actual", type=Path)
    parser.add_argument("reference", type=Path)
    parser.add_argument("--expected-points", type=int, default=32)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=ROOT / "examples" / "rc_pvt" / "ngspice.toml",
        help="fixed current-run manifest used to bind the actual aggregate",
    )
    arguments = parser.parse_args()
    plan = compile_plan(load_manifest(arguments.manifest))
    verify_reference(
        arguments.actual,
        arguments.reference,
        expected_points=arguments.expected_points,
        expected_activity_id=plan.activities[-1].id,
    )
    print("current ngspice bundle and frozen numeric reference verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
