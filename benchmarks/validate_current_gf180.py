"""Validate a fresh GF180 bundle against its current plan and frozen numbers."""

from __future__ import annotations

import argparse
from pathlib import Path

from simcairn import compile_plan, load_manifest
from simcairn.reference import validate_gf180_bundle, verify_reference


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    arguments = parser.parse_args()
    validate_gf180_bundle(arguments.bundle)
    plan = compile_plan(load_manifest(arguments.manifest))
    verify_reference(
        arguments.bundle,
        arguments.reference,
        expected_points=27,
        expected_activity_id=plan.activities[-1].id,
    )
    print("current GF180 bundle and frozen numeric reference verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
