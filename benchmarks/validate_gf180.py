"""Validate one measured GF180 PVT bundle and its electrical invariants."""

from __future__ import annotations

import argparse
from pathlib import Path

from simcairn.reference import validate_gf180_bundle, verify_reference


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--reference", type=Path)
    arguments = parser.parse_args()
    validate_gf180_bundle(arguments.bundle)
    if arguments.reference is not None:
        verify_reference(arguments.bundle, arguments.reference, expected_points=27)
    print("GF180 bundle contract and electrical invariants verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
