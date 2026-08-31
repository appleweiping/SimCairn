"""CLI adapter for the packaged reference verifier."""

from __future__ import annotations

import argparse
from pathlib import Path

from simcairn.reference import verify_reference

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("actual", type=Path)
    parser.add_argument("reference", type=Path)
    parser.add_argument("--expected-points", type=int, default=32)
    args = parser.parse_args()
    verify_reference(args.actual, args.reference, expected_points=args.expected_points)
    print("ngspice reference verified")
