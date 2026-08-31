"""Validate a measurement bundle without claiming numeric reference equivalence."""

from __future__ import annotations

import argparse
from pathlib import Path

from simcairn.reference import validate_bundle

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--expected-points", type=int, required=True)
    args = parser.parse_args()
    validate_bundle(args.bundle, expected_points=args.expected_points)
    print("measurement bundle structure verified; numeric values were not compared")
