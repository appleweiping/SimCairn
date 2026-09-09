"""Measure plan validation and deck compilation; this does not simulate physics."""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path

from simcairn.characterization import load_characterization_plan, render_xyce_deck

ROOT = Path(__file__).parents[1]
DEFAULT_PLAN = ROOT / "examples" / "xyce_sram" / "characterization.json"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    parser.add_argument("--iterations", type=int, default=100)
    args = parser.parse_args()
    if not 1 <= args.iterations <= 10_000:
        parser.error("--iterations must be in [1, 10000]")

    started = time.perf_counter()
    digest = hashlib.sha256()
    deck_count = 0
    for _ in range(args.iterations):
        plan = load_characterization_plan(args.plan)
        for corner in plan.corners:
            for analysis in plan.analyses:
                digest.update(render_xyce_deck(plan, corner, analysis))
                deck_count += 1
    duration = time.perf_counter() - started
    print(
        json.dumps(
            {
                "benchmark": "xyce-plan-load-and-render",
                "deck_count": deck_count,
                "duration_seconds": duration,
                "iterations": args.iterations,
                "output_sha256": digest.hexdigest(),
                "physical_simulation": False,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
