"""Acquire the exact minimal Ciel PDK tree for a manual reference replay."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from simcairn.pdk_replay import ReplayPreparationError, prepare_ciel_family


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("family", choices=("sky130", "gf180"))
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--pdk-base", type=Path, required=True)
    parser.add_argument("--download-directory", type=Path, required=True)
    parser.add_argument("--decision-output", type=Path, required=True)
    parser.add_argument("--evidence-output", type=Path, required=True)
    parser.add_argument("--zstd", type=Path, default=Path("/usr/bin/zstd"))
    arguments = parser.parse_args()
    try:
        root = prepare_ciel_family(
            arguments.inventory,
            arguments.family,
            pdk_base=arguments.pdk_base,
            download_directory=arguments.download_directory,
            decision_output=arguments.decision_output,
            evidence_output=arguments.evidence_output,
            zstd=arguments.zstd,
            github_token=os.environ.get("GITHUB_TOKEN"),
        )
    except ReplayPreparationError as error:
        parser.exit(2, f"prepare_ciel_pdk: {error}\n")
    print(root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
