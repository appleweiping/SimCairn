"""Deterministic subprocess used by examples and integration tests."""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from decimal import Decimal, InvalidOperation
from pathlib import Path

_NUMBER = re.compile(
    r"((?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)(meg|[tgkmunpf])?\Z",
    re.IGNORECASE,
)
_SCALE = {
    "t": Decimal("1e12"),
    "g": Decimal("1e9"),
    "meg": Decimal("1e6"),
    "k": Decimal("1e3"),
    "m": Decimal("1e-3"),
    "u": Decimal("1e-6"),
    "n": Decimal("1e-9"),
    "p": Decimal("1e-12"),
    "f": Decimal("1e-15"),
}


def parse_engineering_value(text: str) -> float:
    match = _NUMBER.fullmatch(text.strip())
    if not match:
        raise ValueError(f"invalid engineering value {text!r}")
    try:
        value = Decimal(match.group(1))
        if match.group(2):
            value *= _SCALE[match.group(2).casefold()]
    except (InvalidOperation, KeyError) as error:
        raise ValueError(f"invalid engineering value {text!r}") from error
    numeric = float(value)
    if not math.isfinite(numeric) or numeric <= 0:
        raise ValueError(f"engineering value must be positive and finite: {text!r}")
    return numeric


def simulate(point: dict[str, str]) -> dict[str, float]:
    normalized = {name.casefold(): str(value) for name, value in point.items()}
    if "r" not in normalized or "c" not in normalized:
        raise ValueError("mock-rc requires sweep parameters R and C")
    resistance = parse_engineering_value(normalized["r"])
    capacitance = parse_engineering_value(normalized["c"])
    cutoff = 1.0 / (2.0 * math.pi * resistance * capacitance)
    return {
        "capacitance_f": capacitance,
        "cutoff_hz": cutoff,
        "resistance_ohm": resistance,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="simcairn-mock-rc")
    parser.add_argument("--point", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        point = json.loads(Path(args.point).read_text(encoding="utf-8"))
        if not isinstance(point, dict):
            raise ValueError("point JSON must be an object")
        metrics = simulate({str(name): str(value) for name, value in point.items()})
        Path(args.output).write_text(
            json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"mock-rc: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
