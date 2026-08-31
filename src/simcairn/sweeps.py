"""Deterministic product and zip sweep expansion."""

from __future__ import annotations

import itertools
from collections.abc import Iterable

from simcairn.manifest import ManifestError, SweepConfig
from simcairn.model import SweepPoint


def expand_sweep(config: SweepConfig) -> tuple[SweepPoint, ...]:
    names = tuple(name for name, _ in config.parameters)
    values = tuple(items for _, items in config.parameters)
    combinations: Iterable[tuple[str, ...]]
    if config.mode == "zip":
        lengths = {len(items) for items in values}
        if len(lengths) != 1:
            raise ManifestError("zip sweep parameter arrays must have equal lengths")
        combinations = zip(*values, strict=True)
    else:
        combinations = itertools.product(*values)
    points: list[SweepPoint] = []
    seen: set[tuple[tuple[str, str], ...]] = set()
    for index, combination in enumerate(combinations):
        pairs = tuple(zip(names, combination, strict=True))
        if pairs in seen:
            raise ManifestError(f"sweep expands to a duplicate point: {dict(pairs)}")
        seen.add(pairs)
        points.append(SweepPoint(index, pairs))
    return tuple(points)
