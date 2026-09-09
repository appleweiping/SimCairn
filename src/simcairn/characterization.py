"""Strict, simulator-neutral circuit characterization plans and result tables."""

from __future__ import annotations

import csv
import hashlib
import io
import math
import os
import posixpath
import re
from dataclasses import dataclass, field
from itertools import pairwise
from pathlib import Path, PurePosixPath
from typing import Any, Literal, TypeAlias

from simcairn.model import strict_json_loads

_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_SPICE_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:+-]*\Z")
_INPUT_PATH = re.compile(r"[A-Za-z0-9_.\-/]+\Z")
_OUTPUT = re.compile(
    r"(?:V|I[A-Za-z0-9]?|VR|VI|VM|VDB|VP|IR|II|IM|IDB|IP|P|W|N|DNI|DNO)"
    r"\([A-Za-z0-9_][A-Za-z0-9_.:+-]*(?:,[A-Za-z0-9_][A-Za-z0-9_.:+-]*)?\)"
    r"|(?:INOISE|ONOISE)\Z",
    re.IGNORECASE,
)
_INCLUDE = re.compile(
    r"^\s*\.(?:inc|incl|include)\s+"
    r'(?:"([^"\r\n]+)"|\'([^\'\r\n]+)\'|([^\s"\'\r\n]+))\s*$',
    re.IGNORECASE,
)
_LIBRARY = re.compile(
    r"^\s*\.lib\s+"
    r'(?:"([^"\r\n]+)"|\'([^\'\r\n]+)\'|([^\s"\'\r\n]+))'
    r"\s+[A-Za-z_][A-Za-z0-9_]*\s*$",
    re.IGNORECASE,
)
_LIBRARY_SECTION = re.compile(r"^\s*\.lib\s+[A-Za-z_][A-Za-z0-9_]*\s*$", re.IGNORECASE)
_INCLUDE_PREFIX = re.compile(r"^\s*\.(?:inc|incl|include|lib)\b", re.IGNORECASE)
_FILE_REFERENCE = re.compile(
    r"\bFILE\s*=\s*"
    r'(?:"([^"\r\n]+)"|\'([^\'\r\n]+)\'|([^\s,()"\'\r\n]+))',
    re.IGNORECASE,
)
_PVT_MARKER = "* SIMCAIRN:PVT"
_ANALYSIS_MARKER = "* SIMCAIRN:ANALYSIS"
_MAX_PLAN_BYTES = 256 * 1024
_HARD_MAX_DECK_BYTES = 4 * 1024 * 1024
_HARD_MAX_INPUT_BYTES = 256 * 1024 * 1024
_HARD_MAX_OUTPUT_BYTES = 64 * 1024 * 1024
_HARD_MAX_LOG_BYTES = 8 * 1024 * 1024
_HARD_MAX_ROWS = 1_000_000
_HARD_MAX_COLUMNS = 256
_HARD_MAX_RUNS = 512


class CharacterizationError(ValueError):
    """A characterization contract is malformed or cannot be normalized."""


def _exact_keys(data: dict[str, Any], required: set[str], optional: set[str], where: str) -> None:
    missing = required - set(data)
    unknown = set(data) - required - optional
    if missing:
        raise CharacterizationError(f"{where} is missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise CharacterizationError(f"{where} has unknown fields: {', '.join(sorted(unknown))}")


def _name(value: object, where: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise CharacterizationError(f"{where} must be an ASCII identifier")
    return value


def _spice_name(value: object, where: str) -> str:
    if not isinstance(value, str) or _SPICE_NAME.fullmatch(value) is None:
        raise CharacterizationError(f"{where} must be a safe SPICE name")
    return value


def _text(value: object, where: str, *, maximum: int = 128) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise CharacterizationError(f"{where} must be non-empty printable text")
    return value


def _number(
    value: object,
    where: str,
    *,
    minimum: float | None = None,
    maximum: float | None = None,
    positive: bool = False,
) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise CharacterizationError(f"{where} must be a finite number")
    try:
        result = float(value)
    except (OverflowError, ValueError) as error:
        raise CharacterizationError(f"{where} must be a finite number") from error
    if not math.isfinite(result):
        raise CharacterizationError(f"{where} must be a finite number")
    if positive and result <= 0:
        raise CharacterizationError(f"{where} must be positive")
    if minimum is not None and result < minimum:
        raise CharacterizationError(f"{where} must be at least {minimum:g}")
    if maximum is not None and result > maximum:
        raise CharacterizationError(f"{where} must be at most {maximum:g}")
    return result


def _positive_int(value: object, where: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= maximum:
        raise CharacterizationError(f"{where} must be an integer in [1, {maximum}]")
    return value


def _format_number(value: float) -> str:
    rendered = format(value, ".17g")
    return "0" if rendered == "-0" else rendered


@dataclass(frozen=True, slots=True)
class CharacterizationLimits:
    """Hard-bounded limits applied while materializing and executing a plan."""

    max_deck_bytes: int = 1 * 1024 * 1024
    max_input_bytes: int = 64 * 1024 * 1024
    max_output_bytes: int = 16 * 1024 * 1024
    max_log_bytes: int = 1 * 1024 * 1024
    max_rows: int = 200_000
    max_columns: int = 64
    max_runs: int = 128

    def __post_init__(self) -> None:
        bounds = {
            "max_deck_bytes": _HARD_MAX_DECK_BYTES,
            "max_input_bytes": _HARD_MAX_INPUT_BYTES,
            "max_output_bytes": _HARD_MAX_OUTPUT_BYTES,
            "max_log_bytes": _HARD_MAX_LOG_BYTES,
            "max_rows": _HARD_MAX_ROWS,
            "max_columns": _HARD_MAX_COLUMNS,
            "max_runs": _HARD_MAX_RUNS,
        }
        for name, maximum in bounds.items():
            _positive_int(getattr(self, name), f"limits.{name}", maximum)

    def as_dict(self) -> dict[str, int]:
        return {
            "max_deck_bytes": self.max_deck_bytes,
            "max_input_bytes": self.max_input_bytes,
            "max_output_bytes": self.max_output_bytes,
            "max_log_bytes": self.max_log_bytes,
            "max_rows": self.max_rows,
            "max_columns": self.max_columns,
            "max_runs": self.max_runs,
        }


@dataclass(frozen=True, slots=True)
class PVTCorner:
    process: str
    voltage: float
    temperature_c: float
    parameters: tuple[tuple[str, float], ...] = ()

    def __post_init__(self) -> None:
        _name(self.process, "corner.process")
        _number(self.voltage, "corner.voltage", positive=True, maximum=1_000.0)
        _number(self.temperature_c, "corner.temperature_c", minimum=-273.15, maximum=2_000.0)
        if len(self.parameters) > 32:
            raise CharacterizationError("corner.parameters has more than 32 entries")
        names: set[str] = set()
        for name, value in self.parameters:
            key = _name(name, "corner parameter").casefold()
            if key == "voltage":
                raise CharacterizationError("corner parameter 'voltage' is reserved")
            if key in names:
                raise CharacterizationError("corner.parameters has duplicate names")
            names.add(key)
            _number(value, f"corner.parameters.{name}")

    @property
    def label(self) -> str:
        voltage = _format_number(self.voltage).replace("-", "m").replace(".", "p")
        temperature = _format_number(self.temperature_c).replace("-", "m").replace(".", "p")
        return f"{self.process}__v{voltage}__t{temperature}"

    def as_dict(self) -> dict[str, Any]:
        return {
            "process": self.process,
            "voltage": self.voltage,
            "temperature_c": self.temperature_c,
            "parameters": dict(self.parameters),
        }


@dataclass(frozen=True, slots=True)
class TraceOutput:
    name: str
    expression: str
    unit: str

    def __post_init__(self) -> None:
        _name(self.name, "output.name")
        if not isinstance(self.expression, str) or _OUTPUT.fullmatch(self.expression) is None:
            raise CharacterizationError(
                f"output.expression {self.expression!r} is not a supported safe probe"
            )
        _text(self.unit, "output.unit", maximum=32)
        prefix = self.expression.split("(", 1)[0].casefold()
        expected_unit = {
            "v": "V",
            "vr": "V",
            "vi": "V",
            "vm": "V",
            "i": "A",
            "ir": "A",
            "ii": "A",
            "im": "A",
            "vdb": "dB",
            "idb": "dB",
            "vp": "deg",
            "ip": "deg",
            "p": "W",
            "w": "W",
            "onoise": "V^2/Hz",
            "dno": "V^2/Hz",
        }.get(prefix)
        if expected_unit is None and re.fullmatch(r"i[a-z0-9]?", prefix) is not None:
            expected_unit = "A"
        if expected_unit is not None and self.unit != expected_unit:
            raise CharacterizationError(
                f"output probe {self.expression!r} requires unit {expected_unit!r}"
            )

    def as_dict(self) -> dict[str, str]:
        return {"name": self.name, "expression": self.expression, "unit": self.unit}


@dataclass(frozen=True, slots=True)
class CharacterizationInput:
    logical_name: str
    path: Path
    _snapshot: bytes | None = field(default=None, repr=False)
    _snapshot_path: Path | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        candidate = Path(self.logical_name)
        if (
            not self.logical_name
            or "\\" in self.logical_name
            or _INPUT_PATH.fullmatch(self.logical_name) is None
            or candidate.is_absolute()
            or self.logical_name.startswith("/")
            or ".." in candidate.parts
            or any(part in {"", "."} for part in candidate.parts)
            or candidate.as_posix() != self.logical_name
        ):
            raise CharacterizationError("input logical_name must be a safe relative path")
        reserved = {
            "deck.cir",
            "results.csv",
            "xyce.log",
            "stdout.log",
            "stderr.log",
            "normalized.json",
            "tmp",
        }
        if candidate.parts[0].casefold() in reserved:
            raise CharacterizationError("input logical_name uses a reserved execution artifact")
        if not self.path.is_absolute() or self.path.resolve() != self.path:
            raise CharacterizationError("input path must be canonical and absolute")
        snapshot = self._snapshot
        if snapshot is None or (
            self._snapshot_path is not None and self._snapshot_path != self.path
        ):
            snapshot = _read_bytes_bounded(
                self.path,
                _HARD_MAX_INPUT_BYTES,
                f"characterization input {self.logical_name!r}",
            )
        elif not isinstance(snapshot, bytes) or len(snapshot) > _HARD_MAX_INPUT_BYTES:
            raise CharacterizationError("input snapshot is invalid or exceeds the hard limit")
        object.__setattr__(self, "_snapshot", snapshot)
        object.__setattr__(self, "_snapshot_path", self.path)

    @property
    def snapshot(self) -> bytes:
        snapshot = self._snapshot
        if snapshot is None:  # pragma: no cover - established by __post_init__
            raise CharacterizationError("characterization input has no content snapshot")
        return snapshot

    @property
    def sha256(self) -> str:
        return self._identity()[1]

    def _identity(self) -> tuple[int, str]:
        snapshot = self.snapshot
        return len(snapshot), hashlib.sha256(snapshot).hexdigest()

    def verify_unchanged(self) -> None:
        observed = _read_bytes_bounded(
            self.path,
            _HARD_MAX_INPUT_BYTES,
            f"characterization input {self.logical_name!r}",
        )
        if observed != self.snapshot:
            raise CharacterizationError(
                f"characterization input {self.logical_name!r} changed after its snapshot"
            )

    def as_identity_dict(self) -> dict[str, str | int]:
        size, digest = self._identity()
        return {
            "logical_name": self.logical_name,
            "sha256": digest,
            "size": size,
        }


@dataclass(frozen=True, slots=True)
class OperatingPointAnalysis:
    name: str
    outputs: tuple[TraceOutput, ...]
    kind: Literal["op"] = field(default="op", init=False)

    def __post_init__(self) -> None:
        _validate_outputs(self.name, self.outputs)


@dataclass(frozen=True, slots=True)
class DCSweepAnalysis:
    name: str
    outputs: tuple[TraceOutput, ...]
    source: str
    axis_expression: str
    start: float
    stop: float
    step: float
    kind: Literal["dc"] = field(default="dc", init=False)

    def __post_init__(self) -> None:
        _validate_outputs(self.name, self.outputs)
        _spice_name(self.source, "dc.source")
        if self.source[0].casefold() not in {"v", "i"}:
            raise CharacterizationError(
                "dc.source must name an independent voltage or current source"
            )
        if (
            not isinstance(self.axis_expression, str)
            or _OUTPUT.fullmatch(self.axis_expression) is None
        ):
            raise CharacterizationError("dc.axis_expression is not a supported safe probe")
        axis_prefix = self.axis_expression.split("(", 1)[0].casefold()
        if self.source[0].casefold() == "v" and axis_prefix != "v":
            raise CharacterizationError(
                "dc.axis_expression must be a voltage probe for a swept voltage source"
            )
        if self.source[0].casefold() == "i" and _probe_key(self.axis_expression) != _probe_key(
            f"I({self.source})"
        ):
            raise CharacterizationError(
                "dc.axis_expression must be the swept current-source probe I(source)"
            )
        if _probe_key(self.axis_expression) in {
            _probe_key(output.expression) for output in self.outputs
        }:
            raise CharacterizationError("dc.axis_expression must be distinct from output probes")
        _number(self.start, "dc.start")
        _number(self.stop, "dc.stop")
        _number(self.step, "dc.step")
        if self.start == self.stop:
            raise CharacterizationError("dc.start and dc.stop must differ")
        if self.step == 0 or (self.stop - self.start) * self.step < 0:
            raise CharacterizationError("dc.step must move from start toward stop")


SweepMode = Literal["lin", "dec", "oct"]


@dataclass(frozen=True, slots=True)
class ACSweepAnalysis:
    name: str
    outputs: tuple[TraceOutput, ...]
    sweep: SweepMode
    points: int
    start_hz: float
    stop_hz: float
    kind: Literal["ac"] = field(default="ac", init=False)

    def __post_init__(self) -> None:
        _validate_outputs(self.name, self.outputs)
        if self.sweep not in {"lin", "dec", "oct"}:
            raise CharacterizationError("ac.sweep must be 'lin', 'dec', or 'oct'")
        _positive_int(self.points, "ac.points", _HARD_MAX_ROWS)
        _number(self.start_hz, "ac.start_hz", positive=True)
        _number(self.stop_hz, "ac.stop_hz", positive=True)
        if self.stop_hz <= self.start_hz:
            raise CharacterizationError("ac.stop_hz must be greater than start_hz")


@dataclass(frozen=True, slots=True)
class TransientAnalysis:
    name: str
    outputs: tuple[TraceOutput, ...]
    step_seconds: float
    stop_seconds: float
    start_seconds: float = 0.0
    kind: Literal["tran"] = field(default="tran", init=False)

    def __post_init__(self) -> None:
        _validate_outputs(self.name, self.outputs)
        _number(self.step_seconds, "tran.step_seconds", positive=True)
        _number(self.stop_seconds, "tran.stop_seconds", positive=True)
        _number(self.start_seconds, "tran.start_seconds", minimum=0.0)
        if not 0 <= self.start_seconds < self.stop_seconds:
            raise CharacterizationError("tran.start_seconds must be in [0, stop_seconds)")
        if self.step_seconds > self.stop_seconds - self.start_seconds:
            raise CharacterizationError("tran.step_seconds exceeds the simulated interval")


@dataclass(frozen=True, slots=True)
class NoiseAnalysis:
    name: str
    outputs: tuple[TraceOutput, ...]
    output_node: str
    reference_node: str
    source: str
    sweep: SweepMode
    points: int
    start_hz: float
    stop_hz: float
    kind: Literal["noise"] = field(default="noise", init=False)

    def __post_init__(self) -> None:
        _validate_outputs(self.name, self.outputs)
        _spice_name(self.output_node, "noise.output_node")
        _spice_name(self.reference_node, "noise.reference_node")
        _spice_name(self.source, "noise.source")
        if self.source[0].casefold() not in {"v", "i"}:
            raise CharacterizationError(
                "noise.source must name an independent voltage or current source"
            )
        if self.sweep not in {"lin", "dec", "oct"}:
            raise CharacterizationError("noise.sweep must be 'lin', 'dec', or 'oct'")
        _positive_int(self.points, "noise.points", _HARD_MAX_ROWS)
        _number(self.start_hz, "noise.start_hz", positive=True)
        _number(self.stop_hz, "noise.stop_hz", positive=True)
        if self.stop_hz <= self.start_hz:
            raise CharacterizationError("noise.stop_hz must be greater than start_hz")


Analysis: TypeAlias = (
    OperatingPointAnalysis | DCSweepAnalysis | ACSweepAnalysis | TransientAnalysis | NoiseAnalysis
)


def _analysis_expected_rows(analysis: Analysis) -> int:
    if isinstance(analysis, OperatingPointAnalysis):
        return 1
    if isinstance(analysis, DCSweepAnalysis):
        span = (analysis.stop - analysis.start) / analysis.step
        return _HARD_MAX_ROWS + 1 if not math.isfinite(span) else math.floor(span + 1e-12) + 1
    if isinstance(analysis, TransientAnalysis):
        span = (analysis.stop_seconds - analysis.start_seconds) / analysis.step_seconds
        return _HARD_MAX_ROWS + 1 if not math.isfinite(span) else math.ceil(span - 1e-12) + 1
    if analysis.sweep == "lin":
        return analysis.points
    logarithm = math.log10 if analysis.sweep == "dec" else math.log2
    span = analysis.points * logarithm(analysis.stop_hz / analysis.start_hz)
    return _HARD_MAX_ROWS + 1 if not math.isfinite(span) else math.floor(span + 1e-12) + 1


def _validate_outputs(name: str, outputs: tuple[TraceOutput, ...]) -> None:
    _name(name, "analysis.name")
    if not outputs:
        raise CharacterizationError(f"analysis {name!r} must declare at least one output")
    keys = [output.name.casefold() for output in outputs]
    probes = [_probe_key(output.expression) for output in outputs]
    if len(keys) != len(set(keys)):
        raise CharacterizationError(f"analysis {name!r} has duplicate output names")
    if len(probes) != len(set(probes)):
        raise CharacterizationError(f"analysis {name!r} has duplicate output probes")


@dataclass(frozen=True, slots=True)
class CharacterizationPlan:
    name: str
    source_path: Path
    deck: Path
    corners: tuple[PVTCorner, ...]
    analyses: tuple[Analysis, ...]
    limits: CharacterizationLimits
    inputs: tuple[CharacterizationInput, ...] = ()
    _source_snapshot: bytes | None = field(default=None, repr=False)
    _deck_snapshot: bytes | None = field(default=None, repr=False)
    _source_snapshot_path: Path | None = field(default=None, repr=False, compare=False)
    _deck_snapshot_path: Path | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        _name(self.name, "plan.name")
        source_snapshot = self._source_snapshot
        if source_snapshot is None or (
            self._source_snapshot_path is not None
            and self._source_snapshot_path != self.source_path
        ):
            source_snapshot = _read_bytes_bounded(
                self.source_path, _MAX_PLAN_BYTES, "characterization plan"
            )
        deck_snapshot = self._deck_snapshot
        if deck_snapshot is None or (
            self._deck_snapshot_path is not None and self._deck_snapshot_path != self.deck
        ):
            deck_snapshot = _read_bytes_bounded(
                self.deck, self.limits.max_deck_bytes, "characterization deck"
            )
        if not isinstance(source_snapshot, bytes) or len(source_snapshot) > _MAX_PLAN_BYTES:
            raise CharacterizationError("characterization plan snapshot is invalid")
        if not isinstance(deck_snapshot, bytes):
            raise CharacterizationError("characterization deck snapshot is invalid")
        if len(deck_snapshot) > self.limits.max_deck_bytes:
            raise CharacterizationError("deck exceeds limits.max_deck_bytes")
        _decode_utf8(source_snapshot, "characterization plan")
        _decode_utf8(deck_snapshot, "characterization deck")
        object.__setattr__(self, "_source_snapshot", source_snapshot)
        object.__setattr__(self, "_deck_snapshot", deck_snapshot)
        object.__setattr__(self, "_source_snapshot_path", self.source_path)
        object.__setattr__(self, "_deck_snapshot_path", self.deck)
        if not self.corners:
            raise CharacterizationError("plan must declare at least one PVT corner")
        if not self.analyses:
            raise CharacterizationError("plan must declare at least one analysis")
        for analysis in self.analyses:
            _validate_outputs(analysis.name, analysis.outputs)
            for output in analysis.outputs:
                prefix = output.expression.split("(", 1)[0].casefold()
                frequency_only = {
                    "vr",
                    "vi",
                    "vm",
                    "vdb",
                    "vp",
                    "ir",
                    "ii",
                    "im",
                    "idb",
                    "ip",
                    "inoise",
                    "onoise",
                    "dni",
                    "dno",
                }
                if isinstance(analysis, ACSweepAnalysis | NoiseAnalysis):
                    allowed = {"vr", "vi", "vm", "vdb", "vp", "ir", "ii", "im", "idb", "ip"}
                    if isinstance(analysis, NoiseAnalysis):
                        allowed.update({"inoise", "onoise", "dni", "dno"})
                    if prefix not in allowed:
                        raise CharacterizationError(
                            f"analysis {analysis.name!r} must use an explicit scalar "
                            "frequency probe"
                        )
                    if isinstance(analysis, NoiseAnalysis) and prefix in {"inoise", "dni"}:
                        expected_unit = (
                            "A^2/Hz" if analysis.source[:1].casefold() == "i" else "V^2/Hz"
                        )
                        if output.unit != expected_unit:
                            raise CharacterizationError(
                                f"output probe {output.expression!r} requires unit "
                                f"{expected_unit!r} for source {analysis.source!r}"
                            )
                elif prefix in frequency_only:
                    raise CharacterizationError(
                        f"analysis {analysis.name!r} uses a frequency-only output probe"
                    )
        corner_keys = [
            (
                corner.process.casefold(),
                corner.voltage,
                corner.temperature_c,
                corner.parameters,
            )
            for corner in self.corners
        ]
        analysis_keys = [analysis.name.casefold() for analysis in self.analyses]
        if len(corner_keys) != len(set(corner_keys)):
            raise CharacterizationError("plan has duplicate PVT corners")
        corner_labels = [corner.label.casefold() for corner in self.corners]
        if len(corner_labels) != len(set(corner_labels)):
            raise CharacterizationError("plan has PVT corners with colliding evidence labels")
        if len(analysis_keys) != len(set(analysis_keys)):
            raise CharacterizationError("plan has duplicate analysis names")
        if len(self.corners) * len(self.analyses) > self.limits.max_runs:
            raise CharacterizationError("PVT corner and analysis product exceeds limits.max_runs")
        for analysis in self.analyses:
            if len(analysis.outputs) + 2 > self.limits.max_columns:
                raise CharacterizationError(
                    f"analysis {analysis.name!r} exceeds limits.max_columns"
                )
            expected_rows = _analysis_expected_rows(analysis)
            if isinstance(analysis, ACSweepAnalysis | NoiseAnalysis) and expected_rows < 2:
                raise CharacterizationError(
                    f"analysis {analysis.name!r} frequency sweep has fewer than two points"
                )
            if expected_rows > self.limits.max_rows:
                raise CharacterizationError(f"analysis {analysis.name!r} exceeds limits.max_rows")
        logical_names = [item.logical_name.casefold() for item in self.inputs]
        if len(logical_names) != len(set(logical_names)):
            raise CharacterizationError("plan has duplicate input logical names")
        logical_parts = [
            tuple(part.casefold() for part in Path(name).parts) for name in logical_names
        ]
        for left in logical_parts:
            for right in logical_parts:
                if len(left) < len(right) and right[: len(left)] == left:
                    raise CharacterizationError("plan input logical names have a prefix collision")
        total = 0
        for item in self.inputs:
            total += len(item.snapshot)
            if total > self.limits.max_input_bytes:
                raise CharacterizationError("plan inputs exceed limits.max_input_bytes")
        if len(self.deck_snapshot) > self.limits.max_deck_bytes:
            raise CharacterizationError("deck exceeds limits.max_deck_bytes")
        _validate_external_references(self)

    @property
    def source_snapshot(self) -> bytes:
        snapshot = self._source_snapshot
        if snapshot is None:  # pragma: no cover - established by __post_init__
            raise CharacterizationError("characterization plan has no source snapshot")
        return snapshot

    @property
    def deck_snapshot(self) -> bytes:
        snapshot = self._deck_snapshot
        if snapshot is None:  # pragma: no cover - established by __post_init__
            raise CharacterizationError("characterization plan has no deck snapshot")
        return snapshot

    def verify_sources_unchanged(self) -> None:
        if (
            _read_bytes_bounded(self.source_path, _MAX_PLAN_BYTES, "characterization plan")
            != self.source_snapshot
        ):
            raise CharacterizationError("characterization plan changed after its snapshot")
        if (
            _read_bytes_bounded(self.deck, self.limits.max_deck_bytes, "characterization deck")
            != self.deck_snapshot
        ):
            raise CharacterizationError("characterization deck changed after its snapshot")
        for item in self.inputs:
            item.verify_unchanged()

    @property
    def deck_sha256(self) -> str:
        return hashlib.sha256(self.deck_snapshot).hexdigest()

    def as_identity_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "name": self.name,
            "source": {
                "plan_name": self.source_path.name,
                "plan_sha256": hashlib.sha256(self.source_snapshot).hexdigest(),
                "deck_name": self.deck.name,
            },
            "deck_sha256": self.deck_sha256,
            "inputs": [item.as_identity_dict() for item in self.inputs],
            "corners": [corner.as_dict() for corner in self.corners],
            "analyses": [analysis_as_dict(analysis) for analysis in self.analyses],
            "limits": self.limits.as_dict(),
        }


def _read_bytes_bounded(path: Path, maximum: int, label: str) -> bytes:
    try:
        before = path.stat()
        if path.is_symlink() or not path.is_file():
            raise CharacterizationError(f"{label} is not a regular file")
        if before.st_size > maximum:
            raise CharacterizationError(f"{label} exceeds {maximum} bytes")
        with path.open("rb") as stream:
            payload = stream.read(maximum + 1)
            descriptor = os.fstat(stream.fileno())
        after = path.stat()
    except CharacterizationError:
        raise
    except OSError as error:
        raise CharacterizationError(f"cannot read {label}: {error}") from error
    before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    descriptor_identity = (
        descriptor.st_dev,
        descriptor.st_ino,
        descriptor.st_size,
        descriptor.st_mtime_ns,
    )
    if len(payload) > maximum:
        raise CharacterizationError(f"{label} exceeds {maximum} bytes")
    if (
        before_identity != after_identity
        or after_identity != descriptor_identity
        or len(payload) != after.st_size
    ):
        raise CharacterizationError(f"{label} changed while being read")
    return payload


def _decode_utf8(payload: bytes, label: str) -> str:
    try:
        return payload.decode("utf-8")
    except UnicodeError as error:
        raise CharacterizationError(f"{label} is not UTF-8") from error


def _read_utf8_bounded(path: Path, maximum: int, label: str) -> str:
    return _decode_utf8(_read_bytes_bounded(path, maximum, label), label)


def _matched_reference(match: re.Match[str]) -> str:
    for value in match.groups():
        if value is not None:
            return value
    raise CharacterizationError("external file reference has no path")


def _resolve_logical_reference(reference: str, origin: str) -> str:
    if (
        not reference
        or "\\" in reference
        or reference.startswith("/")
        or _INPUT_PATH.fullmatch(reference) is None
    ):
        raise CharacterizationError(f"external file reference {reference!r} is not a safe path")
    base = PurePosixPath(origin).parent.as_posix() if origin else "."
    logical = posixpath.normpath(posixpath.join(base, reference))
    candidate = PurePosixPath(logical)
    if logical in {"", ".", ".."} or logical.startswith("../") or candidate.is_absolute():
        raise CharacterizationError(f"external file reference {reference!r} escapes the plan")
    return logical


def _source_references(source: str, origin: str) -> tuple[str, ...]:
    references: list[str] = []
    for line in source.replace("\r\n", "\n").replace("\r", "\n").splitlines():
        if _INCLUDE_PREFIX.match(line) is not None:
            if _LIBRARY_SECTION.fullmatch(line) is not None:
                continue
            match = _INCLUDE.fullmatch(line) or _LIBRARY.fullmatch(line)
            if match is None:
                raise CharacterizationError("deck has an unsupported include or library directive")
            references.append(_resolve_logical_reference(_matched_reference(match), origin))
            continue
        references.extend(
            _resolve_logical_reference(_matched_reference(match), origin)
            for match in _FILE_REFERENCE.finditer(line)
        )
    return tuple(references)


def _validate_external_references(plan: CharacterizationPlan) -> None:
    declared = {item.logical_name.casefold(): item for item in plan.inputs}
    deck = _decode_utf8(plan.deck_snapshot, "characterization deck")
    sources = [("", deck)]
    for item in plan.inputs:
        sources.append(
            (
                item.logical_name,
                _decode_utf8(item.snapshot, f"characterization input {item.logical_name!r}"),
            )
        )
    for origin, source in sources:
        for reference in _source_references(source, origin):
            if reference.casefold() not in declared:
                raise CharacterizationError(
                    f"deck references undeclared characterization input {reference!r}"
                )


def _parse_outputs(value: object, where: str) -> tuple[TraceOutput, ...]:
    if not isinstance(value, list) or not value:
        raise CharacterizationError(f"{where} must be a non-empty array")
    outputs: list[TraceOutput] = []
    for index, raw in enumerate(value):
        if not isinstance(raw, dict):
            raise CharacterizationError(f"{where}[{index}] must be an object")
        _exact_keys(raw, {"name", "expression", "unit"}, set(), f"{where}[{index}]")
        outputs.append(
            TraceOutput(
                _name(raw["name"], f"{where}[{index}].name"),
                raw["expression"],
                raw["unit"],
            )
        )
    return tuple(outputs)


def _parse_sweep(value: object, where: str) -> SweepMode:
    if not isinstance(value, str) or value.casefold() not in {"lin", "dec", "oct"}:
        raise CharacterizationError(f"{where} must be 'lin', 'dec', or 'oct'")
    return value.casefold()  # type: ignore[return-value]


def _frequency_fields(raw: dict[str, Any], where: str) -> tuple[SweepMode, int, float, float]:
    sweep = _parse_sweep(raw["sweep"], f"{where}.sweep")
    points = _positive_int(raw["points"], f"{where}.points", _HARD_MAX_ROWS)
    start = _number(raw["start_hz"], f"{where}.start_hz", positive=True)
    stop = _number(raw["stop_hz"], f"{where}.stop_hz", positive=True)
    if stop <= start:
        raise CharacterizationError(f"{where}.stop_hz must be greater than start_hz")
    return sweep, points, start, stop


def _parse_analysis(raw: object, index: int) -> Analysis:
    where = f"analyses[{index}]"
    if not isinstance(raw, dict):
        raise CharacterizationError(f"{where} must be an object")
    kind = raw.get("kind")
    name = _name(raw.get("name"), f"{where}.name")
    outputs = _parse_outputs(raw.get("outputs"), f"{where}.outputs")
    common = {"kind", "name", "outputs"}
    if kind == "op":
        _exact_keys(raw, common, set(), where)
        return OperatingPointAnalysis(name, outputs)
    if kind == "dc":
        _exact_keys(
            raw,
            common | {"source", "axis_expression", "start", "stop", "step"},
            set(),
            where,
        )
        return DCSweepAnalysis(
            name,
            outputs,
            _spice_name(raw["source"], f"{where}.source"),
            raw["axis_expression"],
            _number(raw["start"], f"{where}.start"),
            _number(raw["stop"], f"{where}.stop"),
            _number(raw["step"], f"{where}.step"),
        )
    if kind == "ac":
        _exact_keys(
            raw,
            common | {"sweep", "points", "start_hz", "stop_hz"},
            set(),
            where,
        )
        sweep, points, start, stop = _frequency_fields(raw, where)
        return ACSweepAnalysis(name, outputs, sweep, points, start, stop)
    if kind == "tran":
        _exact_keys(
            raw,
            common | {"step_seconds", "stop_seconds"},
            {"start_seconds"},
            where,
        )
        step = _number(raw["step_seconds"], f"{where}.step_seconds", positive=True)
        stop = _number(raw["stop_seconds"], f"{where}.stop_seconds", positive=True)
        start = _number(raw.get("start_seconds", 0.0), f"{where}.start_seconds", minimum=0.0)
        return TransientAnalysis(name, outputs, step, stop, start)
    if kind == "noise":
        _exact_keys(
            raw,
            common
            | {
                "output_node",
                "reference_node",
                "source",
                "sweep",
                "points",
                "start_hz",
                "stop_hz",
            },
            set(),
            where,
        )
        sweep, points, start, stop = _frequency_fields(raw, where)
        return NoiseAnalysis(
            name,
            outputs,
            _spice_name(raw["output_node"], f"{where}.output_node"),
            _spice_name(raw["reference_node"], f"{where}.reference_node"),
            _spice_name(raw["source"], f"{where}.source"),
            sweep,
            points,
            start,
            stop,
        )
    raise CharacterizationError(f"{where}.kind must be op, dc, ac, tran, or noise")


def analysis_from_dict(raw: object) -> Analysis:
    """Reconstruct one strict analysis contract from its canonical mapping."""

    return _parse_analysis(raw, 0)


def _confined_file(root: Path, value: object, where: str) -> Path:
    if (
        not isinstance(value, str)
        or not value
        or value.startswith("/")
        or _INPUT_PATH.fullmatch(value) is None
    ):
        raise CharacterizationError(f"{where} must be a non-empty relative path")
    candidate = Path(value)
    if candidate.is_absolute() or ".." in candidate.parts or "\\" in value:
        raise CharacterizationError(f"{where} must be a safe relative path")
    resolved = (root / candidate).resolve()
    if resolved != root and not resolved.is_relative_to(root):
        raise CharacterizationError(f"{where} escapes the plan directory")
    if not resolved.is_file():
        raise CharacterizationError(f"{where} is not a readable regular file")
    return resolved


def load_characterization_plan(path: str | Path) -> CharacterizationPlan:
    """Load one bounded, duplicate-key-free characterization JSON plan."""

    source_path = Path(path).resolve()
    try:
        source_snapshot = _read_bytes_bounded(source_path, _MAX_PLAN_BYTES, "characterization plan")
        raw = strict_json_loads(_decode_utf8(source_snapshot, "characterization plan"))
    except CharacterizationError:
        raise
    except (OSError, ValueError, RecursionError) as error:
        raise CharacterizationError(
            f"cannot read characterization plan {source_path}: {error}"
        ) from error
    if not isinstance(raw, dict):
        raise CharacterizationError("characterization plan must be a JSON object")
    _exact_keys(
        raw,
        {"schema_version", "name", "deck", "corners", "analyses"},
        {"limits", "inputs"},
        "plan",
    )
    if (
        not isinstance(raw["schema_version"], int)
        or isinstance(raw["schema_version"], bool)
        or raw["schema_version"] != 1
    ):
        raise CharacterizationError("schema_version must be the integer 1")
    raw_limits = raw.get("limits", {})
    if not isinstance(raw_limits, dict):
        raise CharacterizationError("limits must be an object")
    allowed_limits = {
        "max_deck_bytes",
        "max_input_bytes",
        "max_output_bytes",
        "max_log_bytes",
        "max_rows",
        "max_columns",
        "max_runs",
    }
    _exact_keys(raw_limits, set(), allowed_limits, "limits")
    defaults = CharacterizationLimits()
    limits = CharacterizationLimits(
        **{
            field: _positive_int(
                raw_limits.get(field, getattr(defaults, field)),
                f"limits.{field}",
                maximum,
            )
            for field, maximum in {
                "max_deck_bytes": _HARD_MAX_DECK_BYTES,
                "max_input_bytes": _HARD_MAX_INPUT_BYTES,
                "max_output_bytes": _HARD_MAX_OUTPUT_BYTES,
                "max_log_bytes": _HARD_MAX_LOG_BYTES,
                "max_rows": _HARD_MAX_ROWS,
                "max_columns": _HARD_MAX_COLUMNS,
                "max_runs": _HARD_MAX_RUNS,
            }.items()
        }
    )
    raw_corners = raw["corners"]
    if not isinstance(raw_corners, list):
        raise CharacterizationError("corners must be an array")
    corners: list[PVTCorner] = []
    for index, item in enumerate(raw_corners):
        if not isinstance(item, dict):
            raise CharacterizationError(f"corners[{index}] must be an object")
        _exact_keys(
            item,
            {"process", "voltage", "temperature_c"},
            {"parameters"},
            f"corners[{index}]",
        )
        raw_parameters = item.get("parameters", {})
        if not isinstance(raw_parameters, dict):
            raise CharacterizationError(f"corners[{index}].parameters must be an object")
        parameters = tuple(
            (
                _name(name, f"corners[{index}].parameters name"),
                _number(value, f"corners[{index}].parameters.{name}"),
            )
            for name, value in sorted(raw_parameters.items())
        )
        corners.append(
            PVTCorner(
                _name(item["process"], f"corners[{index}].process"),
                _number(item["voltage"], f"corners[{index}].voltage", positive=True),
                _number(item["temperature_c"], f"corners[{index}].temperature_c"),
                parameters,
            )
        )
    raw_analyses = raw["analyses"]
    if not isinstance(raw_analyses, list):
        raise CharacterizationError("analyses must be an array")
    raw_inputs = raw.get("inputs", [])
    if not isinstance(raw_inputs, list) or not all(isinstance(item, str) for item in raw_inputs):
        raise CharacterizationError("inputs must be an array of relative paths")
    inputs: list[CharacterizationInput] = []
    for index, item in enumerate(raw_inputs):
        logical = Path(item).as_posix()
        input_path = _confined_file(source_path.parent, item, f"inputs[{index}]")
        inputs.append(
            CharacterizationInput(
                logical,
                input_path,
                _read_bytes_bounded(
                    input_path,
                    limits.max_input_bytes,
                    f"characterization input {logical!r}",
                ),
            )
        )
    deck_path = _confined_file(source_path.parent, raw["deck"], "plan.deck")
    deck_snapshot = _read_bytes_bounded(deck_path, limits.max_deck_bytes, "characterization deck")
    plan = CharacterizationPlan(
        _name(raw["name"], "plan.name"),
        source_path,
        deck_path,
        tuple(corners),
        tuple(_parse_analysis(item, index) for index, item in enumerate(raw_analyses)),
        limits,
        tuple(inputs),
        source_snapshot,
        deck_snapshot,
    )
    return plan


def analysis_as_dict(analysis: Analysis) -> dict[str, Any]:
    common: dict[str, Any] = {
        "kind": analysis.kind,
        "name": analysis.name,
        "outputs": [output.as_dict() for output in analysis.outputs],
    }
    if isinstance(analysis, DCSweepAnalysis):
        common.update(
            source=analysis.source,
            axis_expression=analysis.axis_expression,
            start=analysis.start,
            stop=analysis.stop,
            step=analysis.step,
        )
    elif isinstance(analysis, ACSweepAnalysis):
        common.update(
            sweep=analysis.sweep,
            points=analysis.points,
            start_hz=analysis.start_hz,
            stop_hz=analysis.stop_hz,
        )
    elif isinstance(analysis, TransientAnalysis):
        common.update(
            step_seconds=analysis.step_seconds,
            stop_seconds=analysis.stop_seconds,
            start_seconds=analysis.start_seconds,
        )
    elif isinstance(analysis, NoiseAnalysis):
        common.update(
            output_node=analysis.output_node,
            reference_node=analysis.reference_node,
            source=analysis.source,
            sweep=analysis.sweep,
            points=analysis.points,
            start_hz=analysis.start_hz,
            stop_hz=analysis.stop_hz,
        )
    return common


def _sweep_token(value: SweepMode) -> str:
    return value.upper()


def _xyce_transient_output_schedule(analysis: TransientAnalysis) -> str:
    """Request an exact, simulator-independent transient result grid.

    Xyce interprets the first value on ``.TRAN`` as an initial integration
    step, not as SPICE's print interval.  OUTPUTTIMEPOINTS makes the evidence
    shape explicit and prevents adaptive integration points from leaking into
    the normalized result.  Wrapping is deterministic and keeps generated
    netlists readable without changing the comma-delimited option value.
    """

    values = [_format_number(value) for value in _expected_axis(analysis)]
    chunks = [values[index : index + 8] for index in range(0, len(values), 8)]
    rendered = [
        f"{','.join(chunk)}{',' if index + 1 < len(chunks) else ''}"
        for index, chunk in enumerate(chunks)
    ]
    lines = [f".OPTIONS OUTPUT OUTPUTTIMEPOINTS={rendered[0]}"]
    lines.extend(f"+ {chunk}" for chunk in rendered[1:])
    return "\n".join(lines)


def xyce_analysis_directives(analysis: Analysis, *, result_file: str = "results.csv") -> str:
    """Compile one validated analysis to fixed-shape Xyce cards."""

    result_path = Path(result_file)
    if (
        result_path.name != result_file
        or not _NAME.fullmatch(result_path.stem)
        or result_path.suffix != ".csv"
    ):
        raise CharacterizationError("result_file must be an identifier followed by .csv")
    expressions = [output.expression for output in analysis.outputs]
    if isinstance(analysis, DCSweepAnalysis):
        expressions.insert(0, analysis.axis_expression)
    probes = " ".join(expressions)
    print_kind = "DC" if isinstance(analysis, OperatingPointAnalysis) else analysis.kind.upper()
    if isinstance(analysis, OperatingPointAnalysis):
        card = ".OP"
    elif isinstance(analysis, DCSweepAnalysis):
        card = " ".join(
            [
                ".DC",
                analysis.source,
                _format_number(analysis.start),
                _format_number(analysis.stop),
                _format_number(analysis.step),
            ]
        )
    elif isinstance(analysis, ACSweepAnalysis):
        card = " ".join(
            [
                ".AC",
                _sweep_token(analysis.sweep),
                str(analysis.points),
                _format_number(analysis.start_hz),
                _format_number(analysis.stop_hz),
            ]
        )
    elif isinstance(analysis, TransientAnalysis):
        card = " ".join(
            [
                ".TRAN",
                _format_number(analysis.step_seconds),
                _format_number(analysis.stop_seconds),
                _format_number(analysis.start_seconds),
            ]
        )
        card = f"{card}\n{_xyce_transient_output_schedule(analysis)}"
    else:
        card = " ".join(
            [
                ".NOISE",
                f"V({analysis.output_node},{analysis.reference_node})",
                analysis.source,
                _sweep_token(analysis.sweep),
                str(analysis.points),
                _format_number(analysis.start_hz),
                _format_number(analysis.stop_hz),
            ]
        )
    output = f".PRINT {print_kind} FORMAT=CSV FILE={result_file} PRECISION=17 {probes}"
    return f"{card}\n{output}"


def render_xyce_deck(plan: CharacterizationPlan, corner: PVTCorner, analysis: Analysis) -> bytes:
    """Materialize a plan without allowing values to introduce arbitrary SPICE cards."""

    source = _decode_utf8(plan.deck_snapshot, "characterization deck")
    source = source.replace("\r\n", "\n").replace("\r", "\n")
    if "\x00" in source:
        raise CharacterizationError("deck contains a NUL byte")
    declared_inputs = {item.logical_name.casefold() for item in plan.inputs}
    for referenced in _source_references(source, ""):
        if referenced.casefold() not in declared_inputs:
            raise CharacterizationError(
                f"deck references undeclared characterization input {referenced!r}"
            )
    lines = source.splitlines()
    if lines.count(_PVT_MARKER) != 1 or lines.count(_ANALYSIS_MARKER) != 1:
        raise CharacterizationError(
            f"deck must contain exactly one {_PVT_MARKER!r} and {_ANALYSIS_MARKER!r} line"
        )
    pvt = "\n".join(
        [
            f"* SimCairn process corner: {corner.process}",
            f".PARAM SIMCAIRN_VOLTAGE={_format_number(corner.voltage)}",
            *(
                f".PARAM SIMCAIRN_{name.upper()}={_format_number(value)}"
                for name, value in corner.parameters
            ),
            f".TEMP {_format_number(corner.temperature_c)}",
        ]
    )
    rendered = source.replace(_PVT_MARKER, pvt).replace(
        _ANALYSIS_MARKER, xyce_analysis_directives(analysis)
    )
    if not rendered.endswith("\n"):
        rendered += "\n"
    encoded = rendered.encode("utf-8")
    if len(encoded) > plan.limits.max_deck_bytes:
        raise CharacterizationError("rendered deck exceeds limits.max_deck_bytes")
    return encoded


def _probe_key(value: str) -> str:
    return "".join(value.split()).casefold()


@dataclass(frozen=True, slots=True)
class NormalizedTrace:
    axis_name: str
    axis_unit: str
    axis_values: tuple[float, ...]
    signals: tuple[tuple[str, str, tuple[float, ...]], ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "axis": {
                "name": self.axis_name,
                "unit": self.axis_unit,
                "values": list(self.axis_values),
            },
            "signals": {
                name: {"unit": unit, "values": list(values)} for name, unit, values in self.signals
            },
        }


def _rows(source: str, maximum_columns: int) -> list[list[str]]:
    meaningful = [line for line in source.splitlines() if line.strip()]
    if not meaningful:
        raise CharacterizationError("simulator result table is empty")
    comma = "," in meaningful[0]
    if comma:
        try:
            rows = list(csv.reader(io.StringIO("\n".join(meaningful)), strict=True))
        except csv.Error as error:
            raise CharacterizationError(f"simulator CSV is malformed: {error}") from error
    else:
        rows = [line.split() for line in meaningful]
    if any(not row or len(row) > maximum_columns for row in rows):
        raise CharacterizationError("simulator result table has an invalid column count")
    return rows


def _finite_cell(value: str, where: str) -> float:
    try:
        result = float(value)
    except ValueError as error:
        raise CharacterizationError(f"{where} is not numeric") from error
    if not math.isfinite(result):
        raise CharacterizationError(f"{where} is non-finite")
    return result


def _axis_close(left: float, right: float) -> bool:
    return math.isclose(left, right, rel_tol=1e-10, abs_tol=1e-15)


def _expected_axis(analysis: Analysis) -> tuple[float, ...]:
    count = _analysis_expected_rows(analysis)
    if isinstance(analysis, DCSweepAnalysis):
        return tuple(analysis.start + index * analysis.step for index in range(count))
    if isinstance(analysis, TransientAnalysis):
        values = [
            analysis.start_seconds + index * analysis.step_seconds for index in range(count - 1)
        ]
        values.append(analysis.stop_seconds)
        return tuple(values)
    if isinstance(analysis, ACSweepAnalysis | NoiseAnalysis):
        if analysis.sweep == "lin":
            return tuple(
                analysis.start_hz + index * (analysis.stop_hz - analysis.start_hz) / (count - 1)
                for index in range(count)
            )
        base = 10.0 if analysis.sweep == "dec" else 2.0
        return tuple(
            analysis.start_hz * base ** (index / analysis.points) for index in range(count)
        )
    return (0.0,)


def normalize_result_table(
    source: bytes,
    analysis: Analysis,
    *,
    simulator: Literal["xyce", "ngspice"],
    limits: CharacterizationLimits,
) -> NormalizedTrace:
    """Normalize bounded Xyce CSV or ngspice whitespace/CSV output to one contract."""

    if simulator not in {"xyce", "ngspice"}:
        raise CharacterizationError("simulator must be 'xyce' or 'ngspice'")
    if not isinstance(limits, CharacterizationLimits):
        raise CharacterizationError("limits must be CharacterizationLimits")
    if len(source) > limits.max_output_bytes:
        raise CharacterizationError("simulator result exceeds limits.max_output_bytes")
    try:
        text = source.decode("utf-8")
    except UnicodeError as error:
        raise CharacterizationError("simulator result is not UTF-8") from error
    rows = _rows(text, limits.max_columns)
    header = [item.strip() for item in rows[0]]
    if any(not item for item in header):
        raise CharacterizationError("simulator result has an empty header")
    keys = [_probe_key(item) for item in header]
    if len(keys) != len(set(keys)):
        raise CharacterizationError("simulator result has duplicate headers")
    body = rows[1:]
    if not body or len(body) > limits.max_rows:
        raise CharacterizationError("simulator result has an invalid row count")
    if any(len(row) != len(header) for row in body):
        raise CharacterizationError("simulator result rows have inconsistent column counts")

    output_indices: list[int] = []
    for output in analysis.outputs:
        key = _probe_key(output.expression)
        if key not in keys:
            raise CharacterizationError(
                f"simulator result is missing requested probe {output.expression!r}"
            )
        output_indices.append(keys.index(key))

    if isinstance(analysis, OperatingPointAnalysis):
        if len(body) != 1:
            raise CharacterizationError("operating-point result must contain exactly one row")
        axis_name, axis_unit = "index", "1"
        axis_values: tuple[float, ...] = (0.0,)
    else:
        expected_axis = _expected_axis(analysis)
        if len(body) != len(expected_axis):
            raise CharacterizationError(
                "simulator result row count does not match the declared analysis"
            )
        expected = {"time"} if isinstance(analysis, TransientAnalysis) else {"freq", "frequency"}
        if isinstance(analysis, DCSweepAnalysis):
            expected = {_probe_key(analysis.axis_expression)}
        candidates = [
            index
            for index, key in enumerate(keys)
            if key in expected and index not in output_indices
        ]
        if len(candidates) != 1:
            raise CharacterizationError("simulator result does not have one unambiguous axis")
        else:
            axis_index = candidates[0]
            axis_name = "time" if isinstance(analysis, TransientAnalysis) else "frequency"
            axis_unit = "s" if isinstance(analysis, TransientAnalysis) else "Hz"
            if isinstance(analysis, DCSweepAnalysis):
                axis_name = "sweep"
                axis_unit = "A" if analysis.source[:1].casefold() == "i" else "V"
            axis_values = tuple(
                _finite_cell(row[axis_index], f"row {index + 2} axis")
                for index, row in enumerate(body)
            )
        direction = -1 if isinstance(analysis, DCSweepAnalysis) and analysis.step < 0 else 1
        if any(direction * (right - left) <= 0 for left, right in pairwise(axis_values)):
            raise CharacterizationError("simulator result axis is not strictly monotonic")
        if len(axis_values) != len(expected_axis) or any(
            not _axis_close(observed, expected)
            for observed, expected in zip(axis_values, expected_axis, strict=True)
        ):
            raise CharacterizationError(
                "simulator result axis does not match the declared analysis"
            )

    signals = tuple(
        (
            output.name,
            output.unit,
            tuple(
                _finite_cell(row[column], f"row {row_index + 2} probe {output.expression}")
                for row_index, row in enumerate(body)
            ),
        )
        for output, column in zip(analysis.outputs, output_indices, strict=True)
    )
    return NormalizedTrace(axis_name, axis_unit, axis_values, signals)


__all__ = [
    "ACSweepAnalysis",
    "Analysis",
    "CharacterizationError",
    "CharacterizationInput",
    "CharacterizationLimits",
    "CharacterizationPlan",
    "DCSweepAnalysis",
    "NoiseAnalysis",
    "NormalizedTrace",
    "OperatingPointAnalysis",
    "PVTCorner",
    "TraceOutput",
    "TransientAnalysis",
    "analysis_as_dict",
    "analysis_from_dict",
    "load_characterization_plan",
    "normalize_result_table",
    "render_xyce_deck",
    "xyce_analysis_directives",
]
