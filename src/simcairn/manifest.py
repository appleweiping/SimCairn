"""Strict TOML manifest loading with local input confinement."""

from __future__ import annotations

import math
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ManifestError(ValueError):
    """Raised with one or more actionable manifest diagnostics."""

    def __init__(self, messages: list[str] | tuple[str, ...] | str) -> None:
        self.messages = (messages,) if isinstance(messages, str) else tuple(messages)
        super().__init__("; ".join(self.messages))


@dataclass(frozen=True, slots=True)
class SimulatorConfig:
    adapter: str
    executable: str | None
    environment: tuple[tuple[str, str], ...]
    measure_analysis: str | None = None


@dataclass(frozen=True, slots=True)
class TemplateConfig:
    deck: Path
    inputs: tuple[Path, ...]


@dataclass(frozen=True, slots=True)
class SweepConfig:
    mode: str
    parameters: tuple[tuple[str, tuple[str, ...]], ...]


@dataclass(frozen=True, slots=True)
class RunConfig:
    timeout_seconds: float
    jobs: int
    resources: tuple[tuple[str, int], ...]
    fail_fast: bool


@dataclass(frozen=True, slots=True)
class MeasureConfig:
    name: str
    source: str
    field: str
    unit: str


@dataclass(frozen=True, slots=True)
class Manifest:
    path: Path
    simulator: SimulatorConfig
    template: TemplateConfig
    sweep: SweepConfig
    run: RunConfig
    measures: tuple[MeasureConfig, ...]

    @property
    def root(self) -> Path:
        return self.path.parent


_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_VALUE = re.compile(r"[A-Za-z0-9_.+\-]+\Z")
_ARTIFACT = re.compile(r"[A-Za-z0-9_.\-/]+\Z")
_MAX_TIMEOUT_SECONDS = 31_536_000.0


def _table(data: dict[str, Any], name: str, errors: list[str]) -> dict[str, Any]:
    value = data.get(name)
    if not isinstance(value, dict):
        errors.append(f"[{name}] table is required")
        return {}
    return value


def _string(table: dict[str, Any], key: str, context: str, errors: list[str]) -> str:
    value = table.get(key)
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{context}.{key} must be a non-empty string")
        return ""
    return value.strip()


def _reject_unknown_keys(
    table: dict[str, Any], allowed: set[str], context: str, errors: list[str]
) -> None:
    for unknown in sorted(set(table) - allowed):
        errors.append(f"unknown {context} key {unknown!r}")


def _canonical_sweep_value(value: Any, name: str, errors: list[str]) -> str:
    if isinstance(value, bool):
        rendered = "true" if value else "false"
    elif isinstance(value, int):
        rendered = str(value)
    elif isinstance(value, float):
        if not math.isfinite(value):
            errors.append(f"sweep.{name} contains a non-finite value")
            return "0"
        rendered = repr(value)
    elif isinstance(value, str):
        rendered = value.strip()
    else:
        errors.append(f"sweep.{name} values must be strings or finite scalars")
        return "0"
    if not rendered or not _VALUE.fullmatch(rendered):
        errors.append(
            f"sweep.{name} value {rendered!r} contains whitespace or unsafe template characters"
        )
    return rendered


def _confined_path(root: Path, raw: str, label: str, errors: list[str]) -> Path:
    candidate = Path(raw)
    resolved = candidate.resolve() if candidate.is_absolute() else (root / candidate).resolve()
    if resolved != root and not resolved.is_relative_to(root):
        errors.append(f"{label} escapes the manifest directory: {raw}")
    elif not resolved.is_file():
        errors.append(f"{label} is not a readable regular file: {raw}")
    return resolved


def load_manifest(path: str | Path) -> Manifest:
    manifest_path = Path(path).resolve()
    try:
        with manifest_path.open("rb") as stream:
            data = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ManifestError(f"cannot read manifest {manifest_path}: {error}") from error
    if not isinstance(data, dict):
        raise ManifestError("manifest root must be a TOML table")
    errors: list[str] = []
    version = data.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version != 1:
        errors.append("version must be the integer 1")
    allowed_top = {"version", "simulator", "template", "sweep", "run", "measure"}
    for unknown in sorted(set(data) - allowed_top):
        errors.append(f"unknown top-level key {unknown!r}")

    simulator_data = _table(data, "simulator", errors)
    _reject_unknown_keys(
        simulator_data,
        {"adapter", "executable", "environment", "measure_analysis"},
        "simulator",
        errors,
    )
    adapter = _string(simulator_data, "adapter", "simulator", errors).casefold()
    if adapter not in {"mock-rc", "ngspice", "xyce"}:
        errors.append("simulator.adapter must be 'mock-rc', 'ngspice', or 'xyce'")
    executable_value = simulator_data.get("executable")
    executable = None
    if executable_value is not None:
        if isinstance(executable_value, str) and executable_value.strip():
            executable = executable_value.strip()
        else:
            errors.append("simulator.executable must be a non-empty string when present")
    if adapter == "ngspice" and executable is None:
        executable = "ngspice"
    if adapter == "xyce" and executable is None:
        executable = "Xyce"
    measure_analysis_value = simulator_data.get("measure_analysis")
    measure_analysis = None
    if adapter == "xyce":
        if not isinstance(measure_analysis_value, str) or measure_analysis_value.casefold() not in {
            "tran",
            "dc",
            "ac",
            "noise",
        }:
            errors.append(
                "simulator.measure_analysis is required for xyce and must be "
                "'tran', 'dc', 'ac', or 'noise'"
            )
        else:
            measure_analysis = measure_analysis_value.casefold()
    elif measure_analysis_value is not None:
        errors.append("simulator.measure_analysis is only valid for the xyce adapter")
    environment_data = simulator_data.get("environment", {})
    environment: list[tuple[str, str]] = []
    if not isinstance(environment_data, dict):
        errors.append("simulator.environment must be a table")
    else:
        for name, value in sorted(environment_data.items()):
            if not _NAME.fullmatch(name) or not isinstance(value, str) or "\x00" in value:
                errors.append(f"invalid simulator.environment entry {name!r}")
            else:
                environment.append((name, value))

    template_data = _table(data, "template", errors)
    _reject_unknown_keys(template_data, {"deck", "inputs"}, "template", errors)
    deck_raw = _string(template_data, "deck", "template", errors)
    root = manifest_path.parent
    deck = _confined_path(root, deck_raw, "template.deck", errors) if deck_raw else root
    raw_inputs = template_data.get("inputs", [])
    inputs: list[Path] = []
    if not isinstance(raw_inputs, list) or not all(isinstance(item, str) for item in raw_inputs):
        errors.append("template.inputs must be an array of paths")
    else:
        for index, item in enumerate(raw_inputs):
            inputs.append(_confined_path(root, item, f"template.inputs[{index}]", errors))
    if len(set(inputs)) != len(inputs):
        errors.append("template.inputs contains duplicate resolved paths")

    sweep_data = _table(data, "sweep", errors)
    mode = str(sweep_data.get("mode", "product")).casefold()
    if mode not in {"product", "zip"}:
        errors.append("sweep.mode must be 'product' or 'zip'")
    parameters: list[tuple[str, tuple[str, ...]]] = []
    parameter_names: set[str] = set()
    for name, values in sweep_data.items():
        if name == "mode":
            continue
        if not _NAME.fullmatch(name):
            errors.append(f"invalid sweep parameter name {name!r}")
            continue
        name_key = name.casefold()
        if name_key in parameter_names:
            errors.append(f"duplicate sweep parameter name {name!r} (case-insensitive)")
            continue
        parameter_names.add(name_key)
        if not isinstance(values, list) or not values:
            errors.append(f"sweep.{name} must be a non-empty array")
            continue
        canonical = tuple(_canonical_sweep_value(value, name, errors) for value in values)
        if mode != "zip" and len(set(canonical)) != len(canonical):
            errors.append(f"sweep.{name} contains duplicate canonical values")
        parameters.append((name, canonical))
    if not parameters:
        errors.append("[sweep] must declare at least one parameter array")

    run_data = _table(data, "run", errors)
    _reject_unknown_keys(
        run_data, {"timeout_seconds", "jobs", "fail_fast", "resources"}, "run", errors
    )
    timeout_value = run_data.get("timeout_seconds", 60)
    jobs_value = run_data.get("jobs", 1)
    fail_fast_value = run_data.get("fail_fast", False)
    timeout_seconds = 60.0
    if not isinstance(timeout_value, (int, float)) or isinstance(timeout_value, bool):
        errors.append("run.timeout_seconds must be a positive number")
    else:
        try:
            candidate_timeout = float(timeout_value)
        except OverflowError:
            candidate_timeout = math.inf
        if (
            not math.isfinite(candidate_timeout)
            or candidate_timeout <= 0
            or candidate_timeout > _MAX_TIMEOUT_SECONDS
        ):
            errors.append(
                "run.timeout_seconds must be finite, positive, and no greater than 31536000"
            )
        else:
            timeout_seconds = candidate_timeout
    if not isinstance(jobs_value, int) or isinstance(jobs_value, bool) or jobs_value < 1:
        errors.append("run.jobs must be a positive integer")
        jobs = 1
    else:
        jobs = jobs_value
    if not isinstance(fail_fast_value, bool):
        errors.append("run.fail_fast must be a boolean")
        fail_fast = False
    else:
        fail_fast = fail_fast_value
    resources_data = run_data.get("resources", {})
    resources: list[tuple[str, int]] = []
    if not isinstance(resources_data, dict):
        errors.append("run.resources must be a table")
    else:
        for name, value in sorted(resources_data.items()):
            if (
                not _NAME.fullmatch(name)
                or not isinstance(value, int)
                or isinstance(value, bool)
                or value < 1
            ):
                errors.append(f"run.resources.{name} must be a positive integer")
            else:
                resources.append((name, value))

    raw_measures = data.get("measure", [])
    measures: list[MeasureConfig] = []
    if not isinstance(raw_measures, list):
        errors.append("[[measure]] must be an array of tables")
    else:
        seen_measures: set[str] = set()
        for index, raw_measure in enumerate(raw_measures):
            if not isinstance(raw_measure, dict):
                errors.append(f"measure[{index}] must be a table")
                continue
            _reject_unknown_keys(
                raw_measure, {"name", "source", "field", "unit"}, f"measure[{index}]", errors
            )
            name = _string(raw_measure, "name", f"measure[{index}]", errors)
            raw_source = raw_measure.get("source", "metrics.json")
            if not isinstance(raw_source, str):
                errors.append(f"measure[{index}].source must be a string")
                source = ""
            else:
                source = raw_source
            raw_field = raw_measure.get("field", name)
            if not isinstance(raw_field, str):
                errors.append(f"measure[{index}].field must be a string")
                field = ""
            else:
                field = raw_field
            raw_unit = raw_measure.get("unit", "1")
            if (
                not isinstance(raw_unit, str)
                or not raw_unit.strip()
                or any(ord(character) < 32 for character in raw_unit)
            ):
                errors.append(f"measure[{index}].unit must be a non-empty printable string")
                unit = "1"
            else:
                unit = raw_unit.strip()
            if not _NAME.fullmatch(name):
                errors.append(f"measure[{index}].name must be an identifier")
            if name.casefold() in seen_measures:
                errors.append(f"duplicate measure name {name!r}")
            seen_measures.add(name.casefold())
            if name.casefold() in parameter_names:
                errors.append(f"measure[{index}].name {name!r} conflicts with a sweep parameter")
            if (
                not _ARTIFACT.fullmatch(source)
                or source.startswith("/")
                or ".." in Path(source).parts
            ):
                errors.append(f"measure[{index}].source must be a safe relative artifact path")
            if not _NAME.fullmatch(field):
                errors.append(f"measure[{index}].field must be an identifier")
            measures.append(MeasureConfig(name, source, field, unit))
    if not measures:
        errors.append("at least one [[measure]] table is required")

    if errors:
        raise ManifestError(errors)
    return Manifest(
        manifest_path,
        SimulatorConfig(adapter, executable, tuple(environment), measure_analysis),
        TemplateConfig(deck, tuple(inputs)),
        SweepConfig(mode, tuple(parameters)),
        RunConfig(timeout_seconds, jobs, tuple(resources), fail_fast),
        tuple(measures),
    )
