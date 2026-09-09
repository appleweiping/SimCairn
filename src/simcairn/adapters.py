"""Simulator adapters with argv-only subprocess contracts."""

from __future__ import annotations

import json
import math
import re
import subprocess  # nosec B404
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from simcairn.manifest import ManifestError, SimulatorConfig
from simcairn.xyce import XyceCommand, XyceError, probe_xyce_sync

# Security rationale for B404: adapters use fixed argv lists and never enable a shell.

_XYCE_ARTIFACT_LIMIT = 16 * 1024 * 1024
_XYCE_NUMBER = r"[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?"
_XYCE_FAILED_MEASUREMENT = re.compile(
    r"^\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*FAILED(?:\s|$)",
    re.IGNORECASE | re.MULTILINE,
)
_XYCE_MEASURE_SECTION_HEADER = re.compile(
    r"^\s*\*{5}\s+Measure Functions\s+\*{5}\s*$", re.IGNORECASE
)
_XYCE_SECTION_BOUNDARY = re.compile(r"^\s*\*{5}(?:\s|$)")
_XYCE_SUCCESSFUL_MEASUREMENT = re.compile(
    rf"^\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<value>{_XYCE_NUMBER})(?=\s|$)",
    re.IGNORECASE,
)


class AdapterError(RuntimeError):
    pass


def _read_optional_xyce_diagnostic(path: Path) -> str:
    """Read an existing Xyce diagnostic artifact without trusting special files."""

    if path.is_symlink():
        raise AdapterError(f"Xyce diagnostic {path.name} must be a regular file")
    if not path.exists():
        return ""
    if not path.is_file():
        raise AdapterError(f"Xyce diagnostic {path.name} must be a regular file")
    try:
        with path.open("rb") as stream:
            diagnostic = stream.read(_XYCE_ARTIFACT_LIMIT + 1)
    except OSError as error:
        raise AdapterError(f"cannot read Xyce diagnostic {path.name}: {error}") from error
    if len(diagnostic) > _XYCE_ARTIFACT_LIMIT:
        raise AdapterError(f"Xyce diagnostic {path.name} exceeds 16777216 bytes")
    return diagnostic.decode("utf-8", errors="replace")


def _positive_xyce_measurements(log: str, requested: list[str]) -> dict[str, float]:
    """Extract unique successful values from Xyce's verbose measure section."""

    requested_by_name = {field.casefold(): field for field in requested}
    if len(requested_by_name) != len(requested):
        raise AdapterError("requested Xyce measurement names must be unique ignoring case")

    lines = log.splitlines()
    headers = [
        index for index, line in enumerate(lines) if _XYCE_MEASURE_SECTION_HEADER.fullmatch(line)
    ]
    if not headers:
        raise AdapterError("Xyce log contains no positive success evidence section")
    if len(headers) != 1:
        raise AdapterError("Xyce log contains ambiguous Measure Functions sections")

    start = headers[0] + 1
    end = next(
        (index for index in range(start, len(lines)) if _XYCE_SECTION_BOUNDARY.match(lines[index])),
        None,
    )
    if end is None:
        raise AdapterError("Xyce Measure Functions success evidence section is incomplete")

    values: dict[str, float] = {}
    for line in lines[start:end]:
        match = _XYCE_SUCCESSFUL_MEASUREMENT.match(line)
        if match is None:
            continue
        field = requested_by_name.get(match.group("name").casefold())
        if field is None:
            continue
        if field in values:
            raise AdapterError(f"Xyce log has ambiguous success evidence for measurement {field!r}")
        value = float(match.group("value"))
        if not math.isfinite(value):
            raise AdapterError(f"Xyce log success evidence for measurement {field!r} is non-finite")
        values[field] = value

    missing = [field for field in requested if field not in values]
    if missing:
        raise AdapterError(
            "Xyce log lacks positive success evidence for requested measurements: "
            + ", ".join(missing)
        )
    return values


class SimulatorAdapter(Protocol):
    @property
    def name(self) -> str: ...

    def identity(self) -> str: ...

    def command(self, sandbox: Path, payload: dict[str, Any]) -> list[str]: ...

    def expected_artifacts(self) -> tuple[str, ...]: ...

    def collect(self, sandbox: Path, payload: dict[str, Any]) -> None: ...


@dataclass(frozen=True, slots=True)
class MockRCAdapter:
    name: str = "mock-rc"

    def identity(self) -> str:
        return "simcairn-mock-rc/1"

    def command(self, sandbox: Path, payload: dict[str, Any]) -> list[str]:
        del sandbox, payload
        return [
            sys.executable,
            "-m",
            "simcairn.mock_simulator",
            "--point",
            "point.json",
            "--output",
            "metrics.json",
        ]

    def expected_artifacts(self) -> tuple[str, ...]:
        return ("metrics.json", "stdout.log", "stderr.log")

    def collect(self, sandbox: Path, payload: dict[str, Any]) -> None:
        del payload
        if not (sandbox / "metrics.json").is_file():
            raise AdapterError("mock simulator did not create metrics.json")


@dataclass(frozen=True, slots=True)
class NgspiceAdapter:
    executable: str
    name: str = "ngspice"

    def identity(self) -> str:
        try:
            # The version probe is an argv-only invocation of the configured executable.
            completed = subprocess.run(  # nosec B603
                [self.executable, "--version"],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ManifestError(
                f"cannot identify ngspice executable {self.executable!r}: {error}"
            ) from error
        output = "\n".join(part for part in (completed.stdout, completed.stderr) if part)
        version = None
        for line in output.splitlines():
            match = re.search(r"\bngspice-(\d+(?:\.\d+)*)\b", line, re.IGNORECASE)
            if match is not None:
                version = match.group(1)
                break
        if completed.returncode != 0 or version is None:
            raise ManifestError(f"ngspice executable {self.executable!r} did not return a version")
        return f"simcairn-ngspice/2:ngspice-{version}"

    def command(self, sandbox: Path, payload: dict[str, Any]) -> list[str]:
        del sandbox, payload
        return [self.executable, "-b", "-o", "ngspice_output.log", "deck.sp"]

    def expected_artifacts(self) -> tuple[str, ...]:
        return ("metrics.json", "stdout.log", "stderr.log", "ngspice_output.log")

    def collect(self, sandbox: Path, payload: dict[str, Any]) -> None:
        log_path = sandbox / "ngspice_output.log"
        if not log_path.is_file():
            raise AdapterError("ngspice did not create ngspice_output.log")
        text = log_path.read_text(encoding="utf-8", errors="replace")
        metrics: dict[str, float] = {}
        for field in payload.get("measure_fields", []):
            pattern = re.compile(
                rf"^\s*{re.escape(str(field))}\s*=\s*"
                r"([-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?)\s*$",
                re.MULTILINE | re.IGNORECASE,
            )
            match = pattern.search(text)
            if match:
                metrics[str(field)] = float(match.group(1))
        requested = [str(field) for field in payload.get("measure_fields", [])]
        missing = [field for field in requested if field not in metrics]
        if missing:
            raise AdapterError(
                "ngspice output is missing requested measurements: " + ", ".join(missing)
            )
        (sandbox / "metrics.json").write_text(
            json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )


@dataclass(frozen=True, slots=True)
class XyceAdapter:
    """Scalar ``.MEASURE`` adapter for the existing manifest activity graph."""

    executable: str
    measure_analysis: str
    environment: tuple[tuple[str, str], ...] = ()
    name: str = "xyce"

    def identity(self) -> str:
        measurement = xyce_measurement_filename(self.measure_analysis)
        try:
            identity = probe_xyce_sync(
                XyceCommand.real(self.executable), environment=dict(self.environment)
            )
        except XyceError as error:
            raise ManifestError(
                f"cannot identify Xyce executable {self.executable!r}: {error}"
            ) from error
        return (
            f"simcairn-xyce-measure/4:{self.measure_analysis}:{measurement}:Xyce-{identity.version}:"
            f"command-sha256-{identity.command_sha256}"
        )

    def command(self, sandbox: Path, payload: dict[str, Any]) -> list[str]:
        deck_path = sandbox / "deck.sp"
        if deck_path.is_symlink() or not deck_path.is_file():
            raise AdapterError("Xyce deck.sp must be a regular file")
        try:
            with deck_path.open("rb") as stream:
                deck_bytes = stream.read(16 * 1024 * 1024 + 1)
        except OSError as error:
            raise AdapterError(f"cannot read Xyce deck.sp: {error}") from error
        if len(deck_bytes) > 16 * 1024 * 1024:
            raise AdapterError("Xyce deck.sp exceeds 16777216 bytes")
        try:
            deck = deck_bytes.decode("utf-8")
        except UnicodeError as error:
            raise AdapterError("Xyce deck.sp is not UTF-8") from error
        cards: list[tuple[str, str]] = []
        for line in deck.splitlines():
            if re.match(r"^\s*\.step\b", line, re.IGNORECASE) is not None:
                raise AdapterError("Xyce scalar .MEASURE activities do not support .STEP")
            if re.match(r"^\s*\.meas(?:ure)?\b", line, re.IGNORECASE) is None:
                continue
            match = re.match(
                r"^\s*\.meas(?:ure)?\s+(tran|dc|ac|noise)\s+"
                r"([A-Za-z_][A-Za-z0-9_]*)\b",
                line,
                re.IGNORECASE,
            )
            if match is None:
                raise AdapterError("Xyce deck contains an unsupported scalar .MEASURE card")
            cards.append((match.group(1).casefold(), match.group(2)))
        if not cards:
            raise AdapterError("Xyce deck contains no scalar .MEASURE cards")
        families = {family for family, _name in cards}
        if families != {self.measure_analysis}:
            raise AdapterError(
                "Xyce deck .MEASURE family does not match simulator.measure_analysis"
            )
        requested = [str(field) for field in payload.get("measure_fields", [])]
        declared = [name for _family, name in cards]
        if len({name.casefold() for name in declared}) != len(declared):
            raise AdapterError("Xyce deck repeats a scalar .MEASURE name")
        if {name.casefold() for name in declared} != {name.casefold() for name in requested}:
            raise AdapterError("Xyce deck .MEASURE names do not match requested measure fields")
        return [
            self.executable,
            "-l",
            "xyce.log",
            "-o",
            "xyce_output",
            "deck.sp",
        ]

    def expected_artifacts(self) -> tuple[str, ...]:
        return (
            "metrics.json",
            "stdout.log",
            "stderr.log",
            "xyce.log",
            xyce_measurement_filename(self.measure_analysis),
        )

    def collect(self, sandbox: Path, payload: dict[str, Any]) -> None:
        measurement_name = xyce_measurement_filename(self.measure_analysis)
        measurement_path = sandbox / measurement_name
        log_path = sandbox / "xyce.log"
        if measurement_path.is_symlink() or not measurement_path.is_file():
            raise AdapterError(f"Xyce did not create {measurement_name}")
        next_step_path = sandbox / f"{measurement_name[:-1]}1"
        if next_step_path.is_symlink() or next_step_path.exists():
            raise AdapterError("Xyce scalar .MEASURE activity produced unsupported .STEP output")
        if log_path.is_symlink() or not log_path.is_file():
            raise AdapterError("Xyce did not create xyce.log")
        if log_path.stat().st_size > _XYCE_ARTIFACT_LIMIT:
            raise AdapterError("Xyce log exceeds 16777216 bytes")
        if measurement_path.stat().st_size > _XYCE_ARTIFACT_LIMIT:
            raise AdapterError("Xyce measurement output exceeds 16777216 bytes")
        try:
            with measurement_path.open("rb") as stream:
                payload_bytes = stream.read(_XYCE_ARTIFACT_LIMIT + 1)
        except OSError as error:
            raise AdapterError(f"cannot read Xyce measurement output: {error}") from error
        if len(payload_bytes) > _XYCE_ARTIFACT_LIMIT:
            raise AdapterError("Xyce measurement output exceeds 16777216 bytes")
        try:
            text = payload_bytes.decode("utf-8")
        except UnicodeError as error:
            raise AdapterError("Xyce measurement output is not UTF-8") from error
        requested = [str(field) for field in payload.get("measure_fields", [])]
        requested_by_name = {field.casefold(): field for field in requested}
        diagnostics = {
            diagnostic_name: _read_optional_xyce_diagnostic(sandbox / diagnostic_name)
            for diagnostic_name in ("stdout.log", "stderr.log", "xyce.log")
        }
        for diagnostic_name, diagnostic in diagnostics.items():
            for match in _XYCE_FAILED_MEASUREMENT.finditer(diagnostic):
                field = requested_by_name.get(match.group("name").casefold())
                if field is not None:
                    raise AdapterError(
                        f"Xyce measurement {field!r} failed according to {diagnostic_name}"
                    )
        metrics: dict[str, float] = {}
        for field in requested:
            pattern = re.compile(
                rf"^\s*{re.escape(str(field))}\s*=\s*"
                r"([-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?)\s*$",
                re.MULTILINE | re.IGNORECASE,
            )
            matches = pattern.findall(text)
            if len(matches) > 1:
                raise AdapterError(f"Xyce measurement {field!r} is duplicated")
            if matches:
                value = float(matches[0])
                if not math.isfinite(value):
                    raise AdapterError(f"Xyce measurement {field!r} is non-finite")
                metrics[str(field)] = value
        missing = [field for field in requested if field not in metrics]
        if missing:
            raise AdapterError(
                "Xyce output is missing requested measurements: " + ", ".join(missing)
            )
        positive = _positive_xyce_measurements(diagnostics["xyce.log"], requested)
        for field, value in metrics.items():
            if positive[field] != value:
                raise AdapterError(
                    f"Xyce measurement {field!r} disagrees between xyce.log and {measurement_name}"
                )
        try:
            with (sandbox / "metrics.json").open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(json.dumps(metrics, indent=2, sort_keys=True) + "\n")
        except FileExistsError as error:
            raise AdapterError("refusing to overwrite Xyce metrics.json") from error


def create_adapter(config: SimulatorConfig) -> SimulatorAdapter:
    if config.adapter == "mock-rc":
        return MockRCAdapter()
    if config.adapter == "ngspice" and config.executable:
        return NgspiceAdapter(config.executable)
    if config.adapter == "xyce" and config.executable and config.measure_analysis:
        return XyceAdapter(config.executable, config.measure_analysis, config.environment)
    raise ManifestError(f"unsupported simulator adapter {config.adapter!r}")


def xyce_measurement_filename(analysis: str) -> str:
    """Return Xyce's deterministic first scalar-measure output for an analysis family."""

    suffix = {"tran": "mt0", "dc": "ms0", "ac": "ma0", "noise": "ma0"}.get(analysis)
    if suffix is None:
        raise ManifestError("Xyce scalar measure analysis must be 'tran', 'dc', 'ac', or 'noise'")
    return f"xyce_output.{suffix}"
