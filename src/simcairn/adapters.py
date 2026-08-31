"""Simulator adapters with argv-only subprocess contracts."""

from __future__ import annotations

import json
import re
import subprocess  # nosec B404
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from simcairn.manifest import ManifestError, SimulatorConfig

# Security rationale for B404: adapters use fixed argv lists and never enable a shell.


class AdapterError(RuntimeError):
    pass


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
        version_line = (completed.stdout or completed.stderr).splitlines()
        if completed.returncode != 0 or not version_line:
            raise ManifestError(f"ngspice executable {self.executable!r} did not return a version")
        return "simcairn-ngspice/1:" + version_line[0].strip()

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
        if not metrics:
            raise AdapterError("ngspice output contains none of the requested measurements")
        (sandbox / "metrics.json").write_text(
            json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )


def create_adapter(config: SimulatorConfig) -> SimulatorAdapter:
    if config.adapter == "mock-rc":
        return MockRCAdapter()
    if config.adapter == "ngspice" and config.executable:
        return NgspiceAdapter(config.executable)
    raise ManifestError(f"unsupported simulator adapter {config.adapter!r}")
