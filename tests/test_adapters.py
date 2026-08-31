import json
import subprocess
from types import SimpleNamespace

import pytest

from simcairn.adapters import (
    AdapterError,
    MockRCAdapter,
    NgspiceAdapter,
    create_adapter,
)
from simcairn.manifest import ManifestError, SimulatorConfig
from simcairn.mock_simulator import main as mock_main


def test_mock_adapter_contract_and_collection(tmp_path):
    adapter = MockRCAdapter()
    assert adapter.identity() == "simcairn-mock-rc/1"
    command = adapter.command(tmp_path, {})
    assert command[1:3] == ["-m", "simcairn.mock_simulator"]
    assert adapter.expected_artifacts() == ("metrics.json", "stdout.log", "stderr.log")

    with pytest.raises(AdapterError, match=r"metrics\.json"):
        adapter.collect(tmp_path, {})
    (tmp_path / "metrics.json").write_text("{}", encoding="utf-8")
    adapter.collect(tmp_path, {})


def test_ngspice_identity_finds_and_normalizes_version_line(monkeypatch):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(
            returncode=0,
            stdout="******\n** ngspice-44.2 : simulator\nCopyright\n",
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert NgspiceAdapter("my ngspice").identity() == "simcairn-ngspice/2:ngspice-44.2"
    assert calls[0][0] == ["my ngspice", "--version"]
    assert calls[0][1] == {
        "check": False,
        "capture_output": True,
        "text": True,
        "timeout": 5,
    }


def test_ngspice_identity_searches_stderr_when_stdout_is_nonempty(monkeypatch):
    completed = SimpleNamespace(
        returncode=0,
        stdout="decorative stdout\n",
        stderr="** ngspice-42 : simulator\n",
    )
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: completed)
    assert NgspiceAdapter("ngspice").identity() == "simcairn-ngspice/2:ngspice-42"


@pytest.mark.parametrize(
    "failure",
    [OSError("not found"), subprocess.TimeoutExpired(["ngspice"], 5)],
)
def test_ngspice_identity_wraps_launch_failures(monkeypatch, failure):
    def fail(*args, **kwargs):
        del args, kwargs
        raise failure

    monkeypatch.setattr(subprocess, "run", fail)
    with pytest.raises(ManifestError, match="cannot identify"):
        NgspiceAdapter("missing").identity()


@pytest.mark.parametrize(
    "completed",
    [
        SimpleNamespace(returncode=3, stdout="failed\n", stderr=""),
        SimpleNamespace(returncode=0, stdout="", stderr=""),
        SimpleNamespace(returncode=0, stdout="******\nno version token\n", stderr=""),
    ],
)
def test_ngspice_identity_rejects_unsuccessful_or_empty_version(monkeypatch, completed):
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: completed)
    with pytest.raises(ManifestError, match="did not return a version"):
        NgspiceAdapter("ngspice").identity()


def test_ngspice_command_artifacts_and_measure_collection(tmp_path):
    adapter = NgspiceAdapter("/opt/tools/ngspice")
    assert adapter.command(tmp_path, {}) == [
        "/opt/tools/ngspice",
        "-b",
        "-o",
        "ngspice_output.log",
        "deck.sp",
    ]
    assert adapter.expected_artifacts() == (
        "metrics.json",
        "stdout.log",
        "stderr.log",
        "ngspice_output.log",
    )
    (tmp_path / "ngspice_output.log").write_text(
        "gain = -1.25e+2\nNOISE = .0042\nignored = 9\n", encoding="utf-8"
    )
    adapter.collect(tmp_path, {"measure_fields": ["gain", "noise"]})
    assert json.loads((tmp_path / "metrics.json").read_text(encoding="utf-8")) == {
        "gain": -125.0,
        "noise": 0.0042,
    }


def test_ngspice_collection_requires_log_and_every_measurement(tmp_path):
    adapter = NgspiceAdapter("ngspice")
    with pytest.raises(AdapterError, match="did not create"):
        adapter.collect(tmp_path, {"measure_fields": ["gain"]})
    (tmp_path / "ngspice_output.log").write_text("gain = 1invalid\n", encoding="utf-8")
    with pytest.raises(AdapterError, match="missing requested"):
        adapter.collect(tmp_path, {"measure_fields": ["gain"]})
    (tmp_path / "ngspice_output.log").write_text("gain = 1\n", encoding="utf-8")
    with pytest.raises(AdapterError, match="noise"):
        adapter.collect(tmp_path, {"measure_fields": ["gain", "noise"]})


def test_adapter_registry_is_explicit():
    assert isinstance(create_adapter(SimulatorConfig("mock-rc", None, ())), MockRCAdapter)
    ngspice = create_adapter(SimulatorConfig("ngspice", "custom", ()))
    assert isinstance(ngspice, NgspiceAdapter)
    assert ngspice.executable == "custom"
    with pytest.raises(ManifestError, match="unsupported"):
        create_adapter(SimulatorConfig("other", None, ()))


def test_mock_simulator_cli_writes_metrics_and_reports_bad_input(tmp_path, capsys):
    point = tmp_path / "point.json"
    output = tmp_path / "metrics.json"
    point.write_text('{"R":"1k","C":"2n"}', encoding="utf-8")
    assert mock_main(["--point", str(point), "--output", str(output)]) == 0
    assert json.loads(output.read_text(encoding="utf-8"))["cutoff_hz"] == pytest.approx(
        79577.47154594767
    )

    point.write_text("[]", encoding="utf-8")
    assert mock_main(["--point", str(point), "--output", str(output)]) == 2
    assert "point JSON must be an object" in capsys.readouterr().err

    point.write_text("not-json", encoding="utf-8")
    assert mock_main(["--point", str(point), "--output", str(output)]) == 2
    assert "mock-rc:" in capsys.readouterr().err


def test_mock_simulator_cli_reports_output_io_errors(tmp_path, capsys):
    point = tmp_path / "point.json"
    point.write_text('{"R":"1k","C":"1n"}', encoding="utf-8")
    output_directory = tmp_path / "directory"
    output_directory.mkdir()
    assert mock_main(["--point", str(point), "--output", str(output_directory)]) == 2
    assert "mock-rc:" in capsys.readouterr().err
