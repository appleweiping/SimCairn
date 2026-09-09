import asyncio
import os
import sys
import time
from pathlib import Path

import pytest

import simcairn.xyce as xyce

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows process-job contract")


def _run_python(tmp_path: Path, *code_arguments: str) -> xyce._ProcessResult:
    return asyncio.run(
        xyce._run_process(
            (sys.executable, "-I", "-c", *code_arguments),
            cwd=tmp_path,
            environment=dict(os.environ),
            timeout_seconds=5.0,
            maximum_log_bytes=1024,
            process_name="test child",
        )
    )


def test_child_cannot_execute_before_windows_job_assignment(tmp_path, monkeypatch):
    marker = tmp_path / "child-ran"
    original_attach = xyce._attach_windows_job
    observed_before_assignment: list[bool] = []

    def delayed_attach(process_id: int) -> int | None:
        deadline = time.monotonic() + 0.25
        while time.monotonic() < deadline and not marker.exists():
            time.sleep(0.005)
        observed_before_assignment.append(marker.exists())
        return original_attach(process_id)

    monkeypatch.setattr(xyce, "_attach_windows_job", delayed_attach)
    result = _run_python(
        tmp_path,
        "from pathlib import Path; import sys; Path(sys.argv[1]).write_text('ran')",
        str(marker),
    )

    assert result.returncode == 0
    assert marker.read_text(encoding="utf-8") == "ran"
    assert observed_before_assignment == [False]


def test_fast_child_survives_delayed_windows_job_assignment(tmp_path, monkeypatch):
    original_attach = xyce._attach_windows_job

    def delayed_attach(process_id: int) -> int | None:
        time.sleep(0.25)
        return original_attach(process_id)

    monkeypatch.setattr(xyce, "_attach_windows_job", delayed_attach)

    for _ in range(5):
        result = _run_python(tmp_path, "pass")
        assert result.returncode == 0


def test_resume_failure_terminates_suspended_child_without_running_it(tmp_path, monkeypatch):
    marker = tmp_path / "must-not-run"

    def fail_resume(_process_id: int) -> None:
        raise xyce.XyceExecutionError("injected resume failure")

    monkeypatch.setattr(xyce, "_resume_windows_process", fail_resume)
    started = time.monotonic()
    with pytest.raises(xyce.XyceExecutionError, match="injected resume failure"):
        _run_python(
            tmp_path,
            "from pathlib import Path; import sys; Path(sys.argv[1]).write_text('ran')",
            str(marker),
        )

    assert time.monotonic() - started < 2.0
    assert not marker.exists()


def test_assignment_failure_terminates_suspended_child_without_running_it(tmp_path, monkeypatch):
    marker = tmp_path / "must-not-run"

    def fail_attach(_process_id: int) -> None:
        time.sleep(0.1)
        raise xyce.XyceExecutionError("injected assignment failure")

    monkeypatch.setattr(xyce, "_attach_windows_job", fail_attach)
    started = time.monotonic()
    with pytest.raises(xyce.XyceExecutionError, match="injected assignment failure"):
        _run_python(
            tmp_path,
            "from pathlib import Path; import sys; Path(sys.argv[1]).write_text('ran')",
            str(marker),
        )

    assert time.monotonic() - started < 2.0
    assert not marker.exists()


def test_cancellation_terminates_job_bound_descendant(tmp_path):
    ready = tmp_path / "descendant-started"
    orphan = tmp_path / "orphan"
    child_code = (
        "import pathlib,subprocess,sys,time;"
        "subprocess.Popen([sys.executable,'-I','-c',"
        "'import pathlib,sys,time;time.sleep(1);pathlib.Path(sys.argv[1]).write_text(\"orphan\")',"
        "sys.argv[2]]);"
        "pathlib.Path(sys.argv[1]).write_text('ready');"
        "time.sleep(30)"
    )

    async def cancel_after_descendant_starts() -> None:
        task = asyncio.create_task(
            xyce._run_process(
                (sys.executable, "-I", "-c", child_code, str(ready), str(orphan)),
                cwd=tmp_path,
                environment=dict(os.environ),
                timeout_seconds=35.0,
                maximum_log_bytes=1024,
                process_name="test child",
            )
        )
        async with asyncio.timeout(5.0):
            while not ready.exists():
                if task.done():
                    await task
                await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(cancel_after_descendant_starts())
    time.sleep(1.2)
    assert not orphan.exists()
