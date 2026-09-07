"""Append-only run events and single-writer locking."""

from __future__ import annotations

import json
import math
import os
import secrets
import socket
import subprocess  # nosec B404
import sys
from collections.abc import Callable
from contextlib import AbstractContextManager, suppress
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from types import TracebackType
from typing import Any

from simcairn.model import canonical_json, strict_json_loads

# Security rationale for B404/B603: process probes use fixed argv and shell=False.


class JournalError(RuntimeError):
    pass


def _probe_process(pid: int) -> tuple[str, str | None]:
    """Return ``(alive|dead|unknown, start-marker)`` without sending a signal."""

    if pid <= 0:
        return "dead", None
    if sys.platform.startswith("linux"):
        path = Path(f"/proc/{pid}/stat")
        try:
            text = path.read_text(encoding="ascii")
        except FileNotFoundError:
            return "dead", None
        except OSError:
            return "unknown", None
        closing = text.rfind(")")
        fields = text[closing + 2 :].split() if closing >= 0 else []
        return ("alive", f"linux-start:{fields[19]}") if len(fields) > 19 else ("unknown", None)

    if sys.platform == "win32":
        command = [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f"(Get-Process -Id {pid} -ErrorAction Stop).StartTime.ToUniversalTime().Ticks",
        ]
    else:
        command = ["ps", "-o", "lstart=", "-p", str(pid)]
    try:
        completed = subprocess.run(  # nosec B603
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unknown", None
    marker = completed.stdout.strip()
    if completed.returncode == 0 and marker:
        return "alive", f"{sys.platform}-start:{marker}"
    return "dead", None


@lru_cache(maxsize=4)
def _probe_current_process(pid: int) -> tuple[str, str | None]:
    """Cache only this interpreter's marker; the PID key keeps forks separate."""

    if pid != os.getpid():
        return "unknown", None
    return _probe_process(pid)


def _owner_state(owner: object) -> str:
    if not isinstance(owner, dict):
        return "unknown"
    if set(owner) != {"schema_version", "pid", "host", "process_start", "nonce"}:
        return "unknown"
    version = owner.get("schema_version")
    nonce = owner.get("nonce")
    if (
        isinstance(version, bool)
        or version != 1
        or not isinstance(nonce, str)
        or len(nonce) != 32
        or any(character not in "0123456789abcdef" for character in nonce)
    ):
        return "unknown"
    if owner.get("host") != socket.gethostname():
        return "foreign"
    pid = owner.get("pid")
    recorded_marker = owner.get("process_start")
    if not isinstance(pid, int) or isinstance(pid, bool) or not isinstance(recorded_marker, str):
        return "unknown"
    if recorded_marker == "unknown":
        return "unknown"
    status, current_marker = (
        _probe_current_process(pid) if pid == os.getpid() else _probe_process(pid)
    )
    if status == "dead":
        return "stale"
    if status == "alive" and current_marker != recorded_marker:
        return "stale"
    return status


def _read_owner(path: Path) -> tuple[bytes, object]:
    try:
        raw = path.read_bytes()
    except OSError:
        return b"", None
    try:
        return raw, strict_json_loads(raw)
    except (json.JSONDecodeError, ValueError):
        return raw, None


def _directory_owner(path: Path) -> tuple[Path | None, bytes, object]:
    try:
        entries = tuple(path.iterdir())
    except OSError:
        return None, b"", None
    markers = [item for item in entries if item.is_file() and item.name.startswith("owner-")]
    if len(entries) != 1 or len(markers) != 1:
        return None, b"", None
    marker = markers[0]
    raw, owner = _read_owner(marker)
    return marker, raw, owner


def _remove_directory_lock(path: Path, marker: Path, raw: bytes) -> None:
    if not raw or marker.read_bytes() != raw:
        raise JournalError("run.lock changed during inspection; retry unlock")
    try:
        marker.unlink()
        path.rmdir()
    except (FileNotFoundError, OSError) as error:
        raise JournalError("run.lock changed during unlock; retry") from error


def _lock_is_redirected(run_directory: Path, path: Path) -> bool:
    """Treat a link or junction in place of the direct lock child as hostile."""

    try:
        resolved_run = run_directory.resolve()
        expected = run_directory.absolute()
        return (
            run_directory.is_symlink()
            or not run_directory.is_dir()
            or resolved_run != expected
            or path.is_symlink()
            or path.resolve() != expected / "run.lock"
        )
    except (OSError, RuntimeError):
        return True


def run_lock_state(run_directory: Path) -> str | None:
    """Report a run lock without touching it.

    `clear_run_lock` already decides whether an owner is stale, but it decides
    it in order to remove the lock. Anything that needs to know whether a run is
    busy -- reclaiming the store, for one -- must be able to ask without
    changing the answer.

    Returns None when the run is not locked, and otherwise the owner state:
    `alive`, `stale`, `foreign`, or `unknown`. Only `stale` means the run has
    certainly finished; a lock this host cannot identify is not evidence that
    nobody holds it.
    """

    path = run_directory / "run.lock"
    if path.is_symlink():
        return "unknown"
    if not path.exists():
        return None
    if _lock_is_redirected(run_directory, path):
        return "unknown"
    try:
        if path.is_dir():
            _marker, _raw, owner = _directory_owner(path)
        else:
            _raw, owner = _read_owner(path)
    except (OSError, JournalError):
        return "unknown"
    return _owner_state(owner)


def clear_run_lock(run_directory: Path, *, force: bool = False) -> dict[str, Any]:
    """Remove a stale lock, or force an audited removal when ownership is uncertain."""

    path = run_directory / "run.lock"
    if path.is_symlink():
        raise JournalError("refusing to unlock a redirected run.lock")
    if not path.exists():
        return {"removed": False, "reason": "run is not locked"}
    if _lock_is_redirected(run_directory, path):
        raise JournalError("refusing to unlock a redirected run.lock")
    is_directory = path.is_dir()
    marker: Path | None = None
    if is_directory:
        marker, raw, owner = _directory_owner(path)
    else:
        raw, owner = _read_owner(path)
    state = _owner_state(owner)
    if state != "stale" and not force:
        raise JournalError(
            f"refusing to unlock {state} owner; inspect run.lock and use --force if appropriate"
        )
    audit = {
        "time": datetime.now(UTC).isoformat(),
        "action": "forced-unlock" if force else "stale-unlock",
        "actor": {"pid": os.getpid(), "host": socket.gethostname()},
        "owner": owner,
        "observed_state": state,
    }
    if is_directory and marker is None:
        raise JournalError("run.lock directory has an invalid owner marker")
    if not is_directory and (not raw or path.read_bytes() != raw):
        raise JournalError("run.lock changed during inspection; retry unlock")
    audit_path = run_directory / "unlock-audit.jsonl"
    with audit_path.open("ab") as stream:
        stream.write((canonical_json(audit) + "\n").encode("utf-8"))
        stream.flush()
        os.fsync(stream.fileno())
    if is_directory:
        if marker is None:
            raise JournalError("run.lock directory has an invalid owner marker")
        _remove_directory_lock(path, marker, raw)
    else:
        try:
            path.unlink()
        except FileNotFoundError as error:
            raise JournalError("run.lock changed during unlock; retry") from error
    return {"removed": True, "reason": state, "audit": str(audit_path)}


def replay(path: Path) -> tuple[dict[str, Any], ...]:
    if not path.exists():
        return ()
    data = path.read_bytes()
    lines = data.splitlines(keepends=True)
    events: list[dict[str, Any]] = []
    for index, raw_line in enumerate(lines):
        try:
            event = strict_json_loads(raw_line)
        except (json.JSONDecodeError, ValueError) as error:
            is_truncated_tail = index == len(lines) - 1 and not raw_line.endswith((b"\n", b"\r"))
            if is_truncated_tail:
                break
            raise JournalError(f"invalid journal JSON on line {index + 1}: {error}") from error
        required = {"sequence", "time", "state", "activity_id", "message"}
        allowed_fields = {frozenset(required), frozenset({*required, "duration_seconds"})}
        if not isinstance(event, dict):
            raise JournalError(f"invalid journal event schema on line {index + 1}")
        sequence = event.get("sequence")
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence != len(events):
            raise JournalError(f"invalid journal sequence on line {index + 1}")
        if frozenset(event) not in allowed_fields:
            raise JournalError(f"invalid journal event schema on line {index + 1}")
        if not isinstance(event.get("time"), str) or not event["time"]:
            raise JournalError(f"invalid journal time on line {index + 1}")
        if not isinstance(event.get("state"), str) or not event["state"]:
            raise JournalError(f"invalid journal state on line {index + 1}")
        activity_id = event.get("activity_id")
        if activity_id is not None and (not isinstance(activity_id, str) or not activity_id):
            raise JournalError(f"invalid journal activity ID on line {index + 1}")
        if not isinstance(event.get("message"), str):
            raise JournalError(f"invalid journal message on line {index + 1}")
        if "duration_seconds" in event:
            duration = event["duration_seconds"]
            if (
                isinstance(duration, bool)
                or not isinstance(duration, int | float)
                or not math.isfinite(duration)
                or duration < 0
            ):
                raise JournalError(f"invalid journal duration on line {index + 1}")
        events.append(event)
    return tuple(events)


class Journal:
    def __init__(self, path: Path, clock: Callable[[], datetime] | None = None) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.clock = clock or (lambda: datetime.now(UTC))
        self.sequence = len(replay(path))

    def append(
        self,
        state: str,
        *,
        activity_id: str | None = None,
        message: str = "",
        duration_seconds: float | None = None,
    ) -> dict[str, Any]:
        event: dict[str, Any] = {
            "sequence": self.sequence,
            "time": self.clock().isoformat(),
            "state": state,
            "activity_id": activity_id,
            "message": message,
        }
        if duration_seconds is not None:
            event["duration_seconds"] = duration_seconds
        encoded = (canonical_json(event) + "\n").encode("utf-8")
        with self.path.open("ab") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        self.sequence += 1
        return event


def latest_activity_states(events: tuple[dict[str, Any], ...]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for event in events:
        activity_id = event.get("activity_id")
        if isinstance(activity_id, str):
            result[activity_id] = event
    return result


class RunLock(AbstractContextManager["RunLock"]):
    def __init__(self, run_directory: Path) -> None:
        self.path = run_directory / "run.lock"
        self.acquired = False
        self._payload: bytes | None = None
        self._marker: Path | None = None

    def __enter__(self) -> RunLock:
        if _lock_is_redirected(self.path.parent, self.path):
            raise JournalError("refusing to use a redirected or missing run directory")
        process_status, process_start = _probe_current_process(os.getpid())
        payload = (
            canonical_json(
                {
                    "schema_version": 1,
                    "pid": os.getpid(),
                    "host": socket.gethostname(),
                    "process_start": process_start if process_status == "alive" else "unknown",
                    "nonce": secrets.token_hex(16),
                }
            )
            + "\n"
        )
        encoded_payload = payload.encode("utf-8")
        for _ in range(3):
            try:
                self.path.mkdir()
            except FileExistsError as error:
                if _lock_is_redirected(self.path.parent, self.path):
                    raise JournalError("refusing to use a redirected run.lock") from error
                if self.path.is_dir():
                    marker, raw, owner = _directory_owner(self.path)
                else:
                    marker = None
                    raw, owner = _read_owner(self.path)
                state = _owner_state(owner)
                if state != "stale":
                    raise JournalError(
                        f"run is already locked by a {state} owner: {self.path.parent.name}"
                    ) from error
                try:
                    if self.path.is_dir():
                        if marker is None:
                            raise JournalError("run.lock directory has an invalid owner marker")
                        _remove_directory_lock(self.path, marker, raw)
                    else:
                        if not raw or self.path.read_bytes() != raw:
                            continue
                        self.path.unlink()
                except FileNotFoundError:
                    continue
                continue
            if _lock_is_redirected(self.path.parent, self.path):
                with suppress(OSError):
                    self.path.rmdir()
                raise JournalError("refusing to use a redirected run.lock")
            nonce = strict_json_loads(encoded_payload)["nonce"]
            marker = self.path / f"owner-{nonce}.json"
            try:
                with marker.open("xb") as stream:
                    stream.write(encoded_payload)
                    stream.flush()
                    os.fsync(stream.fileno())
            except OSError:
                marker.unlink(missing_ok=True)
                with suppress(OSError):
                    self.path.rmdir()
                continue
            self._payload = encoded_payload
            self._marker = marker
            self.acquired = True
            return self
        raise JournalError(f"could not acquire run lock safely: {self.path.parent.name}")

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback
        if self.acquired:
            marker = self._marker
            if marker is not None:
                current, _owner = _read_owner(marker)
                if self._payload is not None and current == self._payload:
                    marker.unlink(missing_ok=True)
                    with suppress(OSError):
                        self.path.rmdir()
            self.acquired = False
            self._payload = None
            self._marker = None
