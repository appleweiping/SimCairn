"""Bounded Xyce execution and content-addressed PVT characterization evidence."""

from __future__ import annotations

import asyncio
import contextlib
import errno
import hashlib
import math
import os
import platform
import re
import shutil
import signal
import sys
import tempfile
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

from simcairn.characterization import (
    Analysis,
    CharacterizationError,
    CharacterizationLimits,
    CharacterizationPlan,
    PVTCorner,
    analysis_as_dict,
    analysis_from_dict,
    normalize_result_table,
    render_xyce_deck,
)
from simcairn.fingerprints import fingerprint, sha256_file, stable_json
from simcairn.journal import JournalError, RunLock
from simcairn.model import strict_json_loads
from simcairn.provenance import current_producer_identity

_VERSION = re.compile(
    r"(?:\bXyce(?:Rad|NF)?(?:\(TM\))?\s+(?:\([A-Za-z0-9_.-]+\)\s*)?Release\s+"
    r"|\bXyce(?:\(TM\))?.{0,96}?\bVersion[:\s]+)"
    r"([0-9]+(?:\.[0-9]+){1,2})\b",
    re.IGNORECASE | re.DOTALL,
)
_ENVIRONMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_EVIDENCE_PREFIX = re.compile(
    r"runs/[A-Za-z_][A-Za-z0-9_]*__v[A-Za-z0-9mp]+__t[A-Za-z0-9mp]+/"
    r"[A-Za-z_][A-Za-z0-9_]*\Z"
)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_INHERITED_ENVIRONMENT = (
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "WINDIR",
    "LD_LIBRARY_PATH",
    "DYLD_LIBRARY_PATH",
)
_FIXED_ENVIRONMENT = {"HOME", "TEMP", "TMP", "LANG", "LC_ALL", "TZ", "PYTHONIOENCODING"}
_MAX_ENVIRONMENT_ENTRIES = 64
_MAX_ENVIRONMENT_VALUE = 32_768
_MAX_COMMAND_PARTS = 16
_MAX_COMMAND_PART = 4_096
_MAX_EXECUTABLE_BYTES = 1024 * 1024 * 1024
_MAX_CACHE_MANIFEST_BYTES = 8 * 1024 * 1024
_MAX_CACHE_REPORT_BYTES = 256 * 1024 * 1024
_PROBE_TIMEOUT_SECONDS = 10.0
_TERMINATE_GRACE_SECONDS = 2.0
_WINDOWS_CREATE_NEW_PROCESS_GROUP = 0x00000200
_LINUX_RENAME_NOREPLACE = 1
_DARWIN_RENAME_EXCL = 0x00000004


class XyceError(RuntimeError):
    """The executable, execution, or persisted Xyce evidence is invalid."""


class XyceExecutionError(XyceError):
    """A bounded Xyce child process failed."""

    def __init__(
        self,
        message: str,
        *,
        returncode: int | None = None,
        stdout: bytes = b"",
        stderr: bytes = b"",
        log: bytes = b"",
    ) -> None:
        super().__init__(message)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.log = log


EvidenceClass = Literal["real", "controlled-test-double"]


@dataclass(frozen=True, slots=True)
class XyceCommand:
    """An argv prefix; the CLI only constructs the ``real`` form."""

    argv: tuple[str, ...]
    evidence_class: EvidenceClass = "real"

    def __post_init__(self) -> None:
        if not self.argv or len(self.argv) > _MAX_COMMAND_PARTS:
            raise XyceError(f"Xyce command must contain 1 to {_MAX_COMMAND_PARTS} argv parts")
        for part in self.argv:
            if (
                not isinstance(part, str)
                or not part
                or len(part) > _MAX_COMMAND_PART
                or "\x00" in part
                or any(ord(character) < 32 or ord(character) == 127 for character in part)
            ):
                raise XyceError("Xyce command argv contains an invalid part")
        if self.evidence_class not in {"real", "controlled-test-double"}:
            raise XyceError("Xyce command evidence_class is invalid")

    @classmethod
    def real(cls, executable: str = "Xyce") -> XyceCommand:
        return cls((executable,), "real")

    @classmethod
    def controlled_test_double(cls, *argv: str) -> XyceCommand:
        """Label a synthetic executable so its output cannot masquerade as real evidence."""

        return cls(tuple(argv), "controlled-test-double")


@dataclass(frozen=True, slots=True)
class XyceToolIdentity:
    version: str
    executable_name: str
    executable_sha256: str
    executable_size: int
    command_sha256: str
    evidence_class: EvidenceClass

    def as_dict(self) -> dict[str, str | int]:
        return {
            "name": "Xyce",
            "version": self.version,
            "executable_name": self.executable_name,
            "executable_sha256": self.executable_sha256,
            "executable_size": self.executable_size,
            "command_sha256": self.command_sha256,
            "evidence_class": self.evidence_class,
        }


@dataclass(frozen=True, slots=True)
class _ProcessResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes
    duration_seconds: float


def _attach_windows_job(process_id: int) -> int | None:  # pragma: no cover - native OS glue
    if sys.platform != "win32":
        return None
    import ctypes
    from ctypes import wintypes

    class _BasicLimits(ctypes.Structure):
        _fields_ = [
            ("per_process_time", ctypes.c_longlong),
            ("per_job_time", ctypes.c_longlong),
            ("limit_flags", wintypes.DWORD),
            ("minimum_working_set", ctypes.c_size_t),
            ("maximum_working_set", ctypes.c_size_t),
            ("active_process_limit", wintypes.DWORD),
            ("affinity", ctypes.c_size_t),
            ("priority_class", wintypes.DWORD),
            ("scheduling_class", wintypes.DWORD),
        ]

    class _IoCounters(ctypes.Structure):
        _fields_ = [
            (name, ctypes.c_ulonglong)
            for name in (
                "read_operations",
                "write_operations",
                "other_operations",
                "read_bytes",
                "write_bytes",
                "other_bytes",
            )
        ]

    class _ExtendedLimits(ctypes.Structure):
        _fields_ = [
            ("basic", _BasicLimits),
            ("io", _IoCounters),
            ("process_memory", ctypes.c_size_t),
            ("job_memory", ctypes.c_size_t),
            ("peak_process_memory", ctypes.c_size_t),
            ("peak_job_memory", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        raise XyceExecutionError(f"cannot create Windows process job: {ctypes.get_last_error()}")
    try:
        limits = _ExtendedLimits()
        limits.basic.limit_flags = 0x00002000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel32.SetInformationJobObject(
            job, 9, ctypes.byref(limits), ctypes.sizeof(limits)
        ):
            raise XyceExecutionError(
                f"cannot configure Windows process job: {ctypes.get_last_error()}"
            )
        process_handle = kernel32.OpenProcess(0x0101, False, process_id)
        if not process_handle:
            raise XyceExecutionError(
                f"cannot open Xyce process for job assignment: {ctypes.get_last_error()}"
            )
        try:
            if not kernel32.AssignProcessToJobObject(job, process_handle):
                raise XyceExecutionError(
                    f"cannot assign Xyce to a bounded process job: {ctypes.get_last_error()}"
                )
        finally:
            kernel32.CloseHandle(process_handle)
    except BaseException:
        kernel32.CloseHandle(job)
        raise
    return int(job)


def _windows_job_action(  # pragma: no cover - native OS glue
    handle: int | None, *, terminate: bool
) -> None:
    if handle is None:
        return
    if sys.platform != "win32":
        raise XyceExecutionError("Windows process job actions are unavailable on this platform")
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    function = kernel32.TerminateJobObject if terminate else kernel32.CloseHandle
    if terminate:
        function.argtypes = [wintypes.HANDLE, wintypes.UINT]
        function.restype = wintypes.BOOL
        function(handle, 1)
    else:
        function.argtypes = [wintypes.HANDLE]
        function.restype = wintypes.BOOL
        function(handle)


def _hash_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _bounded_file_identity(path: Path) -> tuple[int, str]:
    try:
        before = path.stat()
        if before.st_size <= 0 or before.st_size > _MAX_EXECUTABLE_BYTES:
            raise XyceError("command file is empty or exceeds the executable size limit")
        digest = sha256_file(path)
        after = path.stat()
    except OSError as error:
        raise XyceError(f"cannot hash command file {path.name!r}: {error}") from error
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise XyceError(f"command file {path.name!r} changed while being identified")
    return before.st_size, digest


def _prepare_command(command: XyceCommand, environment: dict[str, str]) -> tuple[str, ...]:
    executable = _resolved_executable(command, environment)
    prepared = [str(executable)]
    for value in command.argv[1:]:
        candidate = Path(value)
        try:
            prepared.append(str(candidate.resolve(strict=True)) if candidate.is_file() else value)
        except OSError as error:
            raise XyceError(f"cannot inspect Xyce command argument {value!r}: {error}") from error
    return tuple(prepared)


def _command_digest(argv: tuple[str, ...]) -> str:
    logical: list[dict[str, str | int]] = []
    for index, value in enumerate(argv):
        candidate = Path(value)
        if index == 0 or candidate.is_file():
            resolved = candidate.resolve()
            size, digest = _bounded_file_identity(resolved)
            logical.append(
                {
                    "kind": "file",
                    "name": resolved.name,
                    "size": size,
                    "sha256": digest,
                }
            )
        else:
            logical.append({"kind": "literal", "value": value})
    return fingerprint({"argv": logical})


def _resolved_executable(command: XyceCommand, environment: dict[str, str]) -> Path:
    raw = command.argv[0]
    candidate = shutil.which(raw, path=environment.get("PATH"))
    if candidate is None:
        candidate = raw if Path(raw).is_file() else None
    if candidate is None:
        raise XyceError(f"cannot resolve Xyce executable {raw!r}")
    try:
        path = Path(candidate).resolve(strict=True)
        stat = path.stat()
    except OSError as error:
        raise XyceError(f"cannot inspect Xyce executable {raw!r}: {error}") from error
    if not path.is_file() or stat.st_size <= 0 or stat.st_size > _MAX_EXECUTABLE_BYTES:
        raise XyceError("Xyce executable is not a bounded regular file")
    return path


def _validate_extra_environment(value: dict[str, str] | None) -> dict[str, str]:
    extra = {} if value is None else value
    if len(extra) > _MAX_ENVIRONMENT_ENTRIES:
        raise XyceError("too many explicit environment entries")
    result: dict[str, str] = {}
    names: set[str] = set()
    for name, item in sorted(extra.items()):
        if not isinstance(name, str) or _ENVIRONMENT.fullmatch(name) is None:
            raise XyceError(f"invalid environment name {name!r}")
        folded = name.casefold()
        if folded in names:
            raise XyceError("explicit environment has case-colliding names")
        if folded in {item.casefold() for item in _FIXED_ENVIRONMENT}:
            raise XyceError(f"environment variable {name!r} is fixed by SimCairn")
        if (
            not isinstance(item, str)
            or len(item) > _MAX_ENVIRONMENT_VALUE
            or "\x00" in item
            or any(
                (ord(character) < 32 and character not in "\t") or ord(character) == 127
                for character in item
            )
        ):
            raise XyceError(f"invalid environment value for {name!r}")
        names.add(folded)
        result[name] = item
    return result


def _environment(sandbox: Path, extra: dict[str, str] | None) -> dict[str, str]:
    result = {name: os.environ[name] for name in _INHERITED_ENVIRONMENT if name in os.environ}
    result.update(_validate_extra_environment(extra))
    temporary = sandbox / "tmp"
    temporary.mkdir(exist_ok=False)
    result.update(
        {
            "HOME": str(sandbox),
            "TEMP": str(temporary),
            "TMP": str(temporary),
            "LANG": "C",
            "LC_ALL": "C",
            "TZ": "UTC",
            "PYTHONIOENCODING": "utf-8",
        }
    )
    return result


def _environment_identity(environment: dict[str, str]) -> dict[str, Any]:
    # Values can contain license paths or other deployment details. Their digests
    # bind execution without copying them into a portable report.
    volatile = {"HOME": "sandbox", "TEMP": "sandbox/tmp", "TMP": "sandbox/tmp"}
    return {
        "algorithm": "simcairn-environment-name-and-value-sha256/1",
        "platform": {
            "machine": platform.machine(),
            "os_name": os.name,
            "python_implementation": platform.python_implementation(),
            "python_version": platform.python_version(),
            "release": platform.release(),
            "system": platform.system(),
        },
        "variables": {
            name: _hash_bytes(volatile.get(name, value).encode("utf-8"))
            for name, value in sorted(environment.items())
        },
    }


async def _read_bounded(
    reader: asyncio.StreamReader, maximum: int, label: str, process_name: str
) -> bytes:
    result = bytearray()
    while True:
        chunk = await reader.read(min(65_536, maximum + 1 - len(result)))
        if not chunk:
            return bytes(result)
        result.extend(chunk)
        if len(result) > maximum:
            raise XyceExecutionError(f"{process_name} {label} exceeded {maximum} bytes")


async def _terminate(  # pragma: no cover - behavior exercised on each native CI OS
    process: asyncio.subprocess.Process, windows_job: int | None
) -> None:
    if windows_job is not None:
        _windows_job_action(windows_job, terminate=True)
    elif os.name != "nt":  # pragma: no cover - exercised by POSIX CI
        with contextlib.suppress(ProcessLookupError, PermissionError):
            kill_process_group = cast(Callable[[int, int], None], os.__dict__["killpg"])
            kill_process_group(process.pid, signal.SIGTERM)
    elif process.returncode is None:
        with contextlib.suppress(ProcessLookupError):
            process.terminate()
    if process.returncode is not None and (windows_job is not None or os.name == "nt"):
        return
    if process.returncode is None:
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(asyncio.shield(process.wait()), timeout=_TERMINATE_GRACE_SECONDS)
    if process.returncode is None or os.name != "nt":
        if windows_job is not None:
            _windows_job_action(windows_job, terminate=True)
        elif os.name != "nt":  # pragma: no cover - exercised by POSIX CI
            with contextlib.suppress(ProcessLookupError, PermissionError):
                kill_process_group = cast(Callable[[int, int], None], os.__dict__["killpg"])
                kill_process_group(process.pid, int(signal.__dict__.get("SIGKILL", 9)))
        elif process.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                process.kill()
        if process.returncode is None:
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(
                    asyncio.shield(process.wait()), timeout=_TERMINATE_GRACE_SECONDS
                )


async def _watch_artifacts(
    wait_task: asyncio.Task[int],
    watched: tuple[tuple[Path, int, str], ...],
    process_name: str,
) -> None:
    while True:
        for path, maximum, label in watched:
            try:
                if path.is_symlink():
                    raise XyceExecutionError(f"{process_name} {label} was redirected")
                if path.is_file() and path.stat().st_size > maximum:
                    raise XyceExecutionError(f"{process_name} {label} exceeded {maximum} bytes")
            except OSError as error:
                raise XyceExecutionError(
                    f"cannot inspect {process_name} {label}: {error}"
                ) from error
        if wait_task.done():
            return
        await asyncio.sleep(0.02)


async def _cancel_tasks(*tasks: asyncio.Task[Any]) -> None:
    for task in tasks:
        if not task.done():
            task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


def _completed_bytes(task: asyncio.Task[bytes]) -> bytes:
    if not task.done() or task.cancelled():
        return b""
    try:
        return task.result()
    except BaseException:
        return b""


async def _run_process(
    argv: tuple[str, ...],
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout_seconds: float,
    maximum_log_bytes: int,
    watched: tuple[tuple[Path, int, str], ...] = (),
    process_name: str = "Xyce",
) -> _ProcessResult:
    started = time.monotonic()
    try:
        platform_options: dict[str, Any] = (
            {"creationflags": _WINDOWS_CREATE_NEW_PROCESS_GROUP}
            if os.name == "nt"
            else {"start_new_session": True}
        )
        process = await asyncio.create_subprocess_exec(
            *argv,
            cwd=cwd,
            env=environment,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            **platform_options,
        )
    except OSError as error:
        raise XyceExecutionError(f"cannot launch {process_name}: {error}") from error
    try:
        windows_job = _attach_windows_job(process.pid)
    except BaseException:
        with contextlib.suppress(ProcessLookupError):
            process.kill()
        await process.wait()
        raise
    # PIPE above establishes these asyncio transport invariants.
    assert process.stdout is not None  # nosec B101
    assert process.stderr is not None  # nosec B101
    stdout_task = asyncio.create_task(
        _read_bounded(process.stdout, maximum_log_bytes, "stdout", process_name)
    )
    stderr_task = asyncio.create_task(
        _read_bounded(process.stderr, maximum_log_bytes, "stderr", process_name)
    )
    wait_task = asyncio.create_task(process.wait())
    watch_task = asyncio.create_task(_watch_artifacts(wait_task, watched, process_name))
    try:
        async with asyncio.timeout(timeout_seconds):
            returncode, stdout, stderr, _ = await asyncio.gather(
                wait_task, stdout_task, stderr_task, watch_task
            )
    except asyncio.CancelledError:
        await _terminate(process, windows_job)
        await _cancel_tasks(stdout_task, stderr_task, wait_task, watch_task)
        raise
    except TimeoutError as error:
        await _terminate(process, windows_job)
        stdout = _completed_bytes(stdout_task)
        stderr = _completed_bytes(stderr_task)
        await _cancel_tasks(stdout_task, stderr_task, wait_task, watch_task)
        raise XyceExecutionError(
            f"{process_name} timed out after {timeout_seconds:g} seconds",
            returncode=process.returncode,
            stdout=stdout,
            stderr=stderr,
        ) from error
    except XyceExecutionError:
        await _terminate(process, windows_job)
        await _cancel_tasks(stdout_task, stderr_task, wait_task, watch_task)
        raise
    except BaseException:
        await _terminate(process, windows_job)
        await _cancel_tasks(stdout_task, stderr_task, wait_task, watch_task)
        raise
    finally:
        if windows_job is not None:
            # Do not rely solely on JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: an
            # explicit termination makes descendant cleanup synchronous with
            # evidence validation and is harmless once the job is empty.
            _windows_job_action(windows_job, terminate=True)
        elif os.name != "nt":  # pragma: no cover - exercised by POSIX CI
            # The main process may exit after leaving descendants in its new
            # session. Escalate cleanup even after the leader has been reaped.
            await _terminate(process, windows_job)
        _windows_job_action(windows_job, terminate=False)
    return _ProcessResult(argv, returncode, stdout, stderr, time.monotonic() - started)


async def probe_xyce(
    command: XyceCommand,
    *,
    environment: dict[str, str] | None = None,
) -> XyceToolIdentity:
    """Run the official ``-v`` probe and bind it to the executable bytes."""

    identity, _ = await _probe_xyce_prepared(command, environment=environment)
    return identity


async def _probe_xyce_prepared(
    command: XyceCommand,
    *,
    environment: dict[str, str] | None,
) -> tuple[XyceToolIdentity, tuple[str, ...]]:
    """Return the probed identity and the exact canonical argv prefix."""

    sandbox = Path(tempfile.mkdtemp(prefix="simcairn-xyce-probe-"))
    try:
        child_environment = _environment(sandbox, environment)
        prepared = _prepare_command(command, child_environment)
        executable = Path(prepared[0])
        executable_size, executable_sha256 = _bounded_file_identity(executable)
        command_sha256 = _command_digest(prepared)
        argv = (*prepared, "-v")
        result = await _run_process(
            argv,
            cwd=sandbox,
            environment=child_environment,
            timeout_seconds=_PROBE_TIMEOUT_SECONDS,
            maximum_log_bytes=256 * 1024,
        )
        combined = b"\n".join((result.stdout, result.stderr)).decode("utf-8", errors="replace")
        match = _VERSION.search(combined)
        if result.returncode != 0 or match is None:
            raise XyceError("configured executable did not return a valid Xyce version banner")
        controlled_marker = "SIMCAIRN CONTROLLED TEST DOUBLE" in combined
        if controlled_marker != (command.evidence_class == "controlled-test-double"):
            raise XyceError("Xyce version banner conflicts with the declared evidence class")
        if _command_digest(prepared) != command_sha256:
            raise XyceError("Xyce command changed during its version probe")
        return (
            XyceToolIdentity(
                match.group(1),
                executable.name,
                executable_sha256,
                executable_size,
                command_sha256,
                command.evidence_class,
            ),
            prepared,
        )
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)


def _safe_cache_root(path: str | Path) -> Path:
    root = Path(path).absolute()
    try:
        if (
            root.parent.is_symlink()
            or not root.parent.is_dir()
            or root.parent.resolve(strict=True) != root.parent
        ):
            raise XyceError("characterization cache parent is redirected or missing")
        root.mkdir(exist_ok=True)
    except OSError as error:
        raise XyceError(f"cannot create characterization cache {root}: {error}") from error
    if root.is_symlink() or not root.is_dir() or root.resolve() != root:
        raise XyceError("characterization cache root is redirected or invalid")
    return root


def _path_exists_no_follow(path: Path) -> bool:
    """Return whether a directory entry exists, including a dangling link."""

    return os.path.lexists(path)


def _direct_cache_directory(parent: Path, name: str, label: str) -> Path:
    """Create or reuse one canonical direct child without following redirects."""

    path = parent / name
    try:
        path.mkdir(exist_ok=True)
        canonical = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise XyceError(f"cannot create {label}: {error}") from error
    if path.is_symlink() or not path.is_dir() or canonical != path:
        raise XyceError(f"{label} is redirected or invalid")
    return path


@dataclass(slots=True)
class _CacheClaim:
    """A nonce-owned claim that serializes one cache key without deleting peers."""

    directory: Path
    lock: RunLock

    def release(self) -> None:
        self.lock.__exit__(None, None, None)


def _acquire_cache_claim(cache_root: Path, cache_key: str, target: Path) -> _CacheClaim | None:
    """Claim a cache key, or return ``None`` if a complete target won the race.

    Empty per-key claim directories intentionally remain reusable. Removing them
    would introduce an ABA window in which a releaser could delete a directory
    created by another local process.
    """

    claims = _direct_cache_directory(cache_root, ".claims", "cache claim root")
    directory = _direct_cache_directory(claims, cache_key, "cache claim directory")
    if _path_exists_no_follow(target):
        return None
    lock = RunLock(directory)
    try:
        lock.__enter__()
    except JournalError as error:
        if _path_exists_no_follow(target):
            return None
        raise XyceError("characterization cache key is claimed by another live process") from error
    if _path_exists_no_follow(target):
        lock.__exit__(None, None, None)
        return None
    return _CacheClaim(directory, lock)


def _rename_no_replace_linux(source: Path, destination: Path) -> None:
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise XyceError("this Linux runtime has no atomic no-replace rename support")
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = renameat2(
        -100,
        os.fsencode(source),
        -100,
        os.fsencode(destination),
        _LINUX_RENAME_NOREPLACE,
    )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise FileExistsError(error_number, os.strerror(error_number), destination)
    if error_number in {errno.EINVAL, errno.ENOSYS, errno.ENOTSUP, errno.EOPNOTSUPP}:
        raise XyceError("the cache filesystem has no atomic no-replace rename support")
    raise OSError(error_number, os.strerror(error_number), destination)


def _rename_no_replace_darwin(source: Path, destination: Path) -> None:
    import ctypes

    libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    renamex = getattr(libc, "renamex_np", None)
    if renamex is None:
        raise XyceError("this macOS runtime has no atomic no-replace rename support")
    renamex.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
    renamex.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = renamex(os.fsencode(source), os.fsencode(destination), _DARWIN_RENAME_EXCL)
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise FileExistsError(error_number, os.strerror(error_number), destination)
    if error_number in {errno.EINVAL, errno.ENOSYS, errno.ENOTSUP, errno.EOPNOTSUPP}:
        raise XyceError("the cache filesystem has no atomic no-replace rename support")
    raise OSError(error_number, os.strerror(error_number), destination)


def _atomic_publish_no_replace(source: Path, destination: Path) -> None:
    """Atomically publish a directory and fail if any destination entry exists."""

    if source.parent != destination.parent:
        raise XyceError("cache publication source and destination must share a parent")
    try:
        parent = source.parent.resolve(strict=True)
        canonical_source = source.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise XyceError(f"cache publication source is unreadable: {error}") from error
    if (
        source.parent != parent
        or source.is_symlink()
        or not source.is_dir()
        or canonical_source != source
        or destination.parent != parent
    ):
        raise XyceError("cache publication paths are redirected or invalid")

    system = platform.system()
    if system == "Linux":
        _rename_no_replace_linux(source, destination)
        return
    if system == "Darwin":
        _rename_no_replace_darwin(source, destination)
        return
    if system == "Windows":
        try:
            os.rename(source, destination)
        except OSError as error:
            if _path_exists_no_follow(destination):
                raise FileExistsError(
                    error.errno, "cache destination already exists", destination
                ) from error
            raise
        return
    raise XyceError(f"atomic no-replace cache publication is unsupported on {system}")


def _manifest_records(root: Path, relative_paths: list[str]) -> list[dict[str, str | int]]:
    records: list[dict[str, str | int]] = []
    for relative in sorted(relative_paths):
        path = root / relative
        _require_confined_regular_file(path, root, f"evidence artifact {relative}")
        records.append({"name": relative, "size": path.stat().st_size, "sha256": sha256_file(path)})
    return records


def _require_confined_regular_file(path: Path, root: Path, label: str) -> Path:
    try:
        canonical_root = root.resolve(strict=True)
        canonical = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise XyceError(f"{label} is unreadable: {error}") from error
    parent = path.parent
    while parent != root:
        if parent == parent.parent or not parent.is_relative_to(root) or parent.is_symlink():
            raise XyceError(f"{label} is redirected or outside its execution directory")
        parent = parent.parent
    if (
        root.is_symlink()
        or canonical_root != root
        or path.is_symlink()
        or not path.is_file()
        or canonical != path
        or not canonical.is_relative_to(canonical_root)
    ):
        raise XyceError(f"{label} is redirected or is not a regular file")
    return canonical


def _verify_cache(path: Path, cache_key: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_dir() or path.resolve() != path:
        raise XyceError("cached characterization directory is redirected or invalid")
    try:
        manifest_bytes = _read_artifact(
            path / "manifest.json",
            path,
            _MAX_CACHE_MANIFEST_BYTES,
            "cache manifest",
        )
        report_bytes = _read_artifact(
            path / "report.json", path, _MAX_CACHE_REPORT_BYTES, "cache report"
        )
        manifest = strict_json_loads(manifest_bytes)
        report = strict_json_loads(report_bytes)
    except (OSError, ValueError, XyceError) as error:
        raise XyceError(f"cached characterization evidence is unreadable: {error}") from error
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema_version",
        "cache_key",
        "artifacts",
    }:
        raise XyceError("cached characterization manifest fields are invalid")
    try:
        if stable_json(manifest).encode("utf-8") != manifest_bytes:
            raise XyceError("cached characterization manifest is not canonical")
        if stable_json(report).encode("utf-8") != report_bytes:
            raise XyceError("cached characterization report is not canonical")
    except (TypeError, ValueError) as error:
        raise XyceError("cached characterization metadata is not canonical") from error
    if manifest["schema_version"] != 1 or manifest["cache_key"] != cache_key:
        raise XyceError("cached characterization manifest identity is invalid")
    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        raise XyceError("cached characterization artifact list is invalid")
    if not isinstance(report, dict):
        raise XyceError("cached characterization report is invalid")
    identity = report.get("identity")
    if not isinstance(identity, dict):
        raise XyceError("cached characterization report identity is invalid")
    try:
        raw_plan = identity["plan"]
        raw_limits = raw_plan["limits"]
        if not isinstance(raw_plan, dict) or not isinstance(raw_limits, dict):
            raise TypeError
        limits = CharacterizationLimits(**raw_limits)
        artifact_limits = {
            "deck.cir": limits.max_deck_bytes,
            "results.csv": limits.max_output_bytes,
            "xyce.log": limits.max_log_bytes,
            "stdout.log": limits.max_log_bytes,
            "stderr.log": limits.max_log_bytes,
            "normalized.json": _MAX_CACHE_REPORT_BYTES,
            "report.json": _MAX_CACHE_REPORT_BYTES,
        }
    except (KeyError, TypeError, ValueError) as error:
        raise XyceError("cached characterization plan limits are invalid") from error
    if any(value <= 0 for value in artifact_limits.values()):
        raise XyceError("cached characterization plan limits are invalid")

    names: set[str] = set()
    for item in artifacts:
        if not isinstance(item, dict) or set(item) != {"name", "size", "sha256"}:
            raise XyceError("cached characterization artifact record is invalid")
        name, size, digest = item["name"], item["size"], item["sha256"]
        if (
            not isinstance(name, str)
            or not name
            or name in {".", ".."}
            or "\\" in name
            or Path(name).is_absolute()
            or ".." in Path(name).parts
            or name.casefold() in names
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
            or size > _MAX_CACHE_REPORT_BYTES
            or not isinstance(digest, str)
            or _DIGEST.fullmatch(digest) is None
        ):
            raise XyceError("cached characterization artifact record is invalid")
        names.add(name.casefold())
        artifact = path / name
        try:
            resolved = artifact.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise XyceError(f"cached characterization artifact is unreadable: {name}") from error
        parent = artifact.parent
        redirected_parent = False
        while parent != path:
            if parent.is_symlink():
                redirected_parent = True
                break
            parent = parent.parent
        if (
            redirected_parent
            or artifact.is_symlink()
            or not artifact.is_file()
            or not resolved.is_relative_to(path)
            or artifact.stat().st_size != size
            or size > artifact_limits.get(Path(name).name, -1)
            or sha256_file(artifact) != digest
        ):
            raise XyceError(f"cached characterization artifact changed: {name}")
    if "report.json" not in names:
        raise XyceError("cached characterization report is invalid")
    if set(report) != {
        "schema_version",
        "cache_key",
        "identity",
        "execution_count",
        "duration_seconds",
        "executions",
    }:
        raise XyceError("cached characterization report fields are invalid")
    if (
        report.get("schema_version") != 1
        or report.get("cache_key") != cache_key
        or not isinstance(identity, dict)
        or fingerprint(identity) != cache_key
    ):
        raise XyceError("cached characterization report identity is invalid")
    count = report.get("execution_count")
    executions = report.get("executions")
    duration = report.get("duration_seconds")
    if (
        isinstance(count, bool)
        or not isinstance(count, int)
        or count <= 0
        or not isinstance(executions, list)
        or len(executions) != count
        or isinstance(duration, bool)
        or not isinstance(duration, int | float)
        or not math.isfinite(duration)
        or duration < 0
    ):
        raise XyceError("cached characterization report execution summary is invalid")
    expected = {"report.json"}
    prefixes: set[str] = set()
    try:
        raw_corners = raw_plan["corners"]
        raw_analyses = raw_plan["analyses"]
        command_sha256 = identity["tool"]["command_sha256"]
        if (
            not isinstance(raw_corners, list)
            or not isinstance(raw_analyses, list)
            or not isinstance(command_sha256, str)
            or _DIGEST.fullmatch(command_sha256) is None
        ):
            raise TypeError
        expected_executions = [
            (corner, analysis, analysis_from_dict(analysis))
            for corner in raw_corners
            for analysis in raw_analyses
        ]
    except (KeyError, TypeError, CharacterizationError) as error:
        raise XyceError("cached characterization plan shape is invalid") from error
    if len(expected_executions) != count:
        raise XyceError("cached characterization execution count does not match its plan")

    execution_fields = {
        "evidence_prefix",
        "corner",
        "analysis",
        "argv",
        "returncode",
        "duration_seconds",
        "deck_sha256",
        "stdout_sha256",
        "stderr_sha256",
        "log_sha256",
        "raw_result_sha256",
        "normalized_result_sha256",
        "normalized",
    }
    for execution, (raw_corner, raw_analysis, analysis) in zip(
        executions, expected_executions, strict=True
    ):
        if not isinstance(execution, dict) or set(execution) != execution_fields:
            raise XyceError("cached characterization execution is invalid")
        try:
            parameters = raw_corner["parameters"]
            if not isinstance(parameters, dict):
                raise TypeError
            corner = PVTCorner(
                raw_corner["process"],
                raw_corner["voltage"],
                raw_corner["temperature_c"],
                tuple(parameters.items()),
            )
            analysis_name = raw_analysis["name"]
        except (KeyError, TypeError, CharacterizationError) as error:
            raise XyceError("cached characterization plan execution is invalid") from error
        expected_prefix = f"runs/{corner.label}/{analysis_name}"
        prefix = execution.get("evidence_prefix")
        if (
            not isinstance(prefix, str)
            or _EVIDENCE_PREFIX.fullmatch(prefix) is None
            or prefix.casefold() in prefixes
            or prefix != expected_prefix
            or execution.get("corner") != raw_corner
            or execution.get("analysis") != raw_analysis
            or execution.get("argv")
            != [
                f"<identified-Xyce-command:{command_sha256}>",
                "-randseed",
                "1",
                "-l",
                "xyce.log",
                "deck.cir",
            ]
            or execution.get("returncode") != 0
        ):
            raise XyceError("cached characterization evidence prefix is invalid")
        execution_duration = execution.get("duration_seconds")
        if (
            isinstance(execution_duration, bool)
            or not isinstance(execution_duration, int | float)
            or not math.isfinite(execution_duration)
            or execution_duration < 0
        ):
            raise XyceError("cached characterization execution duration is invalid")
        prefixes.add(prefix.casefold())
        for filename, hash_field in (
            ("deck.cir", "deck_sha256"),
            ("results.csv", "raw_result_sha256"),
            ("xyce.log", "log_sha256"),
            ("stdout.log", "stdout_sha256"),
            ("stderr.log", "stderr_sha256"),
            ("normalized.json", "normalized_result_sha256"),
        ):
            relative = f"{prefix}/{filename}"
            expected.add(relative)
            digest = execution.get(hash_field)
            if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
                raise XyceError("cached characterization execution digest is invalid")
            if sha256_file(path / relative) != digest:
                raise XyceError(f"cached characterization report digest changed: {relative}")
        try:
            normalized_bytes = stable_json(execution["normalized"]).encode("utf-8")
        except (TypeError, ValueError) as error:
            raise XyceError("cached normalized result is invalid") from error
        cached_normalized = _read_artifact(
            path / prefix / "normalized.json",
            path,
            _MAX_CACHE_REPORT_BYTES,
            "cached normalized result",
        )
        if normalized_bytes != cached_normalized:
            raise XyceError("cached normalized result does not match its evidence artifact")
        raw_result = _read_artifact(
            path / prefix / "results.csv",
            path,
            limits.max_output_bytes,
            "cached raw result",
        )
        try:
            reproduced_normalized = stable_json(
                normalize_result_table(
                    raw_result,
                    analysis,
                    simulator="xyce",
                    limits=limits,
                ).as_dict()
            ).encode("utf-8")
        except CharacterizationError as error:
            raise XyceError(f"cached raw result cannot be normalized: {error}") from error
        if reproduced_normalized != cached_normalized:
            raise XyceError("cached raw result does not reproduce its normalized evidence")
    if names != {name.casefold() for name in expected}:
        raise XyceError("cached characterization artifacts do not match the report")
    expected_files = names | {"manifest.json"}
    expected_directories: set[str] = set()
    for name in expected_files:
        parent = Path(name).parent
        while parent != Path("."):
            expected_directories.add(parent.as_posix().casefold())
            parent = parent.parent
    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    try:
        for candidate in path.rglob("*"):
            relative = candidate.relative_to(path).as_posix().casefold()
            if candidate.is_symlink() or candidate.resolve(strict=True) != candidate:
                raise XyceError("cached characterization tree contains a redirected entry")
            if candidate.is_file():
                actual_files.add(relative)
            elif candidate.is_dir():
                actual_directories.add(relative)
            else:
                raise XyceError("cached characterization tree contains a special entry")
    except (OSError, RuntimeError) as error:
        raise XyceError(f"cached characterization tree is unreadable: {error}") from error
    if actual_files != expected_files or actual_directories != expected_directories:
        raise XyceError("cached characterization tree contains unexpected entries")
    return report


def _write_no_clobber(path: Path, payload: bytes) -> None:
    target = path.absolute()
    try:
        if (
            target.parent.is_symlink()
            or not target.parent.is_dir()
            or target.parent.resolve(strict=True) != target.parent
        ):
            raise XyceError(f"output parent is redirected or missing: {target.parent}")
        with target.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as error:
        raise XyceError(f"refusing to overwrite existing output {target}") from error
    except OSError as error:
        raise XyceError(f"cannot write output {target}: {error}") from error


def _execution_directory(root: Path, corner: PVTCorner, analysis: Analysis) -> Path:
    directory = root / "runs" / corner.label / analysis.name
    directory.mkdir(parents=True, exist_ok=False)
    return directory


def _write_new_artifact(path: Path, payload: bytes, root: Path) -> None:
    try:
        canonical_root = root.resolve(strict=True)
        canonical_parent = path.parent.resolve(strict=True)
        if (
            root.is_symlink()
            or canonical_root != root
            or path.parent.is_symlink()
            or canonical_parent != path.parent
            or not canonical_parent.is_relative_to(canonical_root)
        ):
            raise XyceExecutionError("execution artifact destination is redirected")
        with path.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as error:
        raise XyceExecutionError(f"refusing to overwrite execution artifact {path.name}") from error
    except OSError as error:
        raise XyceExecutionError(f"cannot write execution artifact {path.name}: {error}") from error


def _read_artifact(path: Path, root: Path, maximum: int, label: str) -> bytes:
    try:
        _require_confined_regular_file(path, root, f"Xyce {label}")
        before = path.stat()
        with path.open("rb") as stream:
            payload = stream.read(maximum + 1)
            descriptor = os.fstat(stream.fileno())
        after = path.stat()
    except (OSError, XyceError) as error:
        raise XyceExecutionError(f"cannot read Xyce {label}: {error}") from error
    if len(payload) > maximum:
        raise XyceExecutionError(f"Xyce {label} exceeded {maximum} bytes")
    before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    descriptor_identity = (
        descriptor.st_dev,
        descriptor.st_ino,
        descriptor.st_size,
        descriptor.st_mtime_ns,
    )
    if (
        before_identity != after_identity
        or after_identity != descriptor_identity
        or len(payload) != after.st_size
    ):
        raise XyceExecutionError(f"Xyce {label} changed while being read")
    return payload


def _reject_unexpected_artifacts(directory: Path) -> None:
    allowed = {"deck.cir", "results.csv", "xyce.log", "stdout.log", "stderr.log", "normalized.json"}
    for path in directory.iterdir():
        if path.name not in allowed or path.is_symlink() or not path.is_file():
            raise XyceExecutionError(f"Xyce created unexpected artifact {path.name!r}")
        _require_confined_regular_file(path, directory, f"Xyce artifact {path.name}")


def _materialize_inputs(
    plan: CharacterizationPlan,
    directory: Path,
    expected: list[dict[str, Any]],
) -> tuple[Path, ...]:
    if len(expected) != len(plan.inputs):
        raise XyceExecutionError("characterization input identity is inconsistent")
    materialized: list[Path] = []
    for source, record in zip(plan.inputs, expected, strict=True):
        if record != source.as_identity_dict():
            raise XyceExecutionError(
                f"characterization input changed after planning: {source.logical_name}"
            )
        destination = directory / source.logical_name
        destination.parent.mkdir(parents=True, exist_ok=True)
        if (
            destination.parent.is_symlink()
            or destination.parent.resolve() != destination.parent
            or not destination.parent.is_relative_to(directory)
        ):
            raise XyceExecutionError("characterization input destination is redirected")
        _write_new_artifact(destination, source.snapshot, directory)
        if sha256_file(destination) != record["sha256"]:
            raise XyceExecutionError(
                f"characterization input snapshot changed while copied: {source.logical_name}"
            )
        materialized.append(destination)
    return tuple(materialized)


def _remove_materialized_inputs(
    directory: Path,
    paths: tuple[Path, ...],
    expected: list[dict[str, Any]],
) -> None:
    for path, record in zip(paths, expected, strict=True):
        try:
            _require_confined_regular_file(
                path,
                directory,
                f"declared characterization input {path.relative_to(directory).as_posix()}",
            )
        except XyceError as error:
            raise XyceExecutionError(str(error)) from error
        if sha256_file(path) != record["sha256"]:
            raise XyceExecutionError(
                "Xyce changed declared characterization input "
                f"{path.relative_to(directory).as_posix()}"
            )
        path.unlink()
    parent_set: set[Path] = set()
    for path in paths:
        parent = path.parent
        while parent != directory:
            if not parent.is_relative_to(directory):
                raise XyceExecutionError("materialized input escaped its execution directory")
            parent_set.add(parent)
            parent = parent.parent
    parents = sorted(parent_set, key=lambda path: len(path.parts), reverse=True)
    for parent in parents:
        try:
            parent.rmdir()
        except OSError as error:
            raise XyceExecutionError(
                "Xyce left an unexpected artifact beside a declared input"
            ) from error


async def _execute_one(
    command: tuple[str, ...],
    plan: CharacterizationPlan,
    corner: PVTCorner,
    analysis: Analysis,
    directory: Path,
    environment: dict[str, str],
    timeout_seconds: float,
    expected_deck_sha256: str,
    expected_inputs: list[dict[str, Any]],
    expected_command_sha256: str,
) -> dict[str, Any]:
    if _command_digest(command) != expected_command_sha256:
        raise XyceExecutionError("Xyce command changed after its version probe")
    if plan.deck_sha256 != expected_deck_sha256:
        raise XyceExecutionError("characterization deck identity changed after planning")
    plan.verify_sources_unchanged()
    deck = render_xyce_deck(plan, corner, analysis)
    plan.verify_sources_unchanged()
    materialized = _materialize_inputs(plan, directory, expected_inputs)
    _write_new_artifact(directory / "deck.cir", deck, directory)
    argv = (*command, "-randseed", "1", "-l", "xyce.log", "deck.cir")
    result = await _run_process(
        argv,
        cwd=directory,
        environment=environment,
        timeout_seconds=timeout_seconds,
        maximum_log_bytes=plan.limits.max_log_bytes,
        watched=(
            (directory / "results.csv", plan.limits.max_output_bytes, "result table"),
            (directory / "xyce.log", plan.limits.max_log_bytes, "log"),
        ),
    )
    if _command_digest(command) != expected_command_sha256:
        raise XyceExecutionError("Xyce command changed during execution")
    temporary = directory / "tmp"
    if temporary.is_symlink() or not temporary.is_dir() or temporary.resolve() != temporary:
        raise XyceExecutionError("Xyce temporary directory was redirected or removed")
    shutil.rmtree(temporary)
    _write_new_artifact(directory / "stdout.log", result.stdout, directory)
    _write_new_artifact(directory / "stderr.log", result.stderr, directory)
    xyce_log = (
        _read_artifact(directory / "xyce.log", directory, plan.limits.max_log_bytes, "log")
        if (directory / "xyce.log").exists()
        else b""
    )
    if result.returncode != 0:
        diagnostic = b"\n".join((result.stderr, xyce_log, result.stdout))
        tail = diagnostic.decode("utf-8", errors="replace")[-500:].strip()
        raise XyceExecutionError(
            f"Xyce exited with status {result.returncode}: {tail}",
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
            log=xyce_log,
        )
    if not xyce_log:
        raise XyceExecutionError("Xyce did not create regular log")
    persisted_deck = _read_artifact(
        directory / "deck.cir", directory, plan.limits.max_deck_bytes, "deck"
    )
    if persisted_deck != deck:
        raise XyceExecutionError("Xyce changed the rendered characterization deck")
    table = _read_artifact(
        directory / "results.csv",
        directory,
        plan.limits.max_output_bytes,
        "result table",
    )
    normalized = normalize_result_table(table, analysis, simulator="xyce", limits=plan.limits)
    normalized_bytes = stable_json(normalized.as_dict()).encode("utf-8")
    _write_new_artifact(directory / "normalized.json", normalized_bytes, directory)
    _remove_materialized_inputs(directory, materialized, expected_inputs)
    _reject_unexpected_artifacts(directory)
    return {
        "evidence_prefix": directory.relative_to(directory.parents[2]).as_posix(),
        "corner": corner.as_dict(),
        "analysis": analysis_as_dict(analysis),
        "argv": [
            f"<identified-Xyce-command:{expected_command_sha256}>",
            "-randseed",
            "1",
            "-l",
            "xyce.log",
            "deck.cir",
        ],
        "returncode": result.returncode,
        "duration_seconds": result.duration_seconds,
        "deck_sha256": _hash_bytes(deck),
        "stdout_sha256": _hash_bytes(result.stdout),
        "stderr_sha256": _hash_bytes(result.stderr),
        "log_sha256": _hash_bytes(xyce_log),
        "raw_result_sha256": _hash_bytes(table),
        "normalized_result_sha256": _hash_bytes(normalized_bytes),
        "normalized": normalized.as_dict(),
    }


async def characterize_xyce_async(
    plan: CharacterizationPlan,
    *,
    command: XyceCommand | None = None,
    cache: str | Path = ".simcairn-characterization",
    output: str | Path | None = None,
    timeout_seconds: float = 300.0,
    environment: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Run every PVT/analysis pair and atomically cache a provenance report.

    Cancelling the coroutine terminates and reaps the active child before the
    cancellation is propagated. A requested output is created with ``O_EXCL``.
    """

    try:
        timeout = float(timeout_seconds)
    except (OverflowError, TypeError, ValueError) as error:
        raise XyceError("timeout_seconds must be finite and in (0, 31536000]") from error
    if (
        isinstance(timeout_seconds, bool)
        or not math.isfinite(timeout)
        or not 0 < timeout <= 31_536_000
    ):
        raise XyceError("timeout_seconds must be finite and in (0, 31536000]")
    selected = XyceCommand.real() if command is None else command
    try:
        plan.verify_sources_unchanged()
        plan_identity = plan.as_identity_dict()
    except (OSError, CharacterizationError) as error:
        raise XyceError(f"cannot identify characterization inputs: {error}") from error
    cache_root = _safe_cache_root(cache)
    probe_sandbox = Path(tempfile.mkdtemp(prefix=".environment-", dir=cache_root))
    try:
        child_environment = _environment(probe_sandbox, environment)
        tool, prepared_command = await _probe_xyce_prepared(selected, environment=environment)
        environment_identity = _environment_identity(child_environment)
    finally:
        shutil.rmtree(probe_sandbox, ignore_errors=True)
    producer = current_producer_identity().as_dict()
    identity = {
        "contract": "simcairn.xyce-characterization/1",
        "producer_identity": producer,
        "plan": plan_identity,
        "tool": tool.as_dict(),
        "environment": environment_identity,
        "timeout_seconds": timeout,
    }
    cache_key = fingerprint(identity)
    target = cache_root / cache_key
    if _path_exists_no_follow(target):
        report = _verify_cache(target, cache_key)
        if output is not None:
            _write_no_clobber(Path(output), stable_json(report).encode("utf-8"))
        return report

    claim = _acquire_cache_claim(cache_root, cache_key, target)
    if claim is None:
        report = _verify_cache(target, cache_key)
        if output is not None:
            _write_no_clobber(Path(output), stable_json(report).encode("utf-8"))
        return report

    try:
        temporary = Path(tempfile.mkdtemp(prefix=".xyce-publish-", dir=cache_root))
    except BaseException:
        claim.release()
        raise
    records: list[str] = []
    started = time.monotonic()
    try:
        executions: list[dict[str, Any]] = []
        for corner in plan.corners:
            for analysis in plan.analyses:
                directory = _execution_directory(temporary, corner, analysis)
                execution_environment = _environment(directory, environment)
                if _environment_identity(execution_environment) != environment_identity:
                    raise XyceError("execution environment changed after identification")
                executions.append(
                    await _execute_one(
                        prepared_command,
                        plan,
                        corner,
                        analysis,
                        directory,
                        execution_environment,
                        timeout,
                        str(plan_identity["deck_sha256"]),
                        list(plan_identity["inputs"]),
                        tool.command_sha256,
                    )
                )
                for name in (
                    "deck.cir",
                    "results.csv",
                    "xyce.log",
                    "stdout.log",
                    "stderr.log",
                    "normalized.json",
                ):
                    records.append((directory / name).relative_to(temporary).as_posix())
        plan.verify_sources_unchanged()
        if plan.as_identity_dict() != plan_identity:
            raise XyceError("characterization inputs changed during execution")
        generated_report: dict[str, Any] = {
            "schema_version": 1,
            "cache_key": cache_key,
            "identity": identity,
            "execution_count": len(executions),
            "duration_seconds": time.monotonic() - started,
            "executions": executions,
        }
        report_payload = stable_json(generated_report).encode("utf-8")
        if len(report_payload) > _MAX_CACHE_REPORT_BYTES:
            raise XyceError("characterization report exceeds the cache metadata limit")
        _write_new_artifact(temporary / "report.json", report_payload, temporary)
        records.append("report.json")
        manifest = {
            "schema_version": 1,
            "cache_key": cache_key,
            "artifacts": _manifest_records(temporary, records),
        }
        manifest_payload = stable_json(manifest).encode("utf-8")
        if len(manifest_payload) > _MAX_CACHE_MANIFEST_BYTES:
            raise XyceError("characterization manifest exceeds the cache metadata limit")
        _write_new_artifact(temporary / "manifest.json", manifest_payload, temporary)
        try:
            _atomic_publish_no_replace(temporary, target)
        except FileExistsError:
            generated_report = _verify_cache(target, cache_key)
        else:
            generated_report = _verify_cache(target, cache_key)
        if output is not None:
            _write_no_clobber(Path(output), stable_json(generated_report).encode("utf-8"))
        return generated_report
    except (OSError, CharacterizationError) as error:
        if isinstance(error, XyceError):
            raise
        raise XyceError(str(error)) from error
    finally:
        if temporary.exists():
            shutil.rmtree(temporary, ignore_errors=True)
        claim.release()


def characterize_xyce(
    plan: CharacterizationPlan,
    *,
    command: XyceCommand | None = None,
    cache: str | Path = ".simcairn-characterization",
    output: str | Path | None = None,
    timeout_seconds: float = 300.0,
    environment: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Synchronous Python API for :func:`characterize_xyce_async`."""

    return asyncio.run(
        characterize_xyce_async(
            plan,
            command=command,
            cache=cache,
            output=output,
            timeout_seconds=timeout_seconds,
            environment=environment,
        )
    )


def probe_xyce_sync(
    command: XyceCommand,
    *,
    environment: dict[str, str] | None = None,
) -> XyceToolIdentity:
    """Probe Xyce from synchronous code, including when its caller owns an event loop."""

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(probe_xyce(command, environment=environment))
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="simcairn-xyce-probe") as executor:
        future = executor.submit(lambda: asyncio.run(probe_xyce(command, environment=environment)))
        return future.result()


__all__ = [
    "XyceCommand",
    "XyceError",
    "XyceExecutionError",
    "XyceToolIdentity",
    "characterize_xyce",
    "characterize_xyce_async",
    "probe_xyce",
    "probe_xyce_sync",
]
