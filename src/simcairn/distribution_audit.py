"""Bounded, fail-closed inspection of Python distribution archives."""

from __future__ import annotations

import stat
import tarfile
import unicodedata
import zipfile
from pathlib import PurePosixPath, PureWindowsPath

_MAX_ENTRY_BYTES = 64 * 1024 * 1024
_MAX_TOTAL_BYTES = 256 * 1024 * 1024
_MAX_ENTRIES = 100_000
_MAX_PATH_BYTES = 1_024
_WINDOWS_DEVICES = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{index}" for index in range(1, 10)}
    | {f"lpt{index}" for index in range(1, 10)}
)


class DistributionArchiveError(ValueError):
    """A wheel or sdist has unsafe, ambiguous, or unbounded structure."""


def _archive_path(raw: str, *, directory: bool) -> PurePosixPath:
    name = raw[:-1] if directory and raw.endswith("/") else raw
    if (
        not name
        or "\\" in name
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
        or PureWindowsPath(name).drive
    ):
        raise DistributionArchiveError("archive path is empty or non-portable")
    try:
        encoded = name.encode("utf-8", errors="strict")
    except UnicodeError as error:
        raise DistributionArchiveError("archive path is not valid UTF-8 text") from error
    if len(encoded) > _MAX_PATH_BYTES:
        raise DistributionArchiveError("archive path exceeds the supported length")
    if unicodedata.normalize("NFC", name) != name:
        raise DistributionArchiveError("archive path is not Unicode-normalized")
    path = PurePosixPath(name)
    if not path.parts or path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise DistributionArchiveError("archive path is absolute or traverses a parent")
    if path.as_posix() != name:
        raise DistributionArchiveError("archive path is not canonical")
    for component in path.parts:
        base = component.split(".", maxsplit=1)[0].casefold()
        if ":" in component or component.endswith((" ", ".")) or base in _WINDOWS_DEVICES:
            raise DistributionArchiveError("archive path is unsafe or aliased on Windows")
    return path


def _folded(path: PurePosixPath) -> tuple[str, ...]:
    return tuple(unicodedata.normalize("NFC", part).casefold() for part in path.parts)


def _record_path(
    path: PurePosixPath,
    *,
    directory: bool,
    observed: set[tuple[str, ...]],
    files: set[tuple[str, ...]],
    parents: set[tuple[str, ...]],
) -> None:
    identity = _folded(path)
    if identity in observed:
        raise DistributionArchiveError("archive contains duplicate or casefold-equivalent names")
    for index in range(1, len(identity)):
        if identity[:index] in files:
            raise DistributionArchiveError("archive contains a file/directory prefix collision")
        parents.add(identity[:index])
    if not directory and identity in parents:
        raise DistributionArchiveError("archive contains a file/directory prefix collision")
    observed.add(identity)
    if not directory:
        files.add(identity)


def _is_sparse(member: tarfile.TarInfo) -> bool:
    return bool(
        member.type == getattr(tarfile, "GNUTYPE_SPARSE", b"S")
        or getattr(member, "sparse", None) is not None
        or any(key.startswith("GNU.sparse") for key in member.pax_headers)
    )


def audit_sdist(archive: tarfile.TarFile, *, expected_root: str | None = None) -> frozenset[str]:
    """Validate an sdist and return regular files relative to its sole root."""

    observed: set[tuple[str, ...]] = set()
    files: set[tuple[str, ...]] = set()
    parents: set[tuple[str, ...]] = set()
    roots: set[str] = set()
    result: set[str] = set()
    total = 0
    for count, member in enumerate(archive, start=1):
        if count > _MAX_ENTRIES:
            raise DistributionArchiveError("source distribution contains too many entries")
        directory = member.isdir()
        path = _archive_path(member.name, directory=directory)
        if _is_sparse(member):
            raise DistributionArchiveError("source distribution contains a sparse entry")
        if not directory and not member.isreg():
            raise DistributionArchiveError("source distribution contains a link or special entry")
        if member.size < 0 or member.size > _MAX_ENTRY_BYTES:
            raise DistributionArchiveError("source distribution entry size is outside the limit")
        total += member.size
        if total > _MAX_TOTAL_BYTES:
            raise DistributionArchiveError("source distribution exceeds the total size limit")
        _record_path(
            path,
            directory=directory,
            observed=observed,
            files=files,
            parents=parents,
        )
        roots.add(path.parts[0])
        if len(path.parts) > 1 and not directory:
            result.add(PurePosixPath(*path.parts[1:]).as_posix())
    if len(roots) != 1:
        raise DistributionArchiveError("source distribution does not have one canonical root")
    if expected_root is not None and roots != {expected_root}:
        raise DistributionArchiveError(
            f"source distribution root must be exactly {expected_root!r}"
        )
    return frozenset(result)


def _zip_kind(member: zipfile.ZipInfo) -> tuple[bool, bool]:
    directory = member.is_dir()
    file_type = stat.S_IFMT(member.external_attr >> 16)
    if directory:
        return True, file_type in {0, stat.S_IFDIR}
    return False, file_type in {0, stat.S_IFREG}


def audit_wheel(archive: zipfile.ZipFile) -> frozenset[str]:
    """Validate a wheel and return its canonical regular-file names."""

    observed: set[tuple[str, ...]] = set()
    files: set[tuple[str, ...]] = set()
    parents: set[tuple[str, ...]] = set()
    result: set[str] = set()
    total = 0
    for count, member in enumerate(archive.infolist(), start=1):
        if count > _MAX_ENTRIES:
            raise DistributionArchiveError("wheel contains too many entries")
        directory, permitted = _zip_kind(member)
        path = _archive_path(member.filename, directory=directory)
        if not permitted or member.flag_bits & 1:
            raise DistributionArchiveError("wheel contains a link, special, or encrypted entry")
        if member.file_size < 0 or member.file_size > _MAX_ENTRY_BYTES:
            raise DistributionArchiveError("wheel entry size is outside the limit")
        total += member.file_size
        if total > _MAX_TOTAL_BYTES:
            raise DistributionArchiveError("wheel exceeds the total size limit")
        _record_path(
            path,
            directory=directory,
            observed=observed,
            files=files,
            parents=parents,
        )
        if not directory:
            result.add(path.as_posix())
    return frozenset(result)


__all__ = ["DistributionArchiveError", "audit_sdist", "audit_wheel"]
