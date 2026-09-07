"""Fail-closed archive shape checks used by the release workflow."""

from __future__ import annotations

import stat
import tarfile
import unicodedata
import zipfile
from collections.abc import Iterable
from pathlib import PurePosixPath, PureWindowsPath

_MAX_ENTRY_BYTES = 64 * 1024 * 1024
_MAX_TOTAL_BYTES = 256 * 1024 * 1024
_MAX_ENTRIES = 100_000
_MAX_PATH_BYTES = 1024


class DistributionArchiveError(ValueError):
    """A distribution archive has an ambiguous or unsafe shape."""


def _path(raw: str, *, directory: bool) -> PurePosixPath:
    name = raw[:-1] if directory and raw.endswith("/") else raw
    if (
        not name
        or "\\" in name
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
        or PureWindowsPath(name).drive
    ):
        raise DistributionArchiveError("archive path is empty or non-portable")
    try:
        encoded = name.encode("utf-8")
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
    return path


def _key(path: PurePosixPath) -> tuple[str, ...]:
    return tuple(unicodedata.normalize("NFC", part).casefold() for part in path.parts)


def _record_path(
    path: PurePosixPath,
    *,
    directory: bool,
    observed: set[tuple[str, ...]],
    files: set[tuple[str, ...]],
    parents: set[tuple[str, ...]],
) -> None:
    folded = _key(path)
    if folded in observed:
        raise DistributionArchiveError("archive contains duplicate or normalized-casefold names")
    for index in range(1, len(folded)):
        if folded[:index] in files:
            raise DistributionArchiveError("archive contains a file/directory prefix collision")
        parents.add(folded[:index])
    if not directory and folded in parents:
        raise DistributionArchiveError("archive contains a file/directory prefix collision")
    observed.add(folded)
    if not directory:
        files.add(folded)


def _tar_is_sparse(member: tarfile.TarInfo) -> bool:
    return bool(
        member.type == getattr(tarfile, "GNUTYPE_SPARSE", b"S")
        or getattr(member, "sparse", None) is not None
        or any(key.startswith("GNU.sparse") for key in member.pax_headers)
    )


def audit_sdist(archive: tarfile.TarFile) -> frozenset[str]:
    """Validate an sdist and return canonical regular-file names below its root."""
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
        path = _path(member.name, directory=directory)
        if _tar_is_sparse(member):
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
    return frozenset(result)


def _zip_kind(member: zipfile.ZipInfo) -> tuple[bool, bool]:
    directory = member.is_dir()
    unix_mode = member.external_attr >> 16
    file_type = stat.S_IFMT(unix_mode)
    if directory:
        return True, file_type in {0, stat.S_IFDIR}
    return False, file_type in {0, stat.S_IFREG}


def audit_wheel(archive: zipfile.ZipFile) -> frozenset[str]:
    """Validate a wheel ZIP and return its canonical regular-file names."""
    observed: set[tuple[str, ...]] = set()
    files: set[tuple[str, ...]] = set()
    parents: set[tuple[str, ...]] = set()
    result: set[str] = set()
    total = 0
    members: Iterable[zipfile.ZipInfo] = archive.infolist()
    for count, member in enumerate(members, start=1):
        if count > _MAX_ENTRIES:
            raise DistributionArchiveError("wheel contains too many entries")
        directory, permitted_type = _zip_kind(member)
        path = _path(member.filename, directory=directory)
        if not permitted_type or member.flag_bits & 1:
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
