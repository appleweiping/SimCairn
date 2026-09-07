from __future__ import annotations

import io
import stat
import tarfile
import zipfile
from collections.abc import Sequence

import pytest

from simcairn.distribution_audit import (
    DistributionArchiveError,
    audit_sdist,
    audit_wheel,
)


def _tar(entries: Sequence[tuple[str, bytes, bytes | None]]) -> tarfile.TarFile:
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w:gz") as archive:
        for name, content, type_code in entries:
            member = tarfile.TarInfo(name)
            member.size = len(content)
            if type_code is not None:
                member.type = type_code
                if type_code in {tarfile.SYMTYPE, tarfile.LNKTYPE}:
                    member.linkname = "target"
            archive.addfile(member, io.BytesIO(content) if member.isreg() else None)
    payload.seek(0)
    return tarfile.open(fileobj=payload, mode="r:gz")


def _zip(entries: Sequence[tuple[str, bytes, int | None]]) -> zipfile.ZipFile:
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, mode="w") as archive:
        for name, content, mode in entries:
            member = zipfile.ZipInfo(name)
            if mode is not None:
                member.create_system = 3
                member.external_attr = mode << 16
            archive.writestr(member, content)
    payload.seek(0)
    result = zipfile.ZipFile(payload)
    # ZipInfo normalizes the host path separator while constructing fixtures
    # on Windows. Restore the parsed metadata here so the auditor sees the
    # same hostile member name that a Linux release runner would expose.
    for member, (name, _content, _mode) in zip(result.infolist(), entries, strict=True):
        member.filename = name
    return result


def test_distribution_auditors_accept_canonical_regular_files() -> None:
    with _tar(
        [
            ("simcairn-1/", b"", tarfile.DIRTYPE),
            ("simcairn-1/src/", b"", tarfile.DIRTYPE),
            ("simcairn-1/src/module.py", b"value = 1\n", None),
        ]
    ) as archive:
        assert audit_sdist(archive) == {"src/module.py"}
    with _zip(
        [
            ("simcairn/", b"", stat.S_IFDIR | 0o755),
            ("simcairn/module.py", b"value = 1\n", stat.S_IFREG | 0o644),
        ]
    ) as archive:
        assert audit_wheel(archive) == {"simcairn/module.py"}


@pytest.mark.parametrize(
    ("entries", "message"),
    [
        ([("simcairn-1/../escape", b"x", None)], "traverses"),
        ([("simcairn-1/bad\\path", b"x", None)], "non-portable"),
        ([("simcairn-1/bad\x01path", b"x", None)], "non-portable"),
        ([("simcairn-1/cafe\u0301", b"x", None)], "Unicode-normalized"),
        ([("simcairn-1/link", b"", tarfile.SYMTYPE)], "link or special"),
        ([("simcairn-1/sparse", b"", tarfile.GNUTYPE_SPARSE)], "sparse"),
        (
            [("simcairn-1/Name", b"x", None), ("simcairn-1/name", b"x", None)],
            "duplicate",
        ),
        (
            [("simcairn-1/file", b"x", None), ("simcairn-1/file/child", b"x", None)],
            "prefix collision",
        ),
        (
            [("one/file", b"x", None), ("two/file", b"x", None)],
            "one canonical root",
        ),
    ],
)
def test_sdist_rejects_ambiguous_or_special_entries(
    entries: Sequence[tuple[str, bytes, bytes | None]], message: str
) -> None:
    with _tar(entries) as archive, pytest.raises(DistributionArchiveError, match=message):
        audit_sdist(archive)


@pytest.mark.parametrize(
    ("entries", "message"),
    [
        ([("../escape", b"x", None)], "traverses"),
        ([("bad\\path", b"x", None)], "non-portable"),
        ([("bad\x7fpath", b"x", None)], "non-portable"),
        ([("cafe\u0301", b"x", None)], "Unicode-normalized"),
        ([("link", b"target", stat.S_IFLNK | 0o777)], "link, special"),
        ([("Name", b"x", None), ("name", b"x", None)], "duplicate"),
        ([("file", b"x", None), ("file/child", b"x", None)], "prefix collision"),
    ],
)
def test_wheel_rejects_ambiguous_or_special_entries(
    entries: Sequence[tuple[str, bytes, int | None]], message: str
) -> None:
    with _zip(entries) as archive, pytest.raises(DistributionArchiveError, match=message):
        audit_wheel(archive)


def test_wheel_rejects_encrypted_flag() -> None:
    with _zip([("module.py", b"x", None)]) as archive:
        archive.infolist()[0].flag_bits |= 1
        with pytest.raises(DistributionArchiveError, match="encrypted"):
            audit_wheel(archive)
