from __future__ import annotations

import io
import stat
import tarfile
import zipfile
from collections.abc import Sequence

import pytest

import simcairn.distribution_audit as distribution_audit
from simcairn.distribution_audit import (
    DistributionArchiveError,
    audit_sdist,
    audit_wheel,
)


def tar_archive(entries: Sequence[tuple[str, bytes, bytes | None]]) -> tarfile.TarFile:
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


def zip_archive(entries: Sequence[tuple[str, bytes, int | None]]) -> zipfile.ZipFile:
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
    for member, (name, _content, _mode) in zip(result.infolist(), entries, strict=True):
        member.filename = name
    return result


def test_auditors_accept_canonical_regular_files() -> None:
    with tar_archive(
        [
            ("simcairn-1/", b"", tarfile.DIRTYPE),
            ("simcairn-1/src/", b"", tarfile.DIRTYPE),
            ("simcairn-1/src/module.py", b"value = 1\n", None),
        ]
    ) as archive:
        assert audit_sdist(archive, expected_root="simcairn-1") == {"src/module.py"}
    with zip_archive(
        [
            ("simcairn/", b"", stat.S_IFDIR | 0o755),
            ("simcairn/module.py", b"value = 1\n", stat.S_IFREG | 0o644),
        ]
    ) as archive:
        assert audit_wheel(archive) == {"simcairn/module.py"}


@pytest.mark.parametrize(
    ("entries", "message"),
    [
        ([("root/../escape", b"x", None)], "traverses"),
        ([("root/bad\\path", b"x", None)], "non-portable"),
        ([("root/bad\x01path", b"x", None)], "non-portable"),
        ([("C:/root/file", b"x", None)], "non-portable"),
        ([("root/CON", b"x", None)], "Windows"),
        ([("root/AUX.txt", b"x", None)], "Windows"),
        ([("root/file.", b"x", None)], "Windows"),
        ([("root/file ", b"x", None)], "Windows"),
        ([("root/foo:bar", b"x", None)], "Windows"),
        ([("root//file", b"x", None)], "canonical"),
        ([(f"root/{'x' * 1025}", b"x", None)], "supported length"),
        ([("root/cafe\u0301", b"x", None)], "Unicode-normalized"),
        ([("root/link", b"", tarfile.SYMTYPE)], "link or special"),
        ([("root/sparse", b"", tarfile.GNUTYPE_SPARSE)], "sparse"),
        ([("root/Name", b"x", None), ("root/name", b"x", None)], "duplicate"),
        (
            [("root/file", b"x", None), ("root/file/child", b"x", None)],
            "prefix collision",
        ),
        ([("one/file", b"x", None), ("two/file", b"x", None)], "one canonical root"),
    ],
)
def test_sdist_rejects_ambiguous_or_special_entries(
    entries: Sequence[tuple[str, bytes, bytes | None]], message: str
) -> None:
    with tar_archive(entries) as archive, pytest.raises(DistributionArchiveError, match=message):
        audit_sdist(archive)


@pytest.mark.parametrize(
    ("entries", "message"),
    [
        ([("../escape", b"x", None)], "traverses"),
        ([("bad\\path", b"x", None)], "non-portable"),
        ([("bad\x7fpath", b"x", None)], "non-portable"),
        ([("C:/file", b"x", None)], "non-portable"),
        ([("CON", b"x", None)], "Windows"),
        ([("AUX.txt", b"x", None)], "Windows"),
        ([("file.", b"x", None)], "Windows"),
        ([("file ", b"x", None)], "Windows"),
        ([("foo:bar", b"x", None)], "Windows"),
        ([("root//file", b"x", None)], "canonical"),
        ([("x" * 1025, b"x", None)], "supported length"),
        ([("cafe\u0301", b"x", None)], "Unicode-normalized"),
        ([("link", b"target", stat.S_IFLNK | 0o777)], "link, special"),
        ([("Name", b"x", None), ("name", b"x", None)], "duplicate"),
        ([("file", b"x", None), ("file/child", b"x", None)], "prefix collision"),
    ],
)
def test_wheel_rejects_ambiguous_or_special_entries(
    entries: Sequence[tuple[str, bytes, int | None]], message: str
) -> None:
    with zip_archive(entries) as archive, pytest.raises(DistributionArchiveError, match=message):
        audit_wheel(archive)


def test_wheel_rejects_encrypted_entry() -> None:
    with zip_archive([("module.py", b"x", None)]) as archive:
        archive.infolist()[0].flag_bits |= 1
        with pytest.raises(DistributionArchiveError, match="encrypted"):
            audit_wheel(archive)


def test_sdist_can_require_the_exact_release_root() -> None:
    with (
        tar_archive([("other-1/module.py", b"x", None)]) as archive,
        pytest.raises(DistributionArchiveError, match="root must be exactly"),
    ):
        audit_sdist(archive, expected_root="simcairn-0.4.0")


def test_archive_auditors_enforce_entry_count_and_size_bounds(monkeypatch) -> None:
    monkeypatch.setattr(distribution_audit, "_MAX_ENTRIES", 0)
    with (
        tar_archive([("root/file", b"x", None)]) as archive,
        pytest.raises(DistributionArchiveError, match="too many"),
    ):
        audit_sdist(archive)
    with (
        zip_archive([("module.py", b"x", None)]) as archive,
        pytest.raises(DistributionArchiveError, match="too many"),
    ):
        audit_wheel(archive)

    monkeypatch.setattr(distribution_audit, "_MAX_ENTRIES", 100_000)
    monkeypatch.setattr(distribution_audit, "_MAX_ENTRY_BYTES", 0)
    with (
        tar_archive([("root/file", b"x", None)]) as archive,
        pytest.raises(DistributionArchiveError, match="entry size"),
    ):
        audit_sdist(archive)
    with (
        zip_archive([("module.py", b"x", None)]) as archive,
        pytest.raises(DistributionArchiveError, match="entry size"),
    ):
        audit_wheel(archive)

    monkeypatch.setattr(distribution_audit, "_MAX_ENTRY_BYTES", 64 * 1024 * 1024)
    monkeypatch.setattr(distribution_audit, "_MAX_TOTAL_BYTES", 0)
    with (
        tar_archive([("root/file", b"x", None)]) as archive,
        pytest.raises(DistributionArchiveError, match="total size"),
    ):
        audit_sdist(archive)
    with (
        zip_archive([("module.py", b"x", None)]) as archive,
        pytest.raises(DistributionArchiveError, match="total size"),
    ):
        audit_wheel(archive)
