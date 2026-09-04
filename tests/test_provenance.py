from __future__ import annotations

import hashlib
import re
import shutil
from dataclasses import replace
from pathlib import Path

import pytest

import simcairn.planner as planner_module
import simcairn.provenance as provenance
from simcairn import __version__, compile_plan, load_manifest
from simcairn.model import Plan
from simcairn.provenance import (
    ProducerIdentity,
    ProducerIdentityError,
    _source_snapshot,
    current_producer_identity,
)

ROOT = Path(__file__).parents[1]
EXAMPLE = ROOT / "examples" / "rc_sweep" / "simcairn.toml"


def test_current_producer_identity_hashes_the_imported_package() -> None:
    current_producer_identity.cache_clear()
    identity = current_producer_identity()
    package = ROOT / "src" / "simcairn"
    assert identity.distribution == "simcairn"
    assert identity.version == __version__ == "0.2.0"
    assert (
        identity.validation_implementation_sha256
        == hashlib.sha256((package / "reference.py").read_bytes()).hexdigest()
    )
    assert (
        identity.adapter_implementation_sha256
        == hashlib.sha256((package / "adapters.py").read_bytes()).hexdigest()
    )
    assert len(identity.package_tree_sha256) == 64
    assert current_producer_identity() is identity


def test_logical_source_tree_identity_is_root_independent(tmp_path: Path) -> None:
    source = ROOT / "src" / "simcairn"
    first = tmp_path / "first" / "simcairn"
    second = tmp_path / "second" / "simcairn"
    shutil.copytree(source, first)
    shutil.copytree(source, second)
    assert _source_snapshot(first) == _source_snapshot(second)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("distribution", "other", "distribution"),
        ("version", "", "version"),
        ("version", "1\nforged", "version"),
        ("package_tree_algorithm", "sha256-files", "algorithm"),
        ("package_tree_sha256", "A" * 64, "package_tree"),
        ("validation_implementation_sha256", True, "validation_implementation"),
        ("adapter_implementation_sha256", "0" * 63, "adapter_implementation"),
    ],
)
def test_producer_identity_rejects_malformed_fields(
    field: str, value: object, message: str
) -> None:
    identity = current_producer_identity().as_dict()
    identity[field] = value  # type: ignore[assignment]
    with pytest.raises(ProducerIdentityError, match=message):
        ProducerIdentity.from_value(identity)


def test_producer_identity_is_bound_to_every_activity_and_plan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = load_manifest(EXAMPLE)
    first = compile_plan(manifest)
    expected = current_producer_identity().as_dict()
    assert all(activity.identity["producer_identity"] == expected for activity in first.activities)

    changed = replace(current_producer_identity(), version="0.2.0+different")
    monkeypatch.setattr(planner_module, "current_producer_identity", lambda: changed)
    second = compile_plan(manifest)
    assert first.id != second.id
    assert [activity.id for activity in first.activities] != [
        activity.id for activity in second.activities
    ]


def test_saved_plan_rejects_producer_identity_tampering() -> None:
    data = compile_plan(load_manifest(EXAMPLE)).as_dict()
    data["activities"][0]["identity"]["producer_identity"]["version"] = "0.2.0+forged"
    with pytest.raises(ValueError, match="activity id"):
        Plan.from_dict(data)

    malformed = compile_plan(load_manifest(EXAMPLE)).as_dict()
    malformed["activities"][0]["identity"]["producer_identity"]["package_tree_sha256"] = "bad"
    with pytest.raises(ProducerIdentityError, match="package_tree"):
        Plan.from_dict(malformed)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.pop("version"),
        lambda value: value.update(unexpected="field"),
    ],
)
def test_producer_identity_rejects_missing_and_unknown_fields(mutate) -> None:  # type: ignore[no-untyped-def]
    identity = current_producer_identity().as_dict()
    mutate(identity)
    with pytest.raises(ProducerIdentityError, match="missing or unknown fields"):
        ProducerIdentity.from_value(identity)


def test_producer_identity_rejects_a_non_mapping() -> None:
    with pytest.raises(ProducerIdentityError, match="missing or unknown fields"):
        ProducerIdentity.from_value(["not", "a", "mapping"])


def test_source_snapshot_rejects_a_tree_with_no_python_files(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_text("not python\n", encoding="utf-8")
    with pytest.raises(ProducerIdentityError, match="invalid number of Python files"):
        _source_snapshot(tmp_path)


def test_source_snapshot_rejects_an_oversized_file(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    (tmp_path / "module.py").write_text("x = 1\n", encoding="utf-8")
    # Bound the limit rather than writing an 8 MiB file: the guard is what is
    # under test, not the filesystem's ability to hold a large file.
    monkeypatch.setattr(provenance, "_MAX_SOURCE_FILE_BYTES", 2)
    with pytest.raises(ProducerIdentityError, match=re.escape("source is too large: module.py")):
        _source_snapshot(tmp_path)


def test_source_snapshot_rejects_an_oversized_tree(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("y = 2\n", encoding="utf-8")
    monkeypatch.setattr(provenance, "_MAX_PACKAGE_TREE_BYTES", 8)
    with pytest.raises(ProducerIdentityError, match="source tree is too large"):
        _source_snapshot(tmp_path)


class _GrownStat:
    """A stat result that reports a larger size, delegating everything else."""

    def __init__(self, wrapped: object, size: int) -> None:
        self._wrapped = wrapped
        self.st_size = size

    def __getattr__(self, name: str) -> object:
        return getattr(self._wrapped, name)


def test_source_snapshot_rejects_a_file_that_changes_while_read(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    target = tmp_path / "module.py"
    target.write_text("x = 1\n", encoding="utf-8")
    real_stat = Path.stat

    def growing_stat(self: Path, *args: object, **kwargs: object):  # type: ignore[no-untyped-def]
        result = real_stat(self, *args, **kwargs)
        if self == target:
            # Report a larger size than the file holds, which is what a concurrent
            # writer looks like to the snapshot: the read comes up short. Only
            # st_size is overridden; is_file() needs the real st_mode.
            return _GrownStat(result, result.st_size + 16)
        return result

    monkeypatch.setattr(Path, "stat", growing_stat)
    with pytest.raises(ProducerIdentityError, match=re.escape("changed while read: module.py")):
        _source_snapshot(tmp_path)
