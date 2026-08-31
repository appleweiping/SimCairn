from __future__ import annotations

import hashlib
import shutil
from dataclasses import replace
from pathlib import Path

import pytest

import simcairn.planner as planner_module
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
