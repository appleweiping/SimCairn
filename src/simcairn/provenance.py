"""Identity of the exact imported SimCairn implementation used for a plan."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from simcairn._version import __version__

_DIGEST = re.compile(r"[0-9a-f]{64}")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+!-]{0,127}")
_MAX_SOURCE_FILE_BYTES = 8 * 1024 * 1024
_MAX_PACKAGE_TREE_BYTES = 64 * 1024 * 1024
_MAX_PACKAGE_FILES = 4_096


class ProducerIdentityError(ValueError):
    """The imported implementation cannot be identified without ambiguity."""


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ProducerIdentityError(f"producer identity {field} must be a lowercase SHA-256")
    return value


@dataclass(frozen=True, slots=True)
class ProducerIdentity:
    """Path-independent identity of the distribution and relevant source bytes."""

    distribution: str
    version: str
    package_tree_algorithm: str
    package_tree_sha256: str
    validation_implementation_sha256: str
    adapter_implementation_sha256: str

    def as_dict(self) -> dict[str, str]:
        return {
            "distribution": self.distribution,
            "version": self.version,
            "package_tree_algorithm": self.package_tree_algorithm,
            "package_tree_sha256": self.package_tree_sha256,
            "validation_implementation_sha256": self.validation_implementation_sha256,
            "adapter_implementation_sha256": self.adapter_implementation_sha256,
        }

    @classmethod
    def from_value(cls, value: object) -> ProducerIdentity:
        if not isinstance(value, Mapping) or set(value) != {
            "distribution",
            "version",
            "package_tree_algorithm",
            "package_tree_sha256",
            "validation_implementation_sha256",
            "adapter_implementation_sha256",
        }:
            raise ProducerIdentityError("producer identity has missing or unknown fields")
        distribution = value["distribution"]
        version = value["version"]
        if distribution != "simcairn":
            raise ProducerIdentityError("producer identity distribution must be simcairn")
        if not isinstance(version, str) or _VERSION.fullmatch(version) is None:
            raise ProducerIdentityError("producer identity version is invalid")
        algorithm = value["package_tree_algorithm"]
        if algorithm != "simcairn-python-source-tree/1":
            raise ProducerIdentityError("producer identity package-tree algorithm is unsupported")
        return cls(
            distribution,
            version,
            algorithm,
            _digest(value["package_tree_sha256"], "package_tree_sha256"),
            _digest(
                value["validation_implementation_sha256"],
                "validation_implementation_sha256",
            ),
            _digest(
                value["adapter_implementation_sha256"],
                "adapter_implementation_sha256",
            ),
        )


def _source_snapshot(root: Path) -> tuple[str, dict[str, str]]:
    paths = sorted(root.rglob("*.py"), key=lambda path: path.relative_to(root).as_posix())
    if not paths or len(paths) > _MAX_PACKAGE_FILES:
        raise ProducerIdentityError("imported package has an invalid number of Python files")
    total = 0
    files: dict[str, str] = {}
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise ProducerIdentityError("imported package source files must be regular files")
        relative = path.relative_to(root).as_posix()
        size = path.stat().st_size
        if size > _MAX_SOURCE_FILE_BYTES:
            raise ProducerIdentityError(f"imported package source is too large: {relative}")
        total += size
        if total > _MAX_PACKAGE_TREE_BYTES:
            raise ProducerIdentityError("imported package source tree is too large")
        with path.open("rb") as stream:
            payload = stream.read(_MAX_SOURCE_FILE_BYTES + 1)
        if len(payload) != size:
            raise ProducerIdentityError(f"imported package source changed while read: {relative}")
        files[relative] = hashlib.sha256(payload).hexdigest()
    logical_tree = {
        "algorithm": "simcairn-python-source-tree/1",
        "files": files,
    }
    encoded = json.dumps(logical_tree, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("ascii")).hexdigest(), files


@lru_cache(maxsize=1)
def current_producer_identity() -> ProducerIdentity:
    """Hash the actual imported package twice and reject a changing snapshot."""
    root = Path(__file__).resolve().parent
    first = _source_snapshot(root)
    second = _source_snapshot(root)
    if first != second:
        raise ProducerIdentityError("imported package changed while its identity was computed")
    tree_digest, files = first
    try:
        harness = files["reference.py"]
        adapter = files["adapters.py"]
    except KeyError as error:
        raise ProducerIdentityError("imported package lacks provenance-critical modules") from error
    return ProducerIdentity(
        "simcairn",
        __version__,
        "simcairn-python-source-tree/1",
        tree_digest,
        harness,
        adapter,
    )
