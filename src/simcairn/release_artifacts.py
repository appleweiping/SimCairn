"""Offline validation for release SBOMs, checksums, and asset shape."""

from __future__ import annotations

import argparse
import base64
import binascii
import csv
import hashlib
import json
import os
import re
import stat
import zipfile
from collections.abc import Mapping, Sequence
from datetime import datetime
from email.parser import Parser
from pathlib import Path, PurePosixPath
from tempfile import NamedTemporaryFile
from typing import Any
from urllib.parse import urlsplit

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_SHA1_DIGEST = re.compile(r"[0-9a-f]{40}\Z")
_SAFE_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*\Z")
_CHECKSUM_LINE = re.compile(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._+-]*)\Z")
_SPDX_ID = re.compile(r"SPDXRef-[A-Za-z0-9.-]+\Z")
_SPDX_CREATED = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_URI_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*\Z")
_MAX_SBOM_BYTES = 64 * 1024 * 1024
_MAX_JSON_DEPTH = 64
_MAX_JSON_NODES = 250_000
_DOCUMENT_ID = "SPDXRef-DOCUMENT"


class ReleaseArtifactError(ValueError):
    """A release artifact is missing, malformed, or inconsistent."""


def canonical_distribution_name(value: str) -> str:
    """Return the normalized distribution identity used by Python metadata."""

    return re.sub(r"[-_.]+", "-", value).casefold()


def _safe_component(value: str, context: str) -> str:
    if _SAFE_COMPONENT.fullmatch(value) is None:
        raise ReleaseArtifactError(f"{context} is not a safe filename component")
    return value


def distribution_asset_names(name: str, version: str) -> tuple[str, str]:
    """Return the exact wheel and source-distribution filenames for a release."""

    normalized = canonical_distribution_name(_safe_component(name, "distribution name")).replace(
        "-", "_"
    )
    checked_version = _safe_component(version, "distribution version")
    return (
        f"{normalized}-{checked_version}-py3-none-any.whl",
        f"{normalized}-{checked_version}.tar.gz",
    )


def release_asset_names(name: str, version: str) -> frozenset[str]:
    """Return the exact four-file public release asset allowlist."""

    wheel, sdist = distribution_asset_names(name, version)
    return frozenset({wheel, sdist, "SBOM.spdx.json", "SHA256SUMS"})


def checksum_subject_names(name: str, version: str) -> frozenset[str]:
    """Return the three payloads covered by SHA256SUMS."""

    wheel, sdist = distribution_asset_names(name, version)
    return frozenset({wheel, sdist, "SBOM.spdx.json"})


def _object_without_duplicate_keys(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseArtifactError(f"SBOM contains duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_nonstandard_json_constant(value: str) -> None:
    raise ReleaseArtifactError(f"SBOM contains non-standard JSON constant {value!r}")


def _validate_json_complexity(value: object) -> None:
    pending = [(value, 0)]
    enqueued = 1
    while pending:
        item, depth = pending.pop()
        if depth > _MAX_JSON_DEPTH:
            raise ReleaseArtifactError("SBOM JSON exceeds complexity limits")
        children: object
        if isinstance(item, Mapping):
            children = item.values()
        elif isinstance(item, list):
            children = item
        else:
            continue
        for child in children:
            enqueued += 1
            if enqueued > _MAX_JSON_NODES:
                raise ReleaseArtifactError("SBOM JSON exceeds complexity limits")
            pending.append((child, depth + 1))


def load_spdx(path: Path) -> Mapping[str, Any]:
    """Load one bounded, duplicate-key-free SPDX JSON document."""

    try:
        with path.open("rb") as stream:
            payload = stream.read(_MAX_SBOM_BYTES + 1)
    except OSError as error:
        raise ReleaseArtifactError(f"cannot read SBOM {path}: {error}") from error
    if len(payload) > _MAX_SBOM_BYTES:
        raise ReleaseArtifactError(f"SBOM exceeds {_MAX_SBOM_BYTES} bytes")
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_nonstandard_json_constant,
        )
    except ReleaseArtifactError:
        raise
    except (UnicodeError, RecursionError, OverflowError, ValueError) as error:
        raise ReleaseArtifactError(f"SBOM is not valid UTF-8 JSON: {error}") from error
    _validate_json_complexity(value)
    if not isinstance(value, Mapping):
        raise ReleaseArtifactError("SBOM root must be an object")
    return value


def _objects(value: object, context: str) -> tuple[dict[str, Any], ...]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ReleaseArtifactError(f"SBOM {context} must be an array of objects")
    return tuple(value)


def _safe_spdx_text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or not value.isprintable():
        raise ReleaseArtifactError(f"SBOM {context} must be safe non-empty text")
    return value


def _validate_document_header(
    document: Mapping[str, Any], *, expected_syft_version: str | None = None
) -> None:
    """Validate the SPDX document-header profile required by release evidence."""

    if document.get("spdxVersion") != "SPDX-2.3":
        raise ReleaseArtifactError("SBOM spdxVersion must be SPDX-2.3")
    if document.get("dataLicense") != "CC0-1.0":
        raise ReleaseArtifactError("SBOM dataLicense must be CC0-1.0")
    if document.get("SPDXID") != _DOCUMENT_ID:
        raise ReleaseArtifactError(f"SBOM document SPDXID must be {_DOCUMENT_ID}")
    _safe_spdx_text(document.get("name"), "name")

    namespace = _safe_spdx_text(document.get("documentNamespace"), "documentNamespace")
    try:
        parsed_namespace = urlsplit(namespace)
    except ValueError as error:
        raise ReleaseArtifactError(
            "SBOM documentNamespace must be an absolute URI without a fragment"
        ) from error
    if (
        _URI_SCHEME.fullmatch(parsed_namespace.scheme) is None
        or "#" in namespace
        or any(character.isspace() for character in namespace)
    ):
        raise ReleaseArtifactError(
            "SBOM documentNamespace must be an absolute URI without a fragment"
        )

    creation = document.get("creationInfo")
    if not isinstance(creation, Mapping):
        raise ReleaseArtifactError("SBOM creationInfo must be an object")
    created = creation.get("created")
    if not isinstance(created, str) or _SPDX_CREATED.fullmatch(created) is None:
        raise ReleaseArtifactError("SBOM creationInfo created must be a valid UTC timestamp")
    try:
        datetime.strptime(created, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise ReleaseArtifactError(
            "SBOM creationInfo created must be a valid UTC timestamp"
        ) from error

    creators = creation.get("creators")
    if not isinstance(creators, list) or not creators:
        raise ReleaseArtifactError("SBOM must identify a pinned generator in creationInfo creators")
    for creator in creators:
        _safe_spdx_text(creator, "creationInfo creator")
    if expected_syft_version is not None:
        expected_creator = f"Tool: syft-{expected_syft_version}"
        if expected_creator not in creators:
            raise ReleaseArtifactError(f"SBOM must identify pinned generator {expected_creator}")


def _package_candidates(
    packages: Sequence[dict[str, Any]], expected_name: str, expected_version: str
) -> tuple[dict[str, Any], ...]:
    expected_identity = canonical_distribution_name(expected_name)
    matching_name = tuple(
        package
        for package in packages
        if isinstance(package.get("name"), str)
        and canonical_distribution_name(package["name"]) == expected_identity
    )
    if not matching_name:
        raise ReleaseArtifactError(f"SBOM does not contain package {expected_name!r}")
    candidates = tuple(
        package for package in matching_name if package.get("versionInfo") == expected_version
    )
    if not candidates:
        observed = sorted(repr(package.get("versionInfo")) for package in matching_name)
        raise ReleaseArtifactError(
            f"SBOM package {expected_name!r} version must be non-empty and exactly "
            f"{expected_version!r}; observed {observed}"
        )
    return candidates


def _is_pypi_package(package: Mapping[str, Any], name: str, version: str) -> bool:
    expected_locator = f"pkg:pypi/{canonical_distribution_name(name)}@{version}"
    references = package.get("externalRefs")
    return isinstance(references, list) and any(
        isinstance(reference, Mapping)
        and reference.get("referenceCategory") == "PACKAGE-MANAGER"
        and reference.get("referenceType") == "purl"
        and reference.get("referenceLocator") == expected_locator
        for reference in references
    )


def _record_sha256(value: str, path: str) -> bytes:
    if not value.startswith("sha256="):
        raise ReleaseArtifactError(f"wheel RECORD lacks SHA-256 for {path!r}")
    encoded = value.removeprefix("sha256=")
    try:
        digest = base64.b64decode(
            encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True
        )
    except (ValueError, binascii.Error) as error:
        raise ReleaseArtifactError(f"wheel RECORD has an invalid SHA-256 for {path!r}") from error
    if len(digest) != hashlib.sha256().digest_size:
        raise ReleaseArtifactError(f"wheel RECORD has an invalid SHA-256 for {path!r}")
    return digest


def _wheel_distribution(
    wheel: Path, name: str, version: str, package_prefix: str, dist_prefix: str
) -> dict[str, tuple[bytes | None, int | None]]:
    expected_wheel, _sdist = distribution_asset_names(name, version)
    if wheel.name != expected_wheel or wheel.is_symlink() or not wheel.is_file():
        raise ReleaseArtifactError(
            "wheel path does not identify the exact regular release artifact"
        )
    record_name = f"{dist_prefix}/RECORD"
    result: dict[str, tuple[bytes | None, int | None]] = {}
    try:
        with zipfile.ZipFile(wheel) as archive:
            entries = archive.infolist()
            names = [entry.filename for entry in entries]
            if len(names) != len(set(names)) or names.count(record_name) != 1:
                raise ReleaseArtifactError("wheel has duplicate entries or no unique RECORD")
            if any(
                "\\" in raw
                or PurePosixPath(raw).is_absolute()
                or ".." in PurePosixPath(raw).parts
                or PurePosixPath(raw).as_posix() != raw
                for raw in names
            ):
                raise ReleaseArtifactError("wheel contains a non-canonical archive path")
            if any(stat.S_IFMT(entry.external_attr >> 16) == stat.S_IFLNK for entry in entries):
                raise ReleaseArtifactError("wheel contains a symbolic-link entry")
            if archive.getinfo(record_name).file_size > 8 * 1024 * 1024:
                raise ReleaseArtifactError("wheel RECORD exceeds the supported size")
            rows = tuple(csv.reader(archive.read(record_name).decode("utf-8").splitlines()))
            declared_names: set[str] = set()
            for row in rows:
                if len(row) != 3:
                    raise ReleaseArtifactError("wheel RECORD row must have exactly three fields")
                raw_name, record_hash, record_size = row
                relative = PurePosixPath(raw_name)
                if (
                    not relative.parts
                    or relative.is_absolute()
                    or ".." in relative.parts
                    or "\\" in raw_name
                    or relative.as_posix() != raw_name
                ):
                    raise ReleaseArtifactError("wheel RECORD contains a non-canonical path")
                if raw_name in declared_names:
                    raise ReleaseArtifactError(f"wheel RECORD repeats {raw_name!r}")
                declared_names.add(raw_name)
                if relative.parts[0] not in {package_prefix, dist_prefix}:
                    raise ReleaseArtifactError(
                        "wheel contains an unsupported path outside its package and dist-info: "
                        f"{raw_name!r}"
                    )
                if raw_name == record_name:
                    if record_hash or record_size:
                        raise ReleaseArtifactError("wheel RECORD must not self-hash")
                    result[raw_name] = (None, None)
                    continue
                if not record_size.isdecimal():
                    raise ReleaseArtifactError(f"wheel RECORD lacks a size for {raw_name!r}")
                digest = _record_sha256(record_hash, raw_name)
                try:
                    payload = archive.read(raw_name)
                except KeyError as error:
                    raise ReleaseArtifactError(
                        f"wheel RECORD path is absent from the archive: {raw_name!r}"
                    ) from error
                size = int(record_size)
                if len(payload) != size or hashlib.sha256(payload).digest() != digest:
                    raise ReleaseArtifactError(
                        f"wheel archive entry does not match RECORD: {raw_name!r}"
                    )
                result[raw_name] = (digest, size)
            archive_files = {entry.filename for entry in entries if not entry.is_dir()}
            if archive_files != declared_names:
                missing = sorted(archive_files - declared_names)
                absent = sorted(declared_names - archive_files)
                raise ReleaseArtifactError(
                    "wheel archive and RECORD file sets differ; "
                    f"unrecorded={missing[:5]}, absent={absent[:5]}"
                )
    except ReleaseArtifactError:
        raise
    except (OSError, UnicodeError, csv.Error, zipfile.BadZipFile) as error:
        raise ReleaseArtifactError(f"cannot inspect release wheel {wheel}: {error}") from error
    if record_name not in result or not any(
        path.startswith(f"{package_prefix}/") for path in result
    ):
        raise ReleaseArtifactError("wheel RECORD does not contain the project package")
    return result


def _installed_distribution(
    site_packages: Path,
    wheel: Path,
    name: str,
    version: str,
    *,
    installation_root: Path | None = None,
    expected_external_paths: Sequence[str] = (),
) -> tuple[Path, dict[str, tuple[str, str]]]:
    root = site_packages.resolve(strict=True)
    install_root = root if installation_root is None else installation_root.resolve(strict=True)
    if not root.is_relative_to(install_root):
        raise ReleaseArtifactError("installed site-packages escapes the installation root")

    expected_external: set[str] = set()
    for raw_path in expected_external_paths:
        relative_path = PurePosixPath(raw_path)
        if (
            "\\" in raw_path
            or not relative_path.parts
            or relative_path.is_absolute()
            or ".." in relative_path.parts
            or relative_path.as_posix() != raw_path
        ):
            raise ReleaseArtifactError(
                f"expected external installed path is not canonical: {raw_path!r}"
            )
        if raw_path in expected_external:
            raise ReleaseArtifactError(
                f"expected external installed path is repeated: {raw_path!r}"
            )
        expected_external.add(raw_path)
    matches: list[Path] = []
    for metadata_path in root.glob("*.dist-info/METADATA"):
        if metadata_path.is_symlink() or metadata_path.parent.is_symlink():
            raise ReleaseArtifactError("installed distribution metadata must not be a symlink")
        try:
            metadata = Parser().parsestr(metadata_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError) as error:
            raise ReleaseArtifactError(
                f"cannot read installed metadata {metadata_path}: {error}"
            ) from error
        observed_name = metadata.get("Name")
        observed_version = metadata.get("Version")
        if (
            isinstance(observed_name, str)
            and canonical_distribution_name(observed_name) == canonical_distribution_name(name)
            and observed_version == version
        ):
            matches.append(metadata_path.parent)
    if len(matches) != 1:
        raise ReleaseArtifactError(
            f"installed site-packages must contain exactly one {name!r} {version!r} distribution"
        )
    dist_info = matches[0]
    record = dist_info / "RECORD"
    try:
        if record.is_symlink() or not record.is_file():
            raise ReleaseArtifactError("installed wheel RECORD must be a regular file")
        if record.stat().st_size > 8 * 1024 * 1024:
            raise ReleaseArtifactError("installed wheel RECORD exceeds the supported size")
        rows = tuple(csv.reader(record.read_text(encoding="utf-8").splitlines()))
    except (OSError, UnicodeError, csv.Error) as error:
        raise ReleaseArtifactError(
            f"cannot read installed wheel RECORD {record}: {error}"
        ) from error
    package_prefix = canonical_distribution_name(name).replace("-", "_")
    dist_prefix = dist_info.name
    wheel_files = _wheel_distribution(wheel, name, version, package_prefix, dist_prefix)
    installed: dict[str, tuple[str, str]] = {}
    target_installed: set[str] = set()
    observed_wheel_files: set[str] = set()
    observed_external: set[str] = set()
    record_name = f"{dist_prefix}/RECORD"
    record_rows = 0
    target_roots = ((root / package_prefix).resolve(), dist_info.resolve())
    for external_path in expected_external:
        external_target = install_root.joinpath(*PurePosixPath(external_path).parts).resolve(
            strict=False
        )
        if any(
            external_target == target or external_target.is_relative_to(target)
            for target in target_roots
        ):
            raise ReleaseArtifactError(
                f"expected external path overlaps the installed distribution: {external_path!r}"
            )
    for row in rows:
        if not row:
            raise ReleaseArtifactError("installed wheel RECORD contains an empty row")
        if len(row) != 3:
            raise ReleaseArtifactError("installed wheel RECORD row must have exactly three fields")
        raw_name, record_hash, record_size = row
        if "\\" in raw_name:
            raise ReleaseArtifactError("installed wheel RECORD path is not portable")
        relative = PurePosixPath(raw_name)
        if not relative.parts or relative.is_absolute() or relative.as_posix() != raw_name:
            raise ReleaseArtifactError(
                f"installed wheel RECORD path is not canonical: {raw_name!r}"
            )
        saw_non_parent = False
        for part in relative.parts:
            if part == "..":
                if saw_non_parent:
                    raise ReleaseArtifactError(
                        f"installed wheel RECORD has an interior parent path: {raw_name!r}"
                    )
            else:
                saw_non_parent = True
        if not saw_non_parent:
            raise ReleaseArtifactError(f"installed wheel RECORD path has no filename: {raw_name!r}")
        candidate = root.joinpath(*relative.parts)
        lexical_candidate = Path(os.path.abspath(candidate))
        if not lexical_candidate.is_relative_to(install_root):
            raise ReleaseArtifactError(
                f"installed RECORD path escapes the installation root: {relative}"
            )
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as error:
            raise ReleaseArtifactError(f"installed RECORD path is missing: {relative}") from error
        if (
            candidate.is_symlink()
            or not resolved.is_relative_to(install_root)
            or not resolved.is_file()
        ):
            raise ReleaseArtifactError(
                f"installed RECORD path escapes the installation root: {relative}"
            )
        installed_name = resolved.relative_to(install_root).as_posix()
        path_cursor = install_root
        for component in lexical_candidate.relative_to(install_root).parts:
            path_cursor /= component
            if path_cursor.is_symlink():
                raise ReleaseArtifactError(
                    f"installed RECORD path traverses a symlink: {raw_name!r}"
                )
        if installed_name in installed:
            raise ReleaseArtifactError(
                f"installed wheel RECORD aliases an installed path: {installed_name!r}"
            )
        relative_name = relative.as_posix()
        is_wheel_path = relative.parts[0] in {package_prefix, dist_prefix}
        if is_wheel_path:
            target_installed.add(installed_name)
            if relative_name in wheel_files:
                observed_wheel_files.add(relative_name)
        else:
            if installed_name not in expected_external:
                raise ReleaseArtifactError(
                    f"installed wheel RECORD contains an unexpected external path: {raw_name!r}"
                )
            observed_external.add(installed_name)
        try:
            payload = resolved.read_bytes()
        except OSError as error:
            raise ReleaseArtifactError(f"cannot read installed RECORD path: {relative}") from error
        sha256_digest = hashlib.sha256(payload).digest()
        sha1_hex = hashlib.sha1(payload, usedforsecurity=False).hexdigest()
        wheel_claim = wheel_files.get(relative_name) if is_wheel_path else None
        if relative_name == record_name:
            record_rows += 1
            if record_hash or record_size:
                raise ReleaseArtifactError("installed wheel RECORD must not self-hash")
        elif wheel_claim is None:
            if bool(record_hash) != bool(record_size):
                raise ReleaseArtifactError(
                    "installer-generated RECORD entry must provide both hash and size or neither: "
                    f"{relative_name!r}"
                )
            if record_hash and (
                _record_sha256(record_hash, relative_name) != sha256_digest
                or not record_size.isdecimal()
                or int(record_size) != len(payload)
            ):
                raise ReleaseArtifactError(
                    "installer-generated RECORD entry does not match installed content: "
                    f"{relative_name!r}"
                )
        else:
            expected_digest, expected_size = wheel_claim
            if (
                expected_digest is None
                or expected_size is None
                or _record_sha256(record_hash, relative_name) != expected_digest
                or not record_size.isdecimal()
                or int(record_size) != expected_size
                or sha256_digest != expected_digest
                or len(payload) != expected_size
            ):
                raise ReleaseArtifactError(
                    f"installed file does not match wheel RECORD: {relative_name!r}"
                )
        installed[installed_name] = (sha1_hex, sha256_digest.hex())
    if not installed:
        raise ReleaseArtifactError("installed wheel RECORD contains no package files")
    if record_rows != 1:
        raise ReleaseArtifactError("installed wheel RECORD must list itself exactly once")
    if observed_wheel_files != set(wheel_files):
        missing = sorted(set(wheel_files) - observed_wheel_files)
        unexpected = sorted(observed_wheel_files - set(wheel_files))
        raise ReleaseArtifactError(
            "installed RECORD and wheel file sets differ; "
            f"missing={missing[:5]}, unexpected={unexpected[:5]}"
        )
    if observed_external != expected_external:
        missing = sorted(expected_external - observed_external)
        unexpected = sorted(observed_external - expected_external)
        raise ReleaseArtifactError(
            "installed RECORD external file set differs from the release contract; "
            f"missing={missing[:5]}, unexpected={unexpected[:5]}"
        )
    actual_files: set[str] = set()
    pending = [root / package_prefix, dist_info]
    for tree_root in pending:
        if tree_root.is_symlink() or not tree_root.is_dir():
            raise ReleaseArtifactError(
                f"installed distribution tree is not a regular directory: {tree_root}"
            )
        directories = [tree_root]
        while directories:
            current = directories.pop()
            try:
                entries = tuple(os.scandir(current))
            except OSError as error:
                raise ReleaseArtifactError(
                    f"cannot enumerate installed distribution tree {current}: {error}"
                ) from error
            for entry in entries:
                path = Path(entry.path)
                if entry.is_symlink():
                    raise ReleaseArtifactError(f"installed distribution contains a symlink: {path}")
                if entry.is_dir(follow_symlinks=False):
                    directories.append(path)
                    continue
                if not entry.is_file(follow_symlinks=False):
                    raise ReleaseArtifactError(
                        f"installed distribution contains a non-regular entry: {path}"
                    )
                relative_name = path.relative_to(install_root).as_posix()
                if relative_name in actual_files:
                    raise ReleaseArtifactError(
                        f"installed distribution aliases a file path: {relative_name!r}"
                    )
                actual_files.add(relative_name)
    if actual_files != target_installed:
        unrecorded = sorted(actual_files - target_installed)
        absent = sorted(target_installed - actual_files)
        raise ReleaseArtifactError(
            "installed distribution tree and RECORD file sets differ; "
            f"unrecorded={unrecorded[:5]}, absent={absent[:5]}"
        )
    return dist_info, dict(sorted(installed.items()))


def _package_verification_code(sha1_values: Sequence[str]) -> str:
    payload = "".join(sorted(sha1_values)).encode("ascii")
    return hashlib.sha1(payload, usedforsecurity=False).hexdigest()


def _normalized_spdx_filename(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.replace("\\", "/")
    while normalized.startswith("/"):
        normalized = normalized[1:]
    path = PurePosixPath(normalized)
    if not path.parts or ".." in path.parts:
        return None
    return path.as_posix()


def _spdx_element_ids(
    document_id: object,
    packages: Sequence[dict[str, Any]],
    files: Sequence[dict[str, Any]],
) -> frozenset[str]:
    if not isinstance(document_id, str) or not document_id:
        raise ReleaseArtifactError("SBOM document has an invalid SPDXID")
    identifiers = {document_id}
    for context, items in (("package", packages), ("file", files)):
        for item in items:
            identifier = item.get("SPDXID")
            if not isinstance(identifier, str) or _SPDX_ID.fullmatch(identifier) is None:
                raise ReleaseArtifactError(f"SBOM {context} has an invalid SPDXID")
            if identifier in identifiers:
                raise ReleaseArtifactError(
                    f"SBOM reuses SPDXID {identifier!r} across document, packages, or files"
                )
            identifiers.add(identifier)
    return frozenset(identifiers)


def bind_installed_wheel(
    sbom_path: Path,
    site_packages: Path,
    wheel: Path,
    *,
    expected_name: str,
    expected_version: str,
    installation_root: Path | None = None,
    expected_external_paths: Sequence[str] = (),
) -> int:
    """Bind Syft's installed Python package to its RECORD-backed files in SPDX."""

    document = load_spdx(sbom_path)
    if not isinstance(document, dict):  # pragma: no cover - load_spdx returns a dict
        raise ReleaseArtifactError("SBOM root must be mutable")
    _validate_document_header(document)
    packages = _objects(document.get("packages"), "packages")
    files = _objects(document.get("files"), "files")
    element_ids = _spdx_element_ids(document.get("SPDXID"), packages, files)
    candidates = tuple(
        package
        for package in _package_candidates(packages, expected_name, expected_version)
        if _is_pypi_package(package, expected_name, expected_version)
    )
    if len(candidates) != 1:
        raise ReleaseArtifactError(
            f"SBOM must contain exactly one PyPI package for {expected_name!r} {expected_version!r}"
        )
    package_id = candidates[0].get("SPDXID")
    if not isinstance(package_id, str) or package_id == _DOCUMENT_ID:
        raise ReleaseArtifactError("installed package has an invalid SPDXID")

    _dist_info, installed_files = _installed_distribution(
        site_packages,
        wheel,
        expected_name,
        expected_version,
        installation_root=installation_root,
        expected_external_paths=expected_external_paths,
    )
    file_items: dict[str, dict[str, Any]] = {}
    paths_by_id: dict[str, str] = {}
    for item in files:
        filename = _normalized_spdx_filename(item.get("fileName"))
        spdx_id = item.get("SPDXID")
        if filename is None or not isinstance(spdx_id, str):
            continue
        if filename in file_items:
            raise ReleaseArtifactError(f"SBOM repeats file identity for {filename!r}")
        if spdx_id in paths_by_id:
            raise ReleaseArtifactError(f"SBOM reuses file SPDXID {spdx_id!r} for multiple paths")
        file_items[filename] = item
        paths_by_id[spdx_id] = filename
    missing = sorted(set(installed_files) - set(file_items))
    if missing:
        raise ReleaseArtifactError(
            f"Syft SBOM omitted installed wheel files: {missing[:5]}"
            + (" ..." if len(missing) > 5 else "")
        )

    relationships_value = document.get("relationships")
    if not isinstance(relationships_value, list) or not all(
        isinstance(item, Mapping) for item in relationships_value
    ):
        raise ReleaseArtifactError("SBOM relationships must be an array of objects")
    for relationship in relationships_value:
        endpoints = (
            relationship.get("spdxElementId"),
            relationship.get("relatedSpdxElement"),
        )
        if any(endpoint not in element_ids for endpoint in endpoints):
            raise ReleaseArtifactError("SBOM relationship refers to an unknown SPDX element")
    for path, (sha1_hex, sha256_hex) in installed_files.items():
        file_items[path]["checksums"] = [
            {"algorithm": "SHA1", "checksumValue": sha1_hex},
            {"algorithm": "SHA256", "checksumValue": sha256_hex},
        ]
    package = candidates[0]
    package["filesAnalyzed"] = True
    package["packageVerificationCode"] = {
        "packageVerificationCodeValue": _package_verification_code(
            [sha1 for sha1, _sha256 in installed_files.values()]
        )
    }

    additions: list[dict[str, str]] = [
        {
            "spdxElementId": _DOCUMENT_ID,
            "relatedSpdxElement": package_id,
            "relationshipType": "DESCRIBES",
        }
    ]
    additions.extend(
        {
            "spdxElementId": package_id,
            "relatedSpdxElement": str(file_items[path]["SPDXID"]),
            "relationshipType": "CONTAINS",
        }
        for path in installed_files
    )
    existing = {
        (
            item.get("spdxElementId"),
            item.get("relationshipType"),
            item.get("relatedSpdxElement"),
        )
        for item in relationships_value
    }
    for relationship in additions:
        identity = (
            relationship["spdxElementId"],
            relationship["relationshipType"],
            relationship["relatedSpdxElement"],
        )
        if identity not in existing:
            relationships_value.append(relationship)
            existing.add(identity)
    relationships_value.sort(
        key=lambda item: (
            str(item.get("spdxElementId")),
            str(item.get("relationshipType")),
            str(item.get("relatedSpdxElement")),
            str(item.get("comment", "")),
        )
    )
    payload = (json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()
    temporary: Path | None = None
    try:
        with NamedTemporaryFile(
            mode="wb",
            prefix=f".{sbom_path.name}.",
            suffix=".tmp",
            dir=sbom_path.parent,
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, sbom_path)
        temporary = None
    except OSError as error:
        raise ReleaseArtifactError(f"cannot write bound SBOM {sbom_path}: {error}") from error
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return len(installed_files)


def validate_spdx(
    document: Mapping[str, Any],
    *,
    expected_name: str,
    expected_version: str,
    expected_syft_version: str,
) -> None:
    """Require the release SPDX 2.3 header and installed-package file profile."""

    _validate_document_header(document, expected_syft_version=expected_syft_version)

    packages = _objects(document.get("packages"), "packages")
    files = _objects(document.get("files"), "files")
    relationships = _objects(document.get("relationships"), "relationships")
    element_ids = _spdx_element_ids(document.get("SPDXID"), packages, files)
    file_digests: dict[str, tuple[str, str] | None] = {}
    for item in files:
        file_id = item.get("SPDXID")
        if not isinstance(file_id, str) or file_id == _DOCUMENT_ID:
            continue
        if file_id in file_digests:
            raise ReleaseArtifactError(f"SBOM repeats file SPDXID {file_id!r}")
        checksums = item.get("checksums")
        parsed: dict[str, str] = {}
        if isinstance(checksums, list):
            for checksum in checksums:
                if not isinstance(checksum, Mapping):
                    continue
                algorithm = checksum.get("algorithm")
                value = checksum.get("checksumValue")
                if not isinstance(algorithm, str) or not isinstance(value, str):
                    continue
                if algorithm in parsed:
                    raise ReleaseArtifactError(
                        f"SBOM file {file_id!r} repeats checksum algorithm {algorithm!r}"
                    )
                parsed[algorithm] = value
        if (
            set(parsed) == {"SHA1", "SHA256"}
            and _SHA1_DIGEST.fullmatch(parsed["SHA1"])
            and _DIGEST.fullmatch(parsed["SHA256"])
        ):
            file_digests[file_id] = (parsed["SHA1"], parsed["SHA256"])
        else:
            file_digests[file_id] = None
    if not file_digests:
        raise ReleaseArtifactError("SBOM must contain at least one file")

    candidates = tuple(
        package
        for package in _package_candidates(packages, expected_name, expected_version)
        if _is_pypi_package(package, expected_name, expected_version)
    )
    if len(candidates) != 1:
        raise ReleaseArtifactError(
            f"SBOM must identify exactly one installed PyPI package for {expected_name!r} "
            f"{expected_version!r} with an exact package URL"
        )
    package = candidates[0]
    package_id = package.get("SPDXID")
    if not isinstance(package_id, str) or package_id == _DOCUMENT_ID:
        raise ReleaseArtifactError("installed package has an invalid SPDXID")
    triples: set[tuple[str, str, str]] = set()
    for relationship in relationships:
        triple = (
            relationship.get("spdxElementId"),
            relationship.get("relationshipType"),
            relationship.get("relatedSpdxElement"),
        )
        if not all(isinstance(value, str) and value for value in triple):
            raise ReleaseArtifactError("SBOM relationship is incomplete")
        typed = (str(triple[0]), str(triple[1]), str(triple[2]))
        if typed[0] not in element_ids or typed[2] not in element_ids:
            raise ReleaseArtifactError("SBOM relationship refers to an unknown SPDX element")
        if typed in triples:
            raise ReleaseArtifactError("SBOM repeats a relationship")
        triples.add(typed)
    described = (_DOCUMENT_ID, "DESCRIBES", package_id) in triples
    contained_ids = {
        related
        for element, relation, related in triples
        if element == package_id and relation == "CONTAINS"
    }
    if not described or not contained_ids:
        raise ReleaseArtifactError(
            f"SBOM package {expected_name!r} {expected_version!r} must be DESCRIBED by the "
            "document and directly CONTAIN its listed files"
        )
    contained_digests = [file_digests.get(file_id) for file_id in contained_ids]
    if any(digest is None for digest in contained_digests):
        raise ReleaseArtifactError(
            "every file contained by the release package must have exact SHA1 and SHA256 checksums"
        )
    verification = package.get("packageVerificationCode")
    observed_code = (
        verification.get("packageVerificationCodeValue")
        if isinstance(verification, Mapping)
        and not verification.get("packageVerificationCodeExcludedFiles")
        else None
    )
    sha1_values = [digest[0] for digest in contained_digests if digest is not None]
    expected_code = _package_verification_code(sha1_values)
    if package.get("filesAnalyzed") is not True or observed_code != expected_code:
        raise ReleaseArtifactError(
            "SBOM package verification code does not bind the complete contained-file set"
        )


def validate_spdx_path(
    path: Path,
    *,
    expected_name: str,
    expected_version: str,
    expected_syft_version: str,
) -> None:
    """Load and validate one SPDX JSON document."""

    validate_spdx(
        load_spdx(path),
        expected_name=expected_name,
        expected_version=expected_version,
        expected_syft_version=expected_syft_version,
    )


def _regular_files(directory: Path) -> frozenset[str]:
    try:
        entries = tuple(directory.iterdir())
    except OSError as error:
        raise ReleaseArtifactError(
            f"cannot inspect release directory {directory}: {error}"
        ) from error
    invalid = sorted(entry.name for entry in entries if entry.is_symlink() or not entry.is_file())
    if invalid:
        raise ReleaseArtifactError(f"release directory contains non-regular entries: {invalid}")
    return frozenset(entry.name for entry in entries)


def _require_exact_files(directory: Path, expected: frozenset[str]) -> None:
    observed = _regular_files(directory)
    if observed != expected:
        missing = sorted(expected - observed)
        unexpected = sorted(observed - expected)
        raise ReleaseArtifactError(
            f"release asset set mismatch; missing={missing}, unexpected={unexpected}"
        )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise ReleaseArtifactError(f"cannot hash release asset {path}: {error}") from error
    return digest.hexdigest()


def write_checksums(directory: Path, *, name: str, version: str) -> Path:
    """Write checksums for exactly the wheel, sdist, and validated SBOM payloads."""

    subjects = checksum_subject_names(name, version)
    _require_exact_files(directory, subjects)
    destination = directory / "SHA256SUMS"
    lines = [f"{_sha256(directory / filename)}  {filename}\n" for filename in sorted(subjects)]
    try:
        with destination.open("x", encoding="ascii", newline="\n") as stream:
            stream.writelines(lines)
    except OSError as error:
        raise ReleaseArtifactError(
            f"cannot create checksum manifest {destination}: {error}"
        ) from error
    return destination


def verify_checksums(directory: Path, *, name: str, version: str) -> None:
    """Require exact checksum subjects and verify every digest."""

    expected = checksum_subject_names(name, version)
    checksum_path = directory / "SHA256SUMS"
    try:
        lines = checksum_path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as error:
        raise ReleaseArtifactError(
            f"cannot read checksum manifest {checksum_path}: {error}"
        ) from error
    parsed: dict[str, str] = {}
    for line in lines:
        match = _CHECKSUM_LINE.fullmatch(line)
        if match is None:
            raise ReleaseArtifactError("SHA256SUMS contains a malformed line")
        digest, filename = match.groups()
        if filename in parsed:
            raise ReleaseArtifactError(f"SHA256SUMS repeats {filename!r}")
        parsed[filename] = digest
    if frozenset(parsed) != expected:
        raise ReleaseArtifactError("SHA256SUMS subjects do not match the release payload allowlist")
    for filename, expected_digest in parsed.items():
        observed = _sha256(directory / filename)
        if not _DIGEST.fullmatch(expected_digest) or observed != expected_digest:
            raise ReleaseArtifactError(f"SHA-256 mismatch for {filename}")


def verify_release(
    directory: Path,
    *,
    name: str,
    version: str,
    syft_version: str,
) -> None:
    """Verify the exact four-asset release set, SBOM semantics, and checksums."""

    _require_exact_files(directory, release_asset_names(name, version))
    validate_spdx_path(
        directory / "SBOM.spdx.json",
        expected_name=name,
        expected_version=version,
        expected_syft_version=syft_version,
    )
    verify_checksums(directory, name=name, version=version)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate-sbom")
    validate.add_argument("--sbom", required=True, type=Path)
    validate.add_argument("--name", required=True)
    validate.add_argument("--version", required=True)
    validate.add_argument("--syft-version", required=True)
    verify = subparsers.add_parser("verify-release")
    verify.add_argument("--directory", required=True, type=Path)
    verify.add_argument("--name", required=True)
    verify.add_argument("--version", required=True)
    verify.add_argument("--syft-version", required=True)
    bind = subparsers.add_parser("bind-installed-wheel")
    bind.add_argument("--sbom", required=True, type=Path)
    bind.add_argument("--site-packages", required=True, type=Path)
    bind.add_argument("--installation-root", required=True, type=Path)
    bind.add_argument("--expected-external-path", action="append", default=[])
    bind.add_argument("--wheel", required=True, type=Path)
    bind.add_argument("--name", required=True)
    bind.add_argument("--version", required=True)
    checksums = subparsers.add_parser("write-checksums")
    checksums.add_argument("--directory", required=True, type=Path)
    checksums.add_argument("--name", required=True)
    checksums.add_argument("--version", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run an offline release-artifact validation command."""

    parser = _parser()
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "bind-installed-wheel":
            bind_installed_wheel(
                arguments.sbom,
                arguments.site_packages,
                arguments.wheel,
                expected_name=arguments.name,
                expected_version=arguments.version,
                installation_root=arguments.installation_root,
                expected_external_paths=arguments.expected_external_path,
            )
        elif arguments.command == "validate-sbom":
            validate_spdx_path(
                arguments.sbom,
                expected_name=arguments.name,
                expected_version=arguments.version,
                expected_syft_version=arguments.syft_version,
            )
        elif arguments.command == "write-checksums":
            write_checksums(arguments.directory, name=arguments.name, version=arguments.version)
        else:
            verify_release(
                arguments.directory,
                name=arguments.name,
                version=arguments.version,
                syft_version=arguments.syft_version,
            )
    except ReleaseArtifactError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
