"""Fail-closed acquisition of the exact Ciel files used by reference replays.

The checked-in inventory is the trust anchor. GitHub release metadata is an
observation that must agree with it; it is never allowed to update the pins.
Only explicitly listed regular files are materialized from each archive.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess  # nosec B404
import tarfile
import tempfile
import threading
import unicodedata
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from http.client import HTTPMessage
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import IO, Any, BinaryIO, Protocol, cast
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, OpenerDirector, Request, build_opener

from simcairn.sky130 import load_sizing_decision

_HEX = frozenset("0123456789abcdef")
_MAX_INVENTORY_BYTES = 1024 * 1024
_MAX_RELEASE_BYTES = 4 * 1024 * 1024
_MAX_DECISION_BYTES = 1024 * 1024
_MAX_ASSET_BYTES = 256 * 1024 * 1024
_MAX_TAR_BYTES = 1024 * 1024 * 1024
_MAX_MEMBER_BYTES = 16 * 1024 * 1024
_MAX_JSON_DEPTH = 64
_MAX_TAR_MEMBERS = 1_000_000
_MAX_TAR_PATH_BYTES = 1024
_MAX_SELECTED_BYTES = 64 * 1024 * 1024
_ZSTD_TIMEOUT_SECONDS = 15 * 60
_CHUNK = 1024 * 1024
_API_HOST = "api.github.com"
_ASSET_REDIRECT_HOSTS = frozenset(
    {
        "github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
    }
)
_RAW_HOSTS = frozenset({"raw.githubusercontent.com"})
_REPOSITORY = "fossi-foundation/ciel-releases"
_REPOSITORY_ID = 966850989
LOCKED_INVENTORY_SHA256 = "7d50ea391b0d10a79e2a0a281162659250af95e5c9f10deea3e2b8d5569d0c49"


class ReplayPreparationError(ValueError):
    """A replay lock, response, archive, or destination failed verification."""


class _Response(Protocol):
    status: int
    headers: Mapping[str, str]

    def read(self, size: int = -1) -> bytes: ...

    def close(self) -> None: ...

    def geturl(self) -> str: ...


@dataclass(frozen=True, slots=True)
class MemberPin:
    path: str
    bytes: int
    sha256: str


@dataclass(frozen=True, slots=True)
class AssetPin:
    id: int
    name: str
    api_url: str
    content_type: str
    bytes: int
    sha256: str
    tar_bytes: int
    tar_sha256: str
    members: tuple[MemberPin, ...]


@dataclass(frozen=True, slots=True)
class ReleasePin:
    id: int
    tag: str
    api_url: str
    draft: bool
    prerelease: bool
    immutable: bool


@dataclass(frozen=True, slots=True)
class FamilyPin:
    name: str
    variant: str
    release: ReleasePin
    assets: tuple[AssetPin, ...]
    license: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class DecisionPin:
    url: str
    bytes: int
    sha256: str
    decision_sha256: str
    topology: str
    signature: str
    benchmark_sha256: str
    comparison_sha256: str


@dataclass(frozen=True, slots=True)
class ReplayPin:
    sidecar: str
    reference: str
    reference_sha256: str
    expected_points: int
    expected_activities: int
    observation_path: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ReplayInventory:
    revision: str
    release_repository: str
    release_repository_id: int
    families: Mapping[str, FamilyPin]
    decision: DecisionPin
    replays: Mapping[str, ReplayPin]
    sha256: str


@dataclass(frozen=True, slots=True)
class _PathIdentity:
    device: int
    inode: int
    mode: int


@dataclass(frozen=True, slots=True)
class DownloadObservation:
    bytes: int
    sha256: str
    final_host: str
    redirected: bool
    _identity: _PathIdentity | None = dataclass_field(default=None, repr=False, compare=False)


def _path_identity(path: Path) -> _PathIdentity:
    observed = path.lstat()
    return _PathIdentity(observed.st_dev, observed.st_ino, observed.st_mode)


def _same_owned_path(path: Path, identity: _PathIdentity) -> bool:
    try:
        observed = path.lstat()
    except FileNotFoundError:
        return False
    return (
        observed.st_dev == identity.device
        and observed.st_ino == identity.inode
        and observed.st_mode == identity.mode
    )


def _remove_owned_file(path: Path, identity: _PathIdentity | None) -> None:
    if identity is not None and stat.S_ISREG(identity.mode) and _same_owned_path(path, identity):
        path.unlink(missing_ok=True)


def _remove_owned_tree(path: Path, identity: _PathIdentity | None) -> None:
    if identity is not None and stat.S_ISDIR(identity.mode) and _same_owned_path(path, identity):
        shutil.rmtree(path, ignore_errors=True)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self,
        request: Request,
        file_pointer: IO[bytes],
        code: int,
        message: str,
        headers: HTTPMessage,
        new_url: str,
    ) -> Request | None:
        del request, file_pointer, code, message, headers, new_url
        return None


def _exact(value: object, keys: set[str], name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise ReplayPreparationError(f"{name} has missing or unknown fields")
    return cast(Mapping[str, Any], value)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReplayPreparationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json_bytes(payload: bytes, name: str) -> Any:
    try:
        text = payload.decode("utf-8")
        _check_json_depth(text, name)
        return json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ReplayPreparationError(f"non-finite JSON number in {name}: {token}")
            ),
        )
    except ReplayPreparationError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, OverflowError) as error:
        raise ReplayPreparationError(f"cannot parse {name}: {error}") from error


def _check_json_depth(text: str, name: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
        elif character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > _MAX_JSON_DEPTH:
                raise ReplayPreparationError(f"{name} exceeds the maximum JSON depth")
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise ReplayPreparationError(f"{name} has unbalanced JSON delimiters")


def _bounded_file(path: Path, limit: int, name: str) -> bytes:
    try:
        with path.open("rb") as stream:
            payload = stream.read(limit + 1)
    except OSError as error:
        raise ReplayPreparationError(f"cannot read {name}: {error}") from error
    if len(payload) > limit:
        raise ReplayPreparationError(f"{name} exceeds the {limit}-byte limit")
    return payload


def _string(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ReplayPreparationError(f"{name} must be a non-empty string")
    return value


def _integer(value: object, name: str, *, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ReplayPreparationError(f"{name} must be a positive integer")
    if maximum is not None and value > maximum:
        raise ReplayPreparationError(f"{name} exceeds the supported limit")
    return value


def _digest(value: object, name: str) -> str:
    text = _string(value, name)
    if len(text) != 64 or any(character not in _HEX for character in text):
        raise ReplayPreparationError(f"{name} must be a lowercase SHA-256")
    return text


def _revision(value: object, name: str) -> str:
    text = _string(value, name)
    if len(text) != 40 or any(character not in _HEX for character in text):
        raise ReplayPreparationError(f"{name} must be a lowercase 40-character revision")
    return text


def _boolean(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise ReplayPreparationError(f"{name} must be Boolean")
    return value


def _safe_relative(value: object, name: str) -> str:
    text = _string(value, name)
    if (
        "\\" in text
        or any(ord(character) < 32 or ord(character) == 127 for character in text)
        or PureWindowsPath(text).drive
    ):
        raise ReplayPreparationError(f"{name} is not a portable relative path")
    try:
        text.encode("utf-8")
    except UnicodeError as error:
        raise ReplayPreparationError(f"{name} is not valid UTF-8 text") from error
    if unicodedata.normalize("NFC", text) != text:
        raise ReplayPreparationError(f"{name} is not Unicode-normalized")
    path = PurePosixPath(text)
    if not path.parts or path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ReplayPreparationError(f"{name} is not a safe relative path")
    if path.as_posix() != text:
        raise ReplayPreparationError(f"{name} is not a canonical relative path")
    return text


def _https_url(value: object, name: str, *, hosts: frozenset[str]) -> str:
    text = _string(value, name)
    if any(ord(character) < 32 or ord(character) == 127 for character in text):
        raise ReplayPreparationError(f"{name} contains a control character")
    split = urlsplit(text)
    try:
        port = split.port
    except ValueError as error:
        raise ReplayPreparationError(f"{name} contains an invalid port") from error
    if (
        split.scheme != "https"
        or split.hostname not in hosts
        or split.username is not None
        or split.password is not None
        or port not in {None, 443}
        or split.fragment
    ):
        raise ReplayPreparationError(f"{name} is not an allowed HTTPS URL")
    return text


def _no_path_collisions(members: Sequence[MemberPin]) -> None:
    if sum(member.bytes for member in members) > _MAX_SELECTED_BYTES:
        raise ReplayPreparationError("selected archive members exceed the output limit")
    folded: dict[tuple[str, ...], str] = {}
    for member in members:
        parts = _path_key(PurePosixPath(member.path))
        if previous := folded.get(parts):
            raise ReplayPreparationError(
                f"member paths collide case-insensitively: {previous} and {member.path}"
            )
        folded[parts] = member.path
    paths = tuple(folded)
    for index, left in enumerate(paths):
        for right in paths[index + 1 :]:
            shorter, longer = (left, right) if len(left) < len(right) else (right, left)
            if longer[: len(shorter)] == shorter:
                raise ReplayPreparationError("member paths have a file/directory prefix collision")


def _parse_member(value: object, variant: str, name: str) -> MemberPin:
    raw = _exact(value, {"path", "bytes", "sha256"}, name)
    path = _safe_relative(raw["path"], f"{name}.path")
    if PurePosixPath(path).parts[0] != variant:
        raise ReplayPreparationError(f"{name}.path is outside the locked PDK variant")
    return MemberPin(
        path=path,
        bytes=_integer(raw["bytes"], f"{name}.bytes", maximum=_MAX_MEMBER_BYTES),
        sha256=_digest(raw["sha256"], f"{name}.sha256"),
    )


def _parse_asset(value: object, release: ReleasePin, variant: str, name: str) -> AssetPin:
    raw = _exact(
        value,
        {
            "id",
            "name",
            "api_url",
            "content_type",
            "bytes",
            "sha256",
            "tar_bytes",
            "tar_sha256",
            "members",
        },
        name,
    )
    asset_id = _integer(raw["id"], f"{name}.id")
    asset_name = _safe_relative(raw["name"], f"{name}.name")
    if "/" in asset_name:
        raise ReplayPreparationError(f"{name}.name must be one filename")
    api_url = _https_url(raw["api_url"], f"{name}.api_url", hosts=frozenset({_API_HOST}))
    expected_api = f"https://api.github.com/repos/{_REPOSITORY}/releases/assets/{asset_id}"
    if api_url != expected_api:
        raise ReplayPreparationError(f"{name}.api_url does not match its asset ID")
    raw_members = raw["members"]
    if not isinstance(raw_members, list):
        raise ReplayPreparationError(f"{name}.members must be an array")
    members = tuple(
        _parse_member(member, variant, f"{name}.members[{index}]")
        for index, member in enumerate(raw_members)
    )
    _no_path_collisions(members)
    content_type = _string(raw["content_type"], f"{name}.content_type")
    if content_type != "application/zstd":
        raise ReplayPreparationError(f"{name}.content_type must be application/zstd")
    return AssetPin(
        id=asset_id,
        name=asset_name,
        api_url=api_url,
        content_type=content_type,
        bytes=_integer(raw["bytes"], f"{name}.bytes", maximum=_MAX_ASSET_BYTES),
        sha256=_digest(raw["sha256"], f"{name}.sha256"),
        tar_bytes=_integer(raw["tar_bytes"], f"{name}.tar_bytes", maximum=_MAX_TAR_BYTES),
        tar_sha256=_digest(raw["tar_sha256"], f"{name}.tar_sha256"),
        members=members,
    )


def _parse_family(name: str, value: object, revision: str) -> FamilyPin:
    raw = _exact(value, {"variant", "release", "assets", "license"}, f"families.{name}")
    expected_variant = {"sky130": "sky130A", "gf180": "gf180mcuC"}[name]
    variant = _string(raw["variant"], f"families.{name}.variant")
    if variant != expected_variant:
        raise ReplayPreparationError(f"families.{name}.variant is not the supported variant")
    release_raw = _exact(
        raw["release"],
        {"id", "tag", "api_url", "draft", "prerelease", "immutable"},
        f"families.{name}.release",
    )
    release_id = _integer(release_raw["id"], f"families.{name}.release.id")
    tag = _string(release_raw["tag"], f"families.{name}.release.tag")
    prefix = "sky130" if name == "sky130" else "gf180mcu"
    if tag != f"{prefix}-{revision}":
        raise ReplayPreparationError(f"families.{name}.release.tag does not match the revision")
    api_url = _https_url(
        release_raw["api_url"],
        f"families.{name}.release.api_url",
        hosts=frozenset({_API_HOST}),
    )
    expected_api = f"https://api.github.com/repos/{_REPOSITORY}/releases/tags/{tag}"
    if api_url != expected_api:
        raise ReplayPreparationError(f"families.{name}.release.api_url does not match its tag")
    release = ReleasePin(
        id=release_id,
        tag=tag,
        api_url=api_url,
        draft=_boolean(release_raw["draft"], f"families.{name}.release.draft"),
        prerelease=_boolean(release_raw["prerelease"], f"families.{name}.release.prerelease"),
        immutable=_boolean(release_raw["immutable"], f"families.{name}.release.immutable"),
    )
    assets_raw = raw["assets"]
    if not isinstance(assets_raw, list) or len(assets_raw) != 2:
        raise ReplayPreparationError(f"families.{name}.assets must contain exactly two assets")
    assets = tuple(
        _parse_asset(asset, release, variant, f"families.{name}.assets[{index}]")
        for index, asset in enumerate(assets_raw)
    )
    if len({asset.id for asset in assets}) != len(assets) or len(
        {asset.name.casefold() for asset in assets}
    ) != len(assets):
        raise ReplayPreparationError(f"families.{name}.assets contains duplicate identities")
    all_members = tuple(member for asset in assets for member in asset.members)
    _no_path_collisions(all_members)
    license_raw = _exact(
        raw["license"], {"spdx", "source_commit", "url"}, f"families.{name}.license"
    )
    license_value = {
        "spdx": _string(license_raw["spdx"], f"families.{name}.license.spdx"),
        "source_commit": _revision(
            license_raw["source_commit"], f"families.{name}.license.source_commit"
        ),
        "url": _https_url(
            license_raw["url"],
            f"families.{name}.license.url",
            hosts=frozenset({"github.com"}),
        ),
    }
    if license_value["spdx"] != "Apache-2.0":
        raise ReplayPreparationError(f"families.{name}.license is not Apache-2.0")
    return FamilyPin(name, variant, release, assets, license_value)


def _parse_decision(value: object) -> DecisionPin:
    raw = _exact(
        value,
        {
            "url",
            "bytes",
            "sha256",
            "decision_sha256",
            "topology",
            "signature",
            "benchmark_sha256",
            "comparison_sha256",
        },
        "decision",
    )
    url = _https_url(raw["url"], "decision.url", hosts=_RAW_HOSTS)
    url_parts = PurePosixPath(urlsplit(url).path).parts
    if len(url_parts) < 4 or len(url_parts[3]) != 40 or any(c not in _HEX for c in url_parts[3]):
        raise ReplayPreparationError("decision.url is not pinned to an exact Git commit")
    return DecisionPin(
        url=url,
        bytes=_integer(raw["bytes"], "decision.bytes", maximum=_MAX_DECISION_BYTES),
        sha256=_digest(raw["sha256"], "decision.sha256"),
        decision_sha256=_digest(raw["decision_sha256"], "decision.decision_sha256"),
        topology=_string(raw["topology"], "decision.topology"),
        signature=_digest(raw["signature"], "decision.signature"),
        benchmark_sha256=_digest(raw["benchmark_sha256"], "decision.benchmark_sha256"),
        comparison_sha256=_digest(raw["comparison_sha256"], "decision.comparison_sha256"),
    )


def _parse_replay(name: str, value: object) -> ReplayPin:
    raw = _exact(
        value,
        {
            "sidecar",
            "reference",
            "reference_sha256",
            "expected_points",
            "expected_activities",
            "observation_path",
        },
        f"replays.{name}",
    )
    observation = raw["observation_path"]
    if (
        not isinstance(observation, list)
        or not observation
        or not all(isinstance(part, str) and part for part in observation)
    ):
        raise ReplayPreparationError(f"replays.{name}.observation_path is invalid")
    return ReplayPin(
        sidecar=_safe_relative(raw["sidecar"], f"replays.{name}.sidecar"),
        reference=_safe_relative(raw["reference"], f"replays.{name}.reference"),
        reference_sha256=_digest(raw["reference_sha256"], f"replays.{name}.reference_sha256"),
        expected_points=_integer(raw["expected_points"], f"replays.{name}.expected_points"),
        expected_activities=_integer(
            raw["expected_activities"], f"replays.{name}.expected_activities"
        ),
        observation_path=tuple(cast(list[str], observation)),
    )


def load_replay_inventory(path: str | Path) -> ReplayInventory:
    """Load and strictly validate the committed replay trust inventory."""
    inventory_path = Path(path)
    payload = _bounded_file(inventory_path, _MAX_INVENTORY_BYTES, "replay inventory")
    payload_sha256 = hashlib.sha256(payload).hexdigest()
    if payload_sha256 != LOCKED_INVENTORY_SHA256:
        raise ReplayPreparationError(
            "replay inventory differs from the wheel-embedded trust anchor"
        )
    raw = _exact(
        _load_json_bytes(payload, "replay inventory"),
        {
            "schema",
            "version",
            "revision",
            "release_repository",
            "release_repository_id",
            "families",
            "decision",
            "replays",
        },
        "replay inventory",
    )
    if raw["schema"] != "org.simcairn.ciel-replay-assets" or raw["version"] != 1:
        raise ReplayPreparationError("replay inventory schema or version is unsupported")
    revision = _revision(raw["revision"], "revision")
    repository = _https_url(
        raw["release_repository"],
        "release_repository",
        hosts=frozenset({"github.com"}),
    )
    if repository != f"https://github.com/{_REPOSITORY}":
        raise ReplayPreparationError(
            "release_repository is not the official Ciel release repository"
        )
    repository_id = _integer(raw["release_repository_id"], "release_repository_id")
    if repository_id != _REPOSITORY_ID:
        raise ReplayPreparationError("release_repository_id is not the locked Ciel repository ID")
    families_raw = _exact(raw["families"], {"sky130", "gf180"}, "families")
    families = {
        name: _parse_family(name, families_raw[name], revision) for name in sorted(families_raw)
    }
    replays_raw = _exact(raw["replays"], {"rc", "sky130", "gf180"}, "replays")
    replays = {name: _parse_replay(name, replays_raw[name]) for name in sorted(replays_raw)}
    return ReplayInventory(
        revision=revision,
        release_repository=repository,
        release_repository_id=repository_id,
        families=families,
        decision=_parse_decision(raw["decision"]),
        replays=replays,
        sha256=payload_sha256,
    )


def _status(response: _Response) -> int:
    status = getattr(response, "status", None)
    if status is None:
        status = getattr(response, "code", None)
    if isinstance(status, bool) or not isinstance(status, int):
        raise ReplayPreparationError("HTTP response has no numeric status")
    return status


def _header(response: _Response, name: str) -> str | None:
    direct = response.headers.get(name)
    if direct is not None:
        return direct
    folded = name.casefold()
    for key, value in response.headers.items():
        if key.casefold() == folded:
            return value
    return None


def _require_identity_encoding(response: _Response) -> None:
    encoding = _header(response, "Content-Encoding")
    if encoding is not None and encoding.casefold() != "identity":
        response.close()
        raise ReplayPreparationError("HTTP content encoding is not allowed")


def _open_once(request: Request, timeout: float) -> _Response:
    opener: OpenerDirector = build_opener(_NoRedirect())
    try:
        return cast(_Response, opener.open(request, timeout=timeout))
    except HTTPError as error:
        return cast(_Response, error)


def _open_verified(
    url: str,
    headers: Mapping[str, str],
    *,
    initial_hosts: frozenset[str],
    redirect_hosts: frozenset[str],
    redirects: int,
    timeout: float = 30.0,
) -> tuple[_Response, bool]:
    current = _https_url(url, "request URL", hosts=initial_hosts)
    request_headers = dict(headers)
    response = _open_once(Request(current, headers=request_headers, method="GET"), timeout)
    status = _status(response)
    if status in {301, 302, 303, 307, 308}:
        if redirects != 1:
            response.close()
            raise ReplayPreparationError("unexpected HTTP redirect")
        location = _header(response, "Location")
        response.close()
        if not isinstance(location, str) or not location:
            raise ReplayPreparationError("HTTP redirect has no Location")
        location_parts = urlsplit(location)
        if not location_parts.scheme or not location_parts.netloc:
            raise ReplayPreparationError("relative HTTP redirects are not allowed")
        redirected = _https_url(location, "redirect URL", hosts=redirect_hosts)
        if urlsplit(redirected).hostname != urlsplit(current).hostname:
            request_headers = {
                key: value
                for key, value in request_headers.items()
                if key.lower() != "authorization"
            }
        response = _open_once(Request(redirected, headers=request_headers, method="GET"), timeout)
        if _status(response) != 200:
            next_status = _status(response)
            response.close()
            raise ReplayPreparationError(
                f"redirect target returned unexpected HTTP status {next_status}"
            )
        if response.geturl() != redirected:
            response.close()
            raise ReplayPreparationError("HTTP transport followed an unverified redirect")
        _require_identity_encoding(response)
        return response, True
    if status != 200:
        response.close()
        raise ReplayPreparationError(f"request returned unexpected HTTP status {status}")
    if response.geturl() != current:
        response.close()
        raise ReplayPreparationError("HTTP transport followed an unverified redirect")
    _require_identity_encoding(response)
    return response, False


def _read_response(response: _Response, limit: int, name: str) -> bytes:
    chunks: list[bytes] = []
    count = 0
    try:
        while True:
            block = response.read(min(_CHUNK, limit - count + 1))
            if not block:
                break
            count += len(block)
            if count > limit:
                raise ReplayPreparationError(f"{name} exceeds the {limit}-byte response limit")
            chunks.append(block)
    finally:
        response.close()
    return b"".join(chunks)


def fetch_release_observation(family: FamilyPin, token: str | None) -> dict[str, Any]:
    """Fetch release metadata and require every locked identity field to agree."""
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "SimCairn-real-reference-replay/1",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    response, redirected = _open_verified(
        family.release.api_url,
        headers,
        initial_hosts=frozenset({_API_HOST}),
        redirect_hosts=frozenset(),
        redirects=0,
    )
    if redirected:
        response.close()
        raise ReplayPreparationError("release metadata unexpectedly redirected")
    raw = _load_json_bytes(
        _read_response(response, _MAX_RELEASE_BYTES, "release metadata"), "release metadata"
    )
    if not isinstance(raw, Mapping):
        raise ReplayPreparationError("release metadata is not an object")
    expected_release: dict[str, object] = {
        "id": family.release.id,
        "tag_name": family.release.tag,
        "draft": family.release.draft,
        "prerelease": family.release.prerelease,
        "immutable": family.release.immutable,
    }
    for field, expected in expected_release.items():
        if raw.get(field) != expected or type(raw.get(field)) is not type(expected):
            raise ReplayPreparationError(f"release metadata field {field} differs from its lock")
    raw_assets = raw.get("assets")
    if not isinstance(raw_assets, list):
        raise ReplayPreparationError("release metadata assets is not an array")
    ids: set[int] = set()
    names: set[str] = set()
    by_id: dict[int, Mapping[str, Any]] = {}
    for raw_asset in raw_assets:
        if not isinstance(raw_asset, Mapping):
            raise ReplayPreparationError("release metadata contains a non-object asset")
        asset_id = raw_asset.get("id")
        asset_name = raw_asset.get("name")
        if isinstance(asset_id, bool) or not isinstance(asset_id, int):
            raise ReplayPreparationError("release asset has an invalid ID")
        if not isinstance(asset_name, str) or not asset_name:
            raise ReplayPreparationError("release asset has an invalid name")
        if asset_id in ids or asset_name.casefold() in names:
            raise ReplayPreparationError("release metadata contains duplicate asset identities")
        ids.add(asset_id)
        names.add(asset_name.casefold())
        by_id[asset_id] = cast(Mapping[str, Any], raw_asset)
    observations: list[dict[str, object]] = []
    for asset in family.assets:
        observed = by_id.get(asset.id)
        if observed is None:
            raise ReplayPreparationError(
                f"locked asset is absent from release metadata: {asset.name}"
            )
        expected_asset: dict[str, object] = {
            "id": asset.id,
            "name": asset.name,
            "url": asset.api_url,
            "content_type": asset.content_type,
            "state": "uploaded",
            "size": asset.bytes,
            "digest": f"sha256:{asset.sha256}",
        }
        for field, expected in expected_asset.items():
            if observed.get(field) != expected or type(observed.get(field)) is not type(expected):
                raise ReplayPreparationError(
                    f"release asset {asset.name} field {field} differs from its lock"
                )
        observations.append(expected_asset)
    return {
        "id": family.release.id,
        "tag": family.release.tag,
        "draft": family.release.draft,
        "prerelease": family.release.prerelease,
        "immutable": family.release.immutable,
        "assets": observations,
    }


def fetch_repository_observation(inventory: ReplayInventory, token: str | None) -> dict[str, Any]:
    """Bind the owner/name route to the independently locked repository ID."""
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "SimCairn-real-reference-replay/1",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url = f"https://api.github.com/repositories/{inventory.release_repository_id}"
    response, redirected = _open_verified(
        url,
        headers,
        initial_hosts=frozenset({_API_HOST}),
        redirect_hosts=frozenset(),
        redirects=0,
    )
    if redirected:
        response.close()
        raise ReplayPreparationError("repository metadata unexpectedly redirected")
    raw = _load_json_bytes(
        _read_response(response, _MAX_RELEASE_BYTES, "repository metadata"),
        "repository metadata",
    )
    if not isinstance(raw, Mapping):
        raise ReplayPreparationError("repository metadata is not an object")
    expected: dict[str, object] = {
        "id": inventory.release_repository_id,
        "full_name": _REPOSITORY,
        "archived": False,
    }
    for field, value in expected.items():
        if raw.get(field) != value or type(raw.get(field)) is not type(value):
            raise ReplayPreparationError(f"repository metadata field {field} differs from its lock")
    return expected


def _content_length(response: _Response, expected: int) -> None:
    raw = _header(response, "Content-Length")
    if raw is None:
        return
    try:
        length = int(raw)
    except ValueError as error:
        raise ReplayPreparationError("HTTP Content-Length is invalid") from error
    if length != expected:
        raise ReplayPreparationError("HTTP Content-Length differs from the locked size")


def download_exact(
    url: str,
    destination: Path,
    *,
    expected_bytes: int,
    expected_sha256: str,
    headers: Mapping[str, str],
    initial_hosts: frozenset[str],
    redirect_hosts: frozenset[str],
    redirects: int,
) -> DownloadObservation:
    """Download one bounded body once, with at most one manually checked redirect."""
    if expected_bytes <= 0 or expected_bytes > _MAX_ASSET_BYTES:
        raise ReplayPreparationError("locked download size is outside the supported range")
    _digest(expected_sha256, "locked download SHA-256")
    _safe_output_path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    _safe_output_path(destination)
    response, redirected = _open_verified(
        url,
        headers,
        initial_hosts=initial_hosts,
        redirect_hosts=redirect_hosts,
        redirects=redirects,
    )
    digest = hashlib.sha256()
    count = 0
    final_url = response.geturl()
    staging: Path | None = None
    staging_identity: _PathIdentity | None = None
    published_identity: _PathIdentity | None = None
    descriptor = -1
    try:
        _content_length(response, expected_bytes)
        descriptor, staging_name = tempfile.mkstemp(
            prefix=f".{destination.name}.download-", dir=destination.parent
        )
        staging = Path(staging_name)
        staging_identity = _path_identity(staging)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            while True:
                block = response.read(min(_CHUNK, expected_bytes - count + 1))
                if not block:
                    break
                count += len(block)
                if count > expected_bytes:
                    raise ReplayPreparationError("download exceeds the locked size")
                digest.update(block)
                stream.write(block)
            stream.flush()
            os.fsync(stream.fileno())
        actual = digest.hexdigest()
        if count != expected_bytes or actual != expected_sha256:
            raise ReplayPreparationError("download size or SHA-256 differs from its lock")
        host = urlsplit(final_url).hostname
        if host is None:  # pragma: no cover - verified HTTPS URL invariant
            raise ReplayPreparationError("download response has no final host")
        try:
            os.link(staging, destination)
        except FileExistsError as error:
            raise ReplayPreparationError(
                "download destination appeared during publication"
            ) from error
        except OSError as error:
            raise ReplayPreparationError(
                f"cannot publish verified download without clobbering: {error}"
            ) from error
        published_identity = staging_identity
        staging.unlink()
        staging = None
        return DownloadObservation(count, actual, host, redirected, published_identity)
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        _remove_owned_file(destination, published_identity)
        raise
    finally:
        response.close()
        if staging is not None:
            _remove_owned_file(staging, staging_identity)


def _is_link_or_junction(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(is_junction is not None and is_junction())


def _safe_output_path(path: Path) -> None:
    absolute = path.absolute()
    if absolute.exists() or absolute.is_symlink():
        raise ReplayPreparationError(f"refusing to overwrite destination: {absolute.name}")
    for ancestor in absolute.parents:
        if ancestor.exists() and _is_link_or_junction(ancestor):
            raise ReplayPreparationError("destination path traverses a link or junction")


def _archive_name(raw: str, *, directory: bool) -> PurePosixPath:
    name = raw[:-1] if directory and raw.endswith("/") else raw
    if (
        not name
        or "\\" in name
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
        or PureWindowsPath(name).drive
    ):
        raise ReplayPreparationError("archive contains a non-portable member path")
    try:
        encoded_name = name.encode("utf-8")
    except UnicodeError as error:
        raise ReplayPreparationError("archive member path is not valid UTF-8 text") from error
    if unicodedata.normalize("NFC", name) != name:
        raise ReplayPreparationError("archive member path is not Unicode-normalized")
    path = PurePosixPath(name)
    if not path.parts or path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ReplayPreparationError("archive contains a path traversal or absolute path")
    if path.as_posix() != name:
        raise ReplayPreparationError("archive contains a non-canonical member path")
    if len(encoded_name) > _MAX_TAR_PATH_BYTES:
        raise ReplayPreparationError("archive member path exceeds the supported length")
    return path


def _path_key(path: PurePosixPath) -> tuple[str, ...]:
    return tuple(unicodedata.normalize("NFC", part).casefold() for part in path.parts)


def _conflicts_with_locked_path(path: PurePosixPath, info: tarfile.TarInfo, pin: MemberPin) -> bool:
    observed = _path_key(path)
    locked = _path_key(PurePosixPath(pin.path))
    if observed == locked:
        return path.as_posix() != pin.path
    shorter, longer = (observed, locked) if len(observed) < len(locked) else (locked, observed)
    if longer[: len(shorter)] != shorter:
        return False
    # Directory ancestors of a selected file are expected. Every other prefix
    # relation could change what the selected output resolves to.
    return not (info.isdir() and len(observed) < len(locked))


def _is_sparse(info: tarfile.TarInfo) -> bool:
    sparse_type = getattr(tarfile, "GNUTYPE_SPARSE", b"S")
    sparse_map = getattr(info, "sparse", None)
    return bool(
        info.type == sparse_type
        or sparse_map is not None
        or any(key.startswith("GNU.sparse") for key in info.pax_headers)
    )


def _scan_tar(stream: BinaryIO, members: Sequence[MemberPin]) -> None:
    stream.seek(0)
    locked = {member.path: member for member in members}
    found: set[str] = set()
    observed_paths: dict[tuple[str, ...], str] = {}
    file_paths: set[tuple[str, ...]] = set()
    parent_paths: set[tuple[str, ...]] = set()
    member_count = 0
    content_bytes = 0
    try:
        with tarfile.open(fileobj=stream, mode="r:") as archive:
            for info in archive:
                member_count += 1
                if member_count > _MAX_TAR_MEMBERS:
                    raise ReplayPreparationError("archive contains too many members")
                path = _archive_name(info.name, directory=info.isdir())
                folded = _path_key(path)
                if folded in observed_paths:
                    raise ReplayPreparationError(
                        "archive contains duplicate or case-colliding member paths"
                    )
                for index in range(1, len(folded)):
                    if folded[:index] in file_paths:
                        raise ReplayPreparationError(
                            "archive contains a file/directory prefix collision"
                        )
                    parent_paths.add(folded[:index])
                if not info.isdir() and folded in parent_paths:
                    raise ReplayPreparationError(
                        "archive contains a file/directory prefix collision"
                    )
                if _is_sparse(info):
                    raise ReplayPreparationError(f"archive contains a sparse member: {info.name}")
                if not info.isdir() and not info.isreg():
                    raise ReplayPreparationError(
                        f"archive contains a link or special member: {info.name}"
                    )
                if info.isreg():
                    content_bytes += info.size
                    if content_bytes > _MAX_TAR_BYTES:
                        raise ReplayPreparationError(
                            "archive member content exceeds the supported total"
                        )
                observed_paths[folded] = path.as_posix()
                if not info.isdir():
                    file_paths.add(folded)
                for locked_pin in members:
                    if _conflicts_with_locked_path(path, info, locked_pin):
                        raise ReplayPreparationError(
                            f"archive path collides with locked member: {info.name}"
                        )
                selected = locked.get(path.as_posix())
                if selected is None:
                    continue
                if info.size != selected.bytes or info.size > _MAX_MEMBER_BYTES:
                    raise ReplayPreparationError(
                        f"locked archive member has wrong size: {selected.path}"
                    )
                found.add(selected.path)
    except (ReplayPreparationError, tarfile.TarError, OSError) as error:
        if isinstance(error, ReplayPreparationError):
            raise
        raise ReplayPreparationError(f"cannot scan archive: {error}") from error
    missing = sorted(set(locked) - found)
    if missing:
        raise ReplayPreparationError(f"archive is missing locked members: {missing}")


def _materialize_tar(
    stream: BinaryIO, members: Sequence[MemberPin], destination: Path
) -> list[dict[str, object]]:
    stream.seek(0)
    locked = {member.path: member for member in members}
    observations: list[dict[str, object]] = []
    destination.mkdir(parents=True)
    try:
        with tarfile.open(fileobj=stream, mode="r:") as archive:
            for info in archive:
                path = _archive_name(info.name, directory=info.isdir())
                selected = locked.get(path.as_posix())
                if selected is None:
                    continue
                if not info.isreg() or _is_sparse(info):  # pragma: no cover - scan invariant
                    raise ReplayPreparationError(
                        f"locked archive member is not regular: {selected.path}"
                    )
                source = archive.extractfile(info)
                if source is None:  # pragma: no cover - tarfile regular-file invariant
                    raise ReplayPreparationError(
                        f"cannot read locked archive member: {selected.path}"
                    )
                target = destination.joinpath(*path.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                digest = hashlib.sha256()
                count = 0
                with source, target.open("xb") as output:
                    while True:
                        block = source.read(min(_CHUNK, selected.bytes - count + 1))
                        if not block:
                            break
                        count += len(block)
                        if count > selected.bytes:  # pragma: no cover - scan/tarfile invariant
                            raise ReplayPreparationError(
                                f"locked archive member exceeds its size: {selected.path}"
                            )
                        digest.update(block)
                        output.write(block)
                    output.flush()
                    os.fsync(output.fileno())
                actual = digest.hexdigest()
                if count != selected.bytes or actual != selected.sha256:
                    raise ReplayPreparationError(
                        f"locked archive member size or SHA-256 differs: {selected.path}"
                    )
                target.chmod(0o644)
                observations.append({"path": selected.path, "bytes": count, "sha256": actual})
    except BaseException as error:
        shutil.rmtree(destination, ignore_errors=True)
        if isinstance(error, ReplayPreparationError):
            raise
        if isinstance(error, (tarfile.TarError, OSError, UnicodeError)):
            raise ReplayPreparationError(f"cannot materialize archive: {error}") from error
        raise
    return sorted(observations, key=lambda item: cast(str, item["path"]))


def _extract_validated_tar(
    stream: BinaryIO, members: Sequence[MemberPin], destination: Path
) -> list[dict[str, object]]:
    if destination.exists() or destination.is_symlink():
        raise ReplayPreparationError("archive staging destination already exists")
    _safe_output_path(destination)
    _no_path_collisions(members)
    _scan_tar(stream, members)
    return _materialize_tar(stream, members, destination)


def extract_selected_tar_stream(
    stream: BinaryIO, members: Sequence[MemberPin], destination: Path
) -> list[dict[str, object]]:
    """Authenticate the full tar shape before materializing locked regular files."""
    with tempfile.TemporaryFile(mode="w+b") as raw_tar:
        count = 0
        while block := stream.read(_CHUNK):
            count += len(block)
            if count > _MAX_TAR_BYTES:
                raise ReplayPreparationError("raw tar stream exceeds the supported limit")
            raw_tar.write(block)
        raw_tar.flush()
        return _extract_validated_tar(cast(BinaryIO, raw_tar), members, destination)


class _BoundedDigestReader:
    def __init__(self, stream: BinaryIO, expected_bytes: int, expected_sha256: str) -> None:
        self._stream = stream
        self._expected_bytes = expected_bytes
        self._expected_sha256 = expected_sha256
        self._count = 0
        self._digest = hashlib.sha256()

    def read(self, size: int = -1) -> bytes:
        remaining_with_sentinel = self._expected_bytes - self._count + 1
        requested = (
            min(_CHUNK, remaining_with_sentinel) if size < 0 else min(size, remaining_with_sentinel)
        )
        data = self._stream.read(requested)
        self._count += len(data)
        if self._count > self._expected_bytes:
            raise ReplayPreparationError("decompressed tar stream exceeds its locked size")
        self._digest.update(data)
        return data

    def verify_to_eof(self) -> None:
        while self.read(_CHUNK):
            pass
        if self._count != self._expected_bytes or self._digest.hexdigest() != self._expected_sha256:
            raise ReplayPreparationError("decompressed tar size or SHA-256 differs from its lock")


def _extract_zstd_archive(
    archive_path: Path,
    asset: AssetPin,
    destination: Path,
    zstd: Path,
) -> list[dict[str, object]]:
    if not zstd.is_absolute() or not zstd.is_file() or _is_link_or_junction(zstd):
        raise ReplayPreparationError("zstd must be an absolute regular executable path")
    try:
        subprocess_environment = {
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": os.defpath,
            "TZ": "UTC",
        }
        if system_root := os.environ.get("SYSTEMROOT"):
            subprocess_environment["SYSTEMROOT"] = system_root
        process = subprocess.Popen(  # nosec B603
            [str(zstd), "--decompress", "--stdout", "--quiet", "--", str(archive_path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=subprocess_environment,
        )
    except OSError as error:
        raise ReplayPreparationError(f"cannot start zstd: {error}") from error
    if process.stdout is None or process.stderr is None:
        process.kill()
        process.wait()
        raise ReplayPreparationError("zstd streams are unavailable")
    process_stdout = cast(BinaryIO, process.stdout)
    process_stderr = cast(BinaryIO, process.stderr)
    stderr_bytes = bytearray()
    stderr_overflow = [False]

    def consume_stderr() -> None:
        while block := process_stderr.read(4096):
            remaining = 64 * 1024 - len(stderr_bytes)
            if remaining > 0:
                stderr_bytes.extend(block[:remaining])
            if len(block) > remaining:
                stderr_overflow[0] = True

    stderr_thread = threading.Thread(target=consume_stderr, daemon=True)
    stderr_thread.start()
    watchdog_stop = threading.Event()
    watchdog_expired = threading.Event()

    def enforce_deadline() -> None:
        if watchdog_stop.wait(_ZSTD_TIMEOUT_SECONDS):
            return
        if process.poll() is None:
            watchdog_expired.set()
            with suppress(OSError):
                process.kill()

    watchdog = threading.Thread(target=enforce_deadline, daemon=True)
    watchdog.start()
    reader = _BoundedDigestReader(process_stdout, asset.tar_bytes, asset.tar_sha256)
    try:
        with tempfile.TemporaryFile(mode="w+b") as raw_tar:
            while block := reader.read(_CHUNK):
                raw_tar.write(block)
            reader.verify_to_eof()
            raw_tar.flush()
            process_stdout.close()
            try:
                return_code = process.wait(timeout=30)
            except subprocess.TimeoutExpired as error:
                watchdog_expired.set()
                process.kill()
                process.wait()
                raise ReplayPreparationError(
                    "zstd did not exit after closing its output"
                ) from error
            watchdog_stop.set()
            watchdog.join(timeout=30)
            stderr_thread.join(timeout=30)
            if watchdog.is_alive() or stderr_thread.is_alive():
                raise ReplayPreparationError("zstd supervision threads did not terminate")
            if watchdog_expired.is_set():
                raise ReplayPreparationError("zstd exceeded the decompression time limit")
            if stderr_overflow[0]:
                raise ReplayPreparationError("zstd diagnostics exceed the supported limit")
            if return_code != 0:
                message = bytes(stderr_bytes).decode("utf-8", errors="replace").strip()
                raise ReplayPreparationError(f"zstd failed with status {return_code}: {message}")
            raw_tar.seek(0)
            return _extract_validated_tar(cast(BinaryIO, raw_tar), asset.members, destination)
    except BaseException as error:
        process_stdout.close()
        if process.poll() is None:
            with suppress(OSError):
                process.kill()
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=30)
        watchdog_stop.set()
        watchdog.join(timeout=30)
        stderr_thread.join(timeout=30)
        if watchdog_expired.is_set():
            raise ReplayPreparationError("zstd exceeded the decompression time limit") from error
        raise
    finally:
        watchdog_stop.set()
        watchdog.join(timeout=30)
        process_stderr.close()


def _write_json(path: Path, value: object) -> _PathIdentity:
    _safe_output_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _safe_output_path(path)
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    identity: _PathIdentity | None = None
    try:
        with path.open("x", encoding="ascii", newline="\n") as stream:
            identity = _path_identity(path)
            stream.write(encoded)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        _remove_owned_file(path, identity)
        raise
    if identity is None:  # pragma: no cover - successful exclusive-open invariant
        raise ReplayPreparationError("evidence output identity is unavailable")
    return identity


def _publish_tree_no_clobber(
    source: Path, target: Path, members: Sequence[MemberPin]
) -> _PathIdentity:
    _safe_output_path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    _safe_output_path(target)
    try:
        target.mkdir()
    except FileExistsError as error:
        raise ReplayPreparationError("PDK target appeared during publication") from error
    identity = _path_identity(target)
    try:
        for member in sorted(members, key=lambda item: item.path):
            relative = PurePosixPath(member.path)
            relative = relative.relative_to(relative.parts[0])
            input_path = source.joinpath(*relative.parts)
            output_path = target.joinpath(*relative.parts)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256()
            count = 0
            with input_path.open("rb") as input_stream, output_path.open("xb") as output_stream:
                while block := input_stream.read(_CHUNK):
                    count += len(block)
                    if count > member.bytes:
                        raise ReplayPreparationError("verified member changed before publication")
                    digest.update(block)
                    output_stream.write(block)
            if count != member.bytes or digest.hexdigest() != member.sha256:
                raise ReplayPreparationError("verified member changed before publication")
    except BaseException:
        _remove_owned_tree(target, identity)
        raise
    return identity


def prepare_ciel_family(
    inventory_path: str | Path,
    family_name: str,
    *,
    pdk_base: str | Path,
    download_directory: str | Path,
    decision_output: str | Path,
    evidence_output: str | Path,
    zstd: str | Path = "/usr/bin/zstd",
    github_token: str | None = None,
) -> Path:
    """Acquire, authenticate, and selectively materialize one Ciel family."""
    inventory = load_replay_inventory(inventory_path)
    if family_name not in inventory.families:
        raise ReplayPreparationError(f"unsupported Ciel family: {family_name}")
    family = inventory.families[family_name]
    pdk_base_path = Path(pdk_base).absolute()
    download_path = Path(download_directory).absolute()
    decision_path = Path(decision_output).absolute()
    evidence_path = Path(evidence_output).absolute()
    target = pdk_base_path / "versions" / inventory.revision / family.variant
    _safe_output_path(target)
    _safe_output_path(decision_path)
    _safe_output_path(evidence_path)
    for directory in (pdk_base_path, download_path):
        if directory.exists() and _is_link_or_junction(directory):
            raise ReplayPreparationError("working directory must not be a link or junction")
        directory.mkdir(parents=True, exist_ok=True)
    repository_observation = fetch_repository_observation(inventory, github_token)
    release_observation = fetch_release_observation(family, github_token)
    headers = {
        "Accept": "application/octet-stream",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "SimCairn-real-reference-replay/1",
    }
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"
    staging = Path(tempfile.mkdtemp(prefix=f".ciel-{family.name}-", dir=pdk_base_path))
    archive_observations: list[dict[str, object]] = []
    published_identity: _PathIdentity | None = None
    decision_identity: _PathIdentity | None = None
    evidence_identity: _PathIdentity | None = None
    downloaded: list[tuple[Path, _PathIdentity]] = []
    try:
        for asset in family.assets:
            archive_path = download_path / f"{family.name}-{asset.name}"
            observed = download_exact(
                asset.api_url,
                archive_path,
                expected_bytes=asset.bytes,
                expected_sha256=asset.sha256,
                headers=headers,
                initial_hosts=frozenset({_API_HOST}),
                redirect_hosts=_ASSET_REDIRECT_HOSTS,
                redirects=1,
            )
            if observed._identity is None:  # pragma: no cover - download_exact invariant
                raise ReplayPreparationError("download ownership identity is unavailable")
            downloaded.append((archive_path, observed._identity))
            asset_stage = staging / f"asset-{asset.id}"
            extracted = _extract_zstd_archive(archive_path, asset, asset_stage, Path(zstd))
            if asset.members:
                for member in asset.members:
                    source = asset_stage.joinpath(*PurePosixPath(member.path).parts)
                    relative = PurePosixPath(member.path).relative_to(family.variant)
                    destination = staging / "merged" / family.variant
                    destination = destination.joinpath(*relative.parts)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    source.replace(destination)
            shutil.rmtree(asset_stage)
            archive_observations.append(
                {
                    "id": asset.id,
                    "name": asset.name,
                    "bytes": observed.bytes,
                    "sha256": observed.sha256,
                    "tar_bytes": asset.tar_bytes,
                    "tar_sha256": asset.tar_sha256,
                    "final_host": observed.final_host,
                    "redirected": observed.redirected,
                    "members": extracted,
                }
            )
        decision_headers = {"User-Agent": "SimCairn-real-reference-replay/1"}
        decision_observation = download_exact(
            inventory.decision.url,
            decision_path,
            expected_bytes=inventory.decision.bytes,
            expected_sha256=inventory.decision.sha256,
            headers=decision_headers,
            initial_hosts=_RAW_HOSTS,
            redirect_hosts=_RAW_HOSTS,
            redirects=1,
        )
        if decision_observation._identity is None:  # pragma: no cover - download_exact invariant
            raise ReplayPreparationError("decision ownership identity is unavailable")
        decision_identity = decision_observation._identity
        decision = load_sizing_decision(
            decision_path,
            expected_topology=inventory.decision.topology,
            expected_signature=inventory.decision.signature,
            expected_decision_sha256=inventory.decision.decision_sha256,
            expected_benchmark_sha256=inventory.decision.benchmark_sha256,
            expected_comparison_sha256=inventory.decision.comparison_sha256,
        )
        merged_variant = staging / "merged" / family.variant
        expected_files = {member.path for asset in family.assets for member in asset.members}
        actual_files = {
            path.relative_to(staging / "merged").as_posix()
            for path in (staging / "merged").rglob("*")
            if path.is_file()
        }
        if actual_files != expected_files:
            raise ReplayPreparationError("materialized PDK file set differs from the allowlist")
        all_member_pins = tuple(member for asset in family.assets for member in asset.members)
        published_identity = _publish_tree_no_clobber(merged_variant, target, all_member_pins)
        evidence = {
            "schema": "org.simcairn.ciel-replay-evidence",
            "version": 1,
            "inventory_sha256": inventory.sha256,
            "family": family.name,
            "variant": family.variant,
            "revision": inventory.revision,
            "repository": repository_observation,
            "release": release_observation,
            "assets": archive_observations,
            "decision": {
                "bytes": decision_observation.bytes,
                "sha256": decision_observation.sha256,
                "final_host": decision_observation.final_host,
                "redirected": decision_observation.redirected,
                "decision_sha256": decision.digest,
                "topology": decision.topology_id,
                "signature": decision.topology_signature,
            },
            "license": dict(family.license),
            "pdk_root": f"versions/{inventory.revision}/{family.variant}",
        }
        evidence_identity = _write_json(evidence_path, evidence)
        return target
    except BaseException:
        _remove_owned_tree(target, published_identity)
        _remove_owned_file(decision_path, decision_identity)
        _remove_owned_file(evidence_path, evidence_identity)
        raise
    finally:
        shutil.rmtree(staging, ignore_errors=True)
        for path, identity in downloaded:
            _remove_owned_file(path, identity)


__all__ = [
    "AssetPin",
    "DecisionPin",
    "DownloadObservation",
    "FamilyPin",
    "MemberPin",
    "ReleasePin",
    "ReplayInventory",
    "ReplayPin",
    "ReplayPreparationError",
    "download_exact",
    "extract_selected_tar_stream",
    "fetch_release_observation",
    "fetch_repository_observation",
    "load_replay_inventory",
    "prepare_ciel_family",
]
