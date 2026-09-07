from __future__ import annotations

import hashlib
import io
import json
import tarfile
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.request import Request

import pytest

from simcairn import pdk_replay
from simcairn.pdk_replay import (
    AssetPin,
    DecisionPin,
    DownloadObservation,
    FamilyPin,
    MemberPin,
    ReleasePin,
    ReplayInventory,
    ReplayPreparationError,
    download_exact,
    extract_selected_tar_stream,
    fetch_release_observation,
    fetch_repository_observation,
    load_replay_inventory,
    prepare_ciel_family,
)

ROOT = Path(__file__).parents[1]
INVENTORY = ROOT / "benchmarks" / "ciel-assets.json"


class FakeResponse:
    def __init__(
        self,
        url: str,
        body: bytes = b"",
        *,
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status = status
        self.headers = {} if headers is None else headers
        self._url = url
        self._stream = io.BytesIO(body)
        self.closed = False

    def read(self, size: int = -1) -> bytes:
        return self._stream.read(size)

    def close(self) -> None:
        self.closed = True

    def geturl(self) -> str:
        return self._url


def _tar(entries: list[tuple[str, bytes, bytes | None]]) -> bytes:
    """Build name/data/type entries; None type means a regular file."""
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name, data, type_code in entries:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            if type_code is not None:
                info.type = type_code
                if type_code in {tarfile.SYMTYPE, tarfile.LNKTYPE}:
                    info.linkname = "target"
            archive.addfile(info, io.BytesIO(data) if info.isreg() else None)
    return stream.getvalue()


def _member(name: str, content: bytes) -> MemberPin:
    return MemberPin(name, len(content), hashlib.sha256(content).hexdigest())


def test_committed_inventory_is_wheel_anchored_and_complete() -> None:
    inventory = load_replay_inventory(INVENTORY)
    assert inventory.sha256 == pdk_replay.LOCKED_INVENTORY_SHA256
    assert inventory.release_repository_id == 966850989
    assert set(inventory.families) == {"gf180", "sky130"}
    assert set(inventory.replays) == {"gf180", "rc", "sky130"}
    assert [asset.id for asset in inventory.families["sky130"].assets] == [
        532551086,
        532554533,
    ]
    assert inventory.families["gf180"].assets[0].tar_bytes == 733143040
    assert inventory.decision.bytes == 1158


def test_inventory_rejects_content_drift_before_trusting_fields(tmp_path: Path) -> None:
    payload = INVENTORY.read_bytes().replace(b'"version": 1', b'"version": 2', 1)
    path = tmp_path / "drifted.json"
    path.write_bytes(payload)
    with pytest.raises(ReplayPreparationError, match="wheel-embedded"):
        load_replay_inventory(path)


@pytest.mark.parametrize(
    ("replacement", "message"),
    [
        (b'"version": 1,\n  "version": 1,', "duplicate"),
        (b'"version": NaN,', "non-finite"),
    ],
)
def test_inventory_strict_json_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replacement: bytes,
    message: str,
) -> None:
    payload = INVENTORY.read_bytes().replace(b'"version": 1,', replacement, 1)
    monkeypatch.setattr(pdk_replay, "LOCKED_INVENTORY_SHA256", hashlib.sha256(payload).hexdigest())
    path = tmp_path / "invalid.json"
    path.write_bytes(payload)
    with pytest.raises(ReplayPreparationError, match=message):
        load_replay_inventory(path)


def test_inventory_rejects_excessive_json_depth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = ("[" * 65 + "]" * 65).encode()
    monkeypatch.setattr(pdk_replay, "LOCKED_INVENTORY_SHA256", hashlib.sha256(payload).hexdigest())
    path = tmp_path / "deep.json"
    path.write_bytes(payload)
    with pytest.raises(ReplayPreparationError, match="maximum JSON depth"):
        load_replay_inventory(path)


def _mutated_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    key_path: tuple[str | int, ...],
    value: object,
) -> Path:
    document: Any = json.loads(INVENTORY.read_text(encoding="utf-8"))
    current = document
    for key in key_path[:-1]:
        current = current[key]
    current[key_path[-1]] = value
    payload = (json.dumps(document, indent=2) + "\n").encode()
    monkeypatch.setattr(
        pdk_replay,
        "LOCKED_INVENTORY_SHA256",
        hashlib.sha256(payload).hexdigest(),
    )
    path = tmp_path / "mutated.json"
    path.write_bytes(payload)
    return path


@pytest.mark.parametrize(
    ("key_path", "value", "message"),
    [
        (("schema",), "other", "schema or version"),
        (("release_repository",), "https://github.com/other/repository", "official Ciel"),
        (("release_repository_id",), 1, "locked Ciel repository ID"),
        (("families", "sky130", "variant"), "other", "supported variant"),
        (("families", "sky130", "release", "tag"), "sky130-other", "revision"),
        (
            ("families", "sky130", "release", "api_url"),
            "https://api.github.com/repos/fossi-foundation/ciel-releases/releases/tags/other",
            "match its tag",
        ),
        (("families", "sky130", "assets"), [], "exactly two"),
        (("families", "sky130", "license", "spdx"), "MIT", "not Apache"),
        (
            ("decision", "url"),
            "https://raw.githubusercontent.com/appleweiping/BiasWeave/main/benchmarks/decision.json",
            "exact Git commit",
        ),
        (("replays", "rc", "observation_path"), [], "observation_path"),
        (("families", "sky130", "assets", 0, "name"), "nested/file.zst", "one filename"),
        (
            ("families", "sky130", "assets", 0, "api_url"),
            "https://api.github.com/repos/fossi-foundation/ciel-releases/releases/assets/1",
            "match its asset ID",
        ),
        (("families", "sky130", "assets", 0, "members"), {}, "must be an array"),
        (("families", "sky130", "assets", 0, "content_type"), "text/plain", "application/zstd"),
        (
            ("families", "sky130", "assets", 0, "members", 0, "path"),
            "other/model.spice",
            "outside the locked PDK variant",
        ),
    ],
)
def test_inventory_rejects_semantic_lock_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    key_path: tuple[str | int, ...],
    value: object,
    message: str,
) -> None:
    path = _mutated_inventory(tmp_path, monkeypatch, key_path, value)
    with pytest.raises(ReplayPreparationError, match=message):
        load_replay_inventory(path)


def test_inventory_rejects_duplicate_asset_identities(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    document: Any = json.loads(INVENTORY.read_text(encoding="utf-8"))
    first, second = document["families"]["sky130"]["assets"]
    second["id"] = first["id"]
    second["name"] = first["name"]
    second["api_url"] = first["api_url"]
    payload = (json.dumps(document, indent=2) + "\n").encode()
    monkeypatch.setattr(
        pdk_replay,
        "LOCKED_INVENTORY_SHA256",
        hashlib.sha256(payload).hexdigest(),
    )
    path = tmp_path / "duplicate.json"
    path.write_bytes(payload)
    with pytest.raises(ReplayPreparationError, match="duplicate identities"):
        load_replay_inventory(path)


@pytest.mark.parametrize(
    ("function", "value", "message"),
    [
        (pdk_replay._string, "", "non-empty string"),
        (pdk_replay._integer, True, "positive integer"),
        (pdk_replay._digest, "A" * 64, "lowercase SHA-256"),
        (pdk_replay._revision, "a" * 39, "40-character revision"),
        (pdk_replay._boolean, 1, "Boolean"),
        (pdk_replay._safe_relative, "C:/model", "portable relative"),
    ],
)
def test_lock_primitive_validators_fail_closed(function: Any, value: object, message: str) -> None:
    with pytest.raises(ReplayPreparationError, match=message):
        function(value, "field")


@pytest.mark.parametrize(
    "url",
    [
        "http://api.github.com/value",
        "https://user@api.github.com/value",
        "https://api.github.com:444/value",
        "https://api.github.com/value#fragment",
        "https://api.github.com:not-a-port/value",
    ],
)
def test_https_url_rejects_ambiguous_or_untrusted_authority(url: str) -> None:
    with pytest.raises(ReplayPreparationError, match=r"allowed HTTPS|invalid port"):
        pdk_replay._https_url(url, "URL", hosts=frozenset({"api.github.com"}))


def test_inventory_reader_bounds_io_and_parse_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(ReplayPreparationError, match="cannot read"):
        pdk_replay._bounded_file(tmp_path / "missing", 1, "fixture")
    oversized = tmp_path / "oversized"
    oversized.write_bytes(b"ab")
    with pytest.raises(ReplayPreparationError, match="exceeds"):
        pdk_replay._bounded_file(oversized, 1, "fixture")
    payload = b"}"
    monkeypatch.setattr(
        pdk_replay,
        "LOCKED_INVENTORY_SHA256",
        hashlib.sha256(payload).hexdigest(),
    )
    malformed = tmp_path / "malformed.json"
    malformed.write_bytes(payload)
    with pytest.raises(ReplayPreparationError, match=r"unbalanced|cannot parse"):
        load_replay_inventory(malformed)

    invalid_utf8 = b"\xff"
    monkeypatch.setattr(
        pdk_replay,
        "LOCKED_INVENTORY_SHA256",
        hashlib.sha256(invalid_utf8).hexdigest(),
    )
    malformed.write_bytes(invalid_utf8)
    with pytest.raises(ReplayPreparationError, match="cannot parse"):
        load_replay_inventory(malformed)


def test_low_level_lock_constraints_cover_limits_and_collisions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ReplayPreparationError, match="missing or unknown"):
        pdk_replay._exact({}, {"required"}, "fixture")
    with pytest.raises(ReplayPreparationError, match="supported limit"):
        pdk_replay._integer(2, "fixture", maximum=1)
    with pytest.raises(ReplayPreparationError, match="safe relative"):
        pdk_replay._safe_relative("/absolute", "fixture")
    with pytest.raises(ReplayPreparationError, match="canonical"):
        pdk_replay._safe_relative("parent//child", "fixture")

    first = _member("variant/model", b"a")
    duplicate = _member("VARIANT/MODEL", b"b")
    with pytest.raises(ReplayPreparationError, match="case-insensitively"):
        pdk_replay._no_path_collisions((first, duplicate))
    child = _member("variant/model/child", b"b")
    with pytest.raises(ReplayPreparationError, match="prefix collision"):
        pdk_replay._no_path_collisions((first, child))
    monkeypatch.setattr(pdk_replay, "_MAX_SELECTED_BYTES", 1)
    with pytest.raises(ReplayPreparationError, match="output limit"):
        pdk_replay._no_path_collisions((_member("variant/large", b"xx"),))
    assert pdk_replay._path_key(Path("caf\u00e9/model")) == pdk_replay._path_key(
        Path("cafe\u0301/model")
    )


@pytest.mark.parametrize(
    ("value", "message"),
    [
        (".", "traversal"),
        ("./", "traversal"),
        ("bad\x01name", "non-portable"),
        ("bad\x7fname", "non-portable"),
        ("cafe\u0301/model", "Unicode-normalized"),
        ("bad\ud800name", "valid UTF-8"),
    ],
)
def test_archive_path_rejects_root_control_non_nfc_and_surrogate(value: str, message: str) -> None:
    with pytest.raises(ReplayPreparationError, match=message):
        pdk_replay._archive_name(value, directory=value.endswith("/"))


@pytest.mark.parametrize(
    ("value", "message"),
    [
        (".", "safe relative"),
        ("bad\x01name", "portable relative"),
        ("bad\x7fname", "portable relative"),
        ("cafe\u0301/model", "Unicode-normalized"),
        ("bad\ud800name", "valid UTF-8"),
    ],
)
def test_locked_paths_reject_root_control_non_nfc_and_surrogate(value: str, message: str) -> None:
    with pytest.raises(ReplayPreparationError, match=message):
        pdk_replay._safe_relative(value, "locked path")


def test_http_helpers_handle_legacy_status_and_casefolded_headers() -> None:
    response = SimpleNamespace(
        status=None,
        code=200,
        headers={"content-length": "1"},
    )
    assert pdk_replay._status(response) == 200
    assert pdk_replay._header(response, "Content-Length") == "1"
    with pytest.raises(ReplayPreparationError, match="numeric status"):
        pdk_replay._status(SimpleNamespace(status=None, code=True))


def test_download_allows_one_explicit_redirect_and_strips_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = "https://api.github.com/repos/example/releases/assets/7"
    target = "https://release-assets.githubusercontent.com/signed-object"
    body = b"locked body"
    responses = [
        FakeResponse(source, status=302, headers={"Location": target}),
        FakeResponse(target, body, headers={"Content-Length": str(len(body))}),
    ]
    requests: list[Request] = []

    def fake_open(request: Request, _timeout: float) -> FakeResponse:
        requests.append(request)
        return responses.pop(0)

    monkeypatch.setattr(pdk_replay, "_open_once", fake_open)
    destination = tmp_path / "body"
    result = download_exact(
        source,
        destination,
        expected_bytes=len(body),
        expected_sha256=hashlib.sha256(body).hexdigest(),
        headers={"Authorization": "Bearer secret", "User-Agent": "test"},
        initial_hosts=frozenset({"api.github.com"}),
        redirect_hosts=frozenset({"release-assets.githubusercontent.com"}),
        redirects=1,
    )
    assert result == DownloadObservation(
        len(body), hashlib.sha256(body).hexdigest(), "release-assets.githubusercontent.com", True
    )
    assert destination.read_bytes() == body
    assert dict(requests[0].header_items()).get("Authorization") == "Bearer secret"
    assert "Authorization" not in dict(requests[1].header_items())


@pytest.mark.parametrize(
    ("headers", "status", "message"),
    [
        ({"Location": "/relative"}, 302, "relative"),
        ({"Location": "http://release-assets.githubusercontent.com/file"}, 302, "HTTPS"),
        ({"Location": "https://evil.example/file"}, 302, "allowed HTTPS"),
        ({"Content-Encoding": "gzip"}, 200, "content encoding"),
    ],
)
def test_http_transport_rejects_untrusted_response_shapes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    headers: dict[str, str],
    status: int,
    message: str,
) -> None:
    url = "https://api.github.com/repos/example/releases/assets/7"
    monkeypatch.setattr(
        pdk_replay,
        "_open_once",
        lambda _request, _timeout: FakeResponse(url, b"x", status=status, headers=headers),
    )
    with pytest.raises(ReplayPreparationError, match=message):
        download_exact(
            url,
            tmp_path / "body",
            expected_bytes=1,
            expected_sha256=hashlib.sha256(b"x").hexdigest(),
            headers={},
            initial_hosts=frozenset({"api.github.com"}),
            redirect_hosts=frozenset({"release-assets.githubusercontent.com"}),
            redirects=1,
        )


def test_http_transport_rejects_second_redirect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = "https://api.github.com/repos/example/releases/assets/7"
    target = "https://release-assets.githubusercontent.com/first"
    responses = [
        FakeResponse(source, status=302, headers={"Location": target}),
        FakeResponse(
            target,
            status=302,
            headers={"Location": "https://release-assets.githubusercontent.com/second"},
        ),
    ]
    monkeypatch.setattr(pdk_replay, "_open_once", lambda _request, _timeout: responses.pop(0))
    with pytest.raises(ReplayPreparationError, match="redirect target"):
        download_exact(
            source,
            tmp_path / "body",
            expected_bytes=1,
            expected_sha256=hashlib.sha256(b"x").hexdigest(),
            headers={},
            initial_hosts=frozenset({"api.github.com"}),
            redirect_hosts=frozenset({"release-assets.githubusercontent.com"}),
            redirects=1,
        )


@pytest.mark.parametrize(
    ("status", "response_url", "redirects", "headers", "message"),
    [
        (302, "source", 0, {"Location": "https://api.github.com/next"}, "unexpected HTTP redirect"),
        (302, "source", 1, {}, "no Location"),
        (500, "source", 0, {}, "unexpected HTTP status"),
        (200, "different", 0, {}, "unverified redirect"),
    ],
)
def test_http_transport_rejects_status_redirect_and_url_drift(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    response_url: str,
    redirects: int,
    headers: dict[str, str],
    message: str,
) -> None:
    source = "https://api.github.com/source"
    actual_url = source if response_url == "source" else "https://api.github.com/different"
    monkeypatch.setattr(
        pdk_replay,
        "_open_once",
        lambda _request, _timeout: FakeResponse(actual_url, status=status, headers=headers),
    )
    with pytest.raises(ReplayPreparationError, match=message):
        pdk_replay._open_verified(
            source,
            {},
            initial_hosts=frozenset({"api.github.com"}),
            redirect_hosts=frozenset({"api.github.com"}),
            redirects=redirects,
        )


def test_same_host_redirect_preserves_authorization_and_requires_exact_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = "https://api.github.com/source"
    target = "https://api.github.com/target"
    requests: list[Request] = []
    responses = [
        FakeResponse(source, status=302, headers={"location": target}),
        FakeResponse(target),
    ]

    def fake_open(request: Request, _timeout: float) -> FakeResponse:
        requests.append(request)
        return responses.pop(0)

    monkeypatch.setattr(pdk_replay, "_open_once", fake_open)
    response, redirected = pdk_replay._open_verified(
        source,
        {"Authorization": "Bearer same-host"},
        initial_hosts=frozenset({"api.github.com"}),
        redirect_hosts=frozenset({"api.github.com"}),
        redirects=1,
    )
    response.close()
    assert redirected
    assert dict(requests[1].header_items())["Authorization"] == "Bearer same-host"

    responses[:] = [
        FakeResponse(source, status=302, headers={"Location": target}),
        FakeResponse(source),
    ]
    with pytest.raises(ReplayPreparationError, match="unverified redirect"):
        pdk_replay._open_verified(
            source,
            {},
            initial_hosts=frozenset({"api.github.com"}),
            redirect_hosts=frozenset({"api.github.com"}),
            redirects=1,
        )


def test_download_publication_race_never_deletes_the_other_writer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = "https://raw.githubusercontent.com/example/revision/file"
    destination = tmp_path / "body"
    monkeypatch.setattr(
        pdk_replay,
        "_open_once",
        lambda _request, _timeout: FakeResponse(source, b"ours"),
    )

    def competing_link(_source: Path, target: Path) -> None:
        target.write_bytes(b"theirs")
        raise FileExistsError

    monkeypatch.setattr(pdk_replay.os, "link", competing_link)
    with pytest.raises(ReplayPreparationError, match="appeared during publication"):
        download_exact(
            source,
            destination,
            expected_bytes=4,
            expected_sha256=hashlib.sha256(b"ours").hexdigest(),
            headers={},
            initial_hosts=frozenset({"raw.githubusercontent.com"}),
            redirect_hosts=frozenset({"raw.githubusercontent.com"}),
            redirects=0,
        )
    assert destination.read_bytes() == b"theirs"
    assert not tuple(tmp_path.glob(".body.download-*"))


def test_bounded_http_body_and_content_length_reject_invalid_values() -> None:
    response = FakeResponse("https://api.github.com/value", b"xx")
    with pytest.raises(ReplayPreparationError, match="response limit"):
        pdk_replay._read_response(response, 1, "metadata")
    with pytest.raises(ReplayPreparationError, match="Content-Length is invalid"):
        pdk_replay._content_length(
            FakeResponse("https://api.github.com/value", headers={"Content-Length": "invalid"}),
            1,
        )


@pytest.mark.parametrize(
    ("body", "declared_length", "expected_sha", "message"),
    [
        (b"xx", None, hashlib.sha256(b"x").hexdigest(), "exceeds"),
        (b"x", "2", hashlib.sha256(b"x").hexdigest(), "Content-Length"),
        (b"x", None, "0" * 64, "size or SHA"),
        (b"", None, hashlib.sha256(b"x").hexdigest(), "size or SHA"),
    ],
)
def test_download_rejects_size_and_hash_drift_without_leaving_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    body: bytes,
    declared_length: str | None,
    expected_sha: str,
    message: str,
) -> None:
    url = "https://raw.githubusercontent.com/example/revision/file"
    headers = {} if declared_length is None else {"Content-Length": declared_length}
    monkeypatch.setattr(
        pdk_replay,
        "_open_once",
        lambda _request, _timeout: FakeResponse(url, body, headers=headers),
    )
    destination = tmp_path / "body"
    with pytest.raises(ReplayPreparationError, match=message):
        download_exact(
            url,
            destination,
            expected_bytes=1,
            expected_sha256=expected_sha,
            headers={},
            initial_hosts=frozenset({"raw.githubusercontent.com"}),
            redirect_hosts=frozenset({"raw.githubusercontent.com"}),
            redirects=0,
        )
    assert not destination.exists()


def test_download_rejects_invalid_locked_size_before_transport(tmp_path: Path) -> None:
    with pytest.raises(ReplayPreparationError, match="outside the supported range"):
        download_exact(
            "https://raw.githubusercontent.com/example/revision/file",
            tmp_path / "body",
            expected_bytes=0,
            expected_sha256="0" * 64,
            headers={},
            initial_hosts=frozenset({"raw.githubusercontent.com"}),
            redirect_hosts=frozenset({"raw.githubusercontent.com"}),
            redirects=0,
        )


def _release_payload(family: FamilyPin) -> bytes:
    assets = [
        {
            "id": asset.id,
            "name": asset.name,
            "url": asset.api_url,
            "browser_download_url": "https://ignored.invalid/by-design",
            "content_type": asset.content_type,
            "state": "uploaded",
            "size": asset.bytes,
            "digest": f"sha256:{asset.sha256}",
        }
        for asset in family.assets
    ]
    value = {
        "id": family.release.id,
        "tag_name": family.release.tag,
        "draft": family.release.draft,
        "prerelease": family.release.prerelease,
        "immutable": family.release.immutable,
        "assets": assets,
    }
    return json.dumps(value).encode()


def test_release_metadata_must_match_independent_asset_locks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    family = load_replay_inventory(INVENTORY).families["sky130"]
    body = _release_payload(family)
    monkeypatch.setattr(
        pdk_replay,
        "_open_once",
        lambda request, _timeout: FakeResponse(request.full_url, body),
    )
    observed = fetch_release_observation(family, "token")
    assert observed["id"] == 377963979
    assert observed["assets"][0]["size"] == 6593210
    assert "browser_download_url" not in observed["assets"][0]


def test_repository_metadata_binds_owner_route_to_numeric_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inventory = load_replay_inventory(INVENTORY)
    body = json.dumps(
        {
            "id": 966850989,
            "full_name": "fossi-foundation/ciel-releases",
            "archived": False,
        }
    ).encode()
    monkeypatch.setattr(
        pdk_replay,
        "_open_once",
        lambda request, _timeout: FakeResponse(request.full_url, body),
    )
    assert fetch_repository_observation(inventory, "token") == {
        "id": 966850989,
        "full_name": "fossi-foundation/ciel-releases",
        "archived": False,
    }


def test_repository_metadata_identity_drift_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inventory = load_replay_inventory(INVENTORY)
    body = json.dumps(
        {
            "id": 966850989,
            "full_name": "attacker/replacement",
            "archived": False,
        }
    ).encode()
    monkeypatch.setattr(
        pdk_replay,
        "_open_once",
        lambda request, _timeout: FakeResponse(request.full_url, body),
    )
    with pytest.raises(ReplayPreparationError, match="full_name"):
        fetch_repository_observation(inventory, None)


@pytest.mark.parametrize("field", ["size", "digest", "state", "name", "content_type"])
def test_release_metadata_drift_fails_closed(monkeypatch: pytest.MonkeyPatch, field: str) -> None:
    family = load_replay_inventory(INVENTORY).families["gf180"]
    value = json.loads(_release_payload(family))
    value["assets"][0][field] = "tampered"
    body = json.dumps(value).encode()
    monkeypatch.setattr(
        pdk_replay,
        "_open_once",
        lambda request, _timeout: FakeResponse(request.full_url, body),
    )
    with pytest.raises(ReplayPreparationError, match="differs from its lock"):
        fetch_release_observation(family, None)


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("not-object", "not an object"),
        ("release-field", "release metadata field id"),
        ("assets-not-array", "assets is not an array"),
        ("asset-not-object", "non-object asset"),
        ("invalid-id", "invalid ID"),
        ("invalid-name", "invalid name"),
        ("duplicate", "duplicate asset identities"),
        ("missing", "absent from release metadata"),
    ],
)
def test_release_metadata_rejects_malformed_identity_sets(
    monkeypatch: pytest.MonkeyPatch, case: str, message: str
) -> None:
    family = load_replay_inventory(INVENTORY).families["sky130"]
    value: Any = json.loads(_release_payload(family))
    if case == "not-object":
        value = []
    elif case == "release-field":
        value["id"] = True
    elif case == "assets-not-array":
        value["assets"] = {}
    elif case == "asset-not-object":
        value["assets"].append("bad")
    elif case == "invalid-id":
        value["assets"][0]["id"] = True
    elif case == "invalid-name":
        value["assets"][0]["name"] = ""
    elif case == "duplicate":
        value["assets"].append(dict(value["assets"][0]))
    elif case == "missing":
        value["assets"].pop(0)
    body = json.dumps(value).encode()
    monkeypatch.setattr(
        pdk_replay,
        "_open_once",
        lambda request, _timeout: FakeResponse(request.full_url, body),
    )
    with pytest.raises(ReplayPreparationError, match=message):
        fetch_release_observation(family, None)


def test_metadata_functions_reject_redirect_and_nonobject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inventory = load_replay_inventory(INVENTORY)
    family = inventory.families["sky130"]
    redirected = FakeResponse(family.release.api_url)
    monkeypatch.setattr(pdk_replay, "_open_verified", lambda *_args, **_kwargs: (redirected, True))
    with pytest.raises(ReplayPreparationError, match="release metadata unexpectedly redirected"):
        fetch_release_observation(family, None)

    repository_response = FakeResponse("https://api.github.com/repositories/966850989", b"[]")
    monkeypatch.setattr(
        pdk_replay,
        "_open_verified",
        lambda *_args, **_kwargs: (repository_response, False),
    )
    with pytest.raises(ReplayPreparationError, match="repository metadata is not an object"):
        fetch_repository_observation(inventory, None)


def test_selective_tar_extracts_only_locked_regular_files(tmp_path: Path) -> None:
    content = b"model bytes"
    pin = _member("variant/models/device.spice", content)
    payload = _tar(
        [
            ("ignored/file", b"ignored", None),
            (pin.path, content, None),
        ]
    )
    destination = tmp_path / "selected"
    observed = extract_selected_tar_stream(io.BytesIO(payload), [pin], destination)
    assert observed == [{"path": pin.path, "bytes": len(content), "sha256": pin.sha256}]
    assert (destination / pin.path).read_bytes() == content
    assert not (destination / "ignored").exists()


@pytest.mark.parametrize(
    ("name", "message"),
    [
        ("../escape", "traversal"),
        ("/absolute", "traversal"),
        ("bad\\windows", "non-portable"),
        ("C:/drive", "non-portable"),
    ],
)
def test_tar_rejects_every_unsafe_path_even_when_not_selected(
    tmp_path: Path, name: str, message: str
) -> None:
    pin = _member("variant/model", b"ok")
    payload = _tar([(pin.path, b"ok", None), (name, b"bad", None)])
    destination = tmp_path / "selected"
    with pytest.raises(ReplayPreparationError, match=message):
        extract_selected_tar_stream(io.BytesIO(payload), [pin], destination)
    assert not destination.exists()


@pytest.mark.parametrize("type_code", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE])
def test_tar_rejects_links_and_special_members_globally(tmp_path: Path, type_code: bytes) -> None:
    pin = _member("variant/model", b"ok")
    payload = _tar([(pin.path, b"ok", None), ("ignored-danger", b"", type_code)])
    with pytest.raises(ReplayPreparationError, match="link or special"):
        extract_selected_tar_stream(io.BytesIO(payload), [pin], tmp_path / "selected")


def test_tar_rejects_gnu_sparse_members_before_materialization(tmp_path: Path) -> None:
    pin = _member("variant/model", b"ok")
    payload = _tar([(pin.path, b"ok", None), ("ignored-sparse", b"", tarfile.GNUTYPE_SPARSE)])
    destination = tmp_path / "selected"
    with pytest.raises(ReplayPreparationError, match="sparse"):
        extract_selected_tar_stream(io.BytesIO(payload), [pin], destination)
    assert not destination.exists()


def test_tar_rejects_duplicate_and_casefold_collisions(tmp_path: Path) -> None:
    pin = _member("variant/model", b"ok")
    cases = [
        [(pin.path, b"ok", None), (pin.path, b"ok", None)],
        [(pin.path, b"ok", None), ("VARIANT/MODEL", b"ok", None)],
    ]
    for index, entries in enumerate(cases):
        with pytest.raises(ReplayPreparationError, match=r"duplicate|collid"):
            extract_selected_tar_stream(
                io.BytesIO(_tar(entries)), [pin], tmp_path / f"selected-{index}"
            )


def test_tar_rejects_file_prefix_collisions(tmp_path: Path) -> None:
    pin = _member("variant/model/file", b"ok")
    payload = _tar([("variant/model", b"parent", None), (pin.path, b"ok", None)])
    with pytest.raises(ReplayPreparationError, match="collid"):
        extract_selected_tar_stream(io.BytesIO(payload), [pin], tmp_path / "selected")


def test_tar_rejects_both_prefix_orders_and_existing_destination(tmp_path: Path) -> None:
    for index, entries in enumerate(
        (
            [("parent", b"file", None), ("parent/child", b"child", None)],
            [("parent/child", b"child", None), ("parent", b"file", None)],
        )
    ):
        with pytest.raises(ReplayPreparationError, match="prefix collision"):
            extract_selected_tar_stream(io.BytesIO(_tar(entries)), [], tmp_path / f"prefix-{index}")
    existing = tmp_path / "existing"
    existing.mkdir()
    with pytest.raises(ReplayPreparationError, match="already exists"):
        extract_selected_tar_stream(io.BytesIO(_tar([])), [], existing)


def test_tar_accepts_explicit_directory_ancestors(tmp_path: Path) -> None:
    content = b"model"
    pin = _member("variant/models/device.spice", content)
    payload = _tar(
        [
            ("variant/", b"", tarfile.DIRTYPE),
            ("variant/models/", b"", tarfile.DIRTYPE),
            (pin.path, content, None),
        ]
    )
    observed = extract_selected_tar_stream(io.BytesIO(payload), [pin], tmp_path / "selected")
    assert observed[0]["path"] == pin.path


@pytest.mark.parametrize(
    ("pin", "content", "message"),
    [
        (_member("variant/missing", b"expected"), None, "missing"),
        (_member("variant/model", b"expected"), b"short", "wrong size"),
        (MemberPin("variant/model", 5, "0" * 64), b"12345", "SHA-256"),
    ],
)
def test_tar_rejects_missing_size_and_hash_drift(
    tmp_path: Path, pin: MemberPin, content: bytes | None, message: str
) -> None:
    entries = [] if content is None else [(pin.path, content, None)]
    with pytest.raises(ReplayPreparationError, match=message):
        extract_selected_tar_stream(io.BytesIO(_tar(entries)), [pin], tmp_path / "selected")


def test_tar_rejects_member_count_and_path_length_limits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pin = _member("variant/model", b"ok")
    monkeypatch.setattr(pdk_replay, "_MAX_TAR_MEMBERS", 1)
    with pytest.raises(ReplayPreparationError, match="too many"):
        extract_selected_tar_stream(
            io.BytesIO(_tar([(pin.path, b"ok", None), ("other", b"x", None)])),
            [pin],
            tmp_path / "count",
        )
    monkeypatch.setattr(pdk_replay, "_MAX_TAR_MEMBERS", 10)
    monkeypatch.setattr(pdk_replay, "_MAX_TAR_PATH_BYTES", 4)
    with pytest.raises(ReplayPreparationError, match="path exceeds"):
        extract_selected_tar_stream(
            io.BytesIO(_tar([(pin.path, b"ok", None)])), [pin], tmp_path / "path"
        )


def test_bounded_decompressed_reader_rejects_raw_size_and_hash() -> None:
    digest = hashlib.sha256(b"abc").hexdigest()
    valid = pdk_replay._BoundedDigestReader(io.BytesIO(b"abc"), 3, digest)
    assert valid.read() == b"abc"
    valid.verify_to_eof()
    oversized = pdk_replay._BoundedDigestReader(io.BytesIO(b"abcd"), 3, digest)
    with pytest.raises(ReplayPreparationError, match="exceeds"):
        oversized.verify_to_eof()
    changed = pdk_replay._BoundedDigestReader(io.BytesIO(b"abd"), 3, digest)
    with pytest.raises(ReplayPreparationError, match="SHA-256"):
        changed.verify_to_eof()


class FakeProcess:
    def __init__(self, stdout: bytes | None, stderr: bytes = b"", return_code: int = 0) -> None:
        self.stdout = None if stdout is None else io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.return_code = return_code
        self.killed = False
        self.waited = False

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        self.waited = True
        return -9 if self.killed else self.return_code

    def poll(self) -> int | None:
        return (-9 if self.killed else self.return_code) if self.waited else None

    def kill(self) -> None:
        self.killed = True


class BlockingProcess(FakeProcess):
    def __init__(self) -> None:
        super().__init__(b"")
        self._released = threading.Event()
        self.stdout = self

    def read(self, _size: int = -1) -> bytes:
        self._released.wait(2)
        return b""

    def close(self) -> None:
        self._released.set()

    def kill(self) -> None:
        super().kill()
        self._released.set()


def _small_asset(raw_tar: bytes, pin: MemberPin) -> AssetPin:
    return AssetPin(
        7,
        "models.tar.zst",
        "https://api.github.com/repos/fossi-foundation/ciel-releases/releases/assets/7",
        "application/zstd",
        1,
        hashlib.sha256(b"a").hexdigest(),
        len(raw_tar),
        hashlib.sha256(raw_tar).hexdigest(),
        (pin,),
    )


def test_zstd_subprocess_is_argv_only_bounded_and_reaped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    content = b"model"
    pin = _member("variant/model", content)
    raw_tar = _tar([(pin.path, content, None)])
    process = FakeProcess(raw_tar)
    arguments: list[str] = []

    def fake_popen(argv: list[str], **kwargs: Any) -> FakeProcess:
        arguments.extend(argv)
        assert kwargs["stdin"] is not None
        assert kwargs["stdout"] is not None
        assert kwargs["stderr"] is not None
        assert "GITHUB_TOKEN" not in kwargs["env"]
        assert "GH_TOKEN" not in kwargs["env"]
        return process

    monkeypatch.setenv("GITHUB_TOKEN", "must-not-leak")
    monkeypatch.setenv("GH_TOKEN", "must-not-leak")
    monkeypatch.setattr(pdk_replay.subprocess, "Popen", fake_popen)
    zstd = tmp_path / "zstd"
    zstd.write_bytes(b"executable fixture")
    destination = tmp_path / "selected"
    observed = pdk_replay._extract_zstd_archive(
        tmp_path / "archive.tar.zst", _small_asset(raw_tar, pin), destination, zstd
    )
    assert observed[0]["sha256"] == pin.sha256
    assert arguments == [
        str(zstd),
        "--decompress",
        "--stdout",
        "--quiet",
        "--",
        str(tmp_path / "archive.tar.zst"),
    ]
    assert process.waited
    assert not process.killed


@pytest.mark.parametrize(
    ("stderr", "return_code", "raw_digest", "message"),
    [
        (b"zstd failed", 2, None, "zstd failed"),
        (b"x" * (64 * 1024 + 1), 0, None, "diagnostics"),
        (b"", 0, "0" * 64, "decompressed tar"),
    ],
    ids=("exit-status", "stderr-limit", "raw-hash"),
)
def test_zstd_failure_paths_kill_or_reap_and_remove_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stderr: bytes,
    return_code: int,
    raw_digest: str | None,
    message: str,
) -> None:
    content = b"model"
    pin = _member("variant/model", content)
    raw_tar = _tar([(pin.path, content, None)])
    asset = _small_asset(raw_tar, pin)
    if raw_digest is not None:
        asset = AssetPin(
            asset.id,
            asset.name,
            asset.api_url,
            asset.content_type,
            asset.bytes,
            asset.sha256,
            asset.tar_bytes,
            raw_digest,
            asset.members,
        )
    process = FakeProcess(raw_tar, stderr, return_code)
    monkeypatch.setattr(pdk_replay.subprocess, "Popen", lambda *_args, **_kwargs: process)
    zstd = tmp_path / "zstd"
    zstd.write_bytes(b"fixture")
    destination = tmp_path / "selected"
    with pytest.raises(ReplayPreparationError, match=message):
        pdk_replay._extract_zstd_archive(tmp_path / "archive", asset, destination, zstd)
    assert process.waited
    assert not destination.exists()


def test_zstd_watchdog_bounds_a_stalled_stdout_and_reaps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    content = b"model"
    pin = _member("variant/model", content)
    raw_tar = _tar([(pin.path, content, None)])
    process = BlockingProcess()
    monkeypatch.setattr(pdk_replay, "_ZSTD_TIMEOUT_SECONDS", 0.01)
    monkeypatch.setattr(pdk_replay.subprocess, "Popen", lambda *_args, **_kwargs: process)
    zstd = tmp_path / "zstd"
    zstd.write_bytes(b"fixture")
    with pytest.raises(ReplayPreparationError, match="time limit"):
        pdk_replay._extract_zstd_archive(
            tmp_path / "archive", _small_asset(raw_tar, pin), tmp_path / "selected", zstd
        )
    assert process.killed
    assert process.waited


def test_zstd_failure_never_removes_a_preexisting_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    content = b"model"
    pin = _member("variant/model", content)
    raw_tar = _tar([(pin.path, content, None)])
    process = FakeProcess(raw_tar)
    monkeypatch.setattr(pdk_replay.subprocess, "Popen", lambda *_args, **_kwargs: process)
    zstd = tmp_path / "zstd"
    zstd.write_bytes(b"fixture")
    destination = tmp_path / "selected"
    destination.mkdir()
    marker = destination / "owned-by-another-writer"
    marker.write_bytes(b"keep")

    with pytest.raises(ReplayPreparationError, match="already exists"):
        pdk_replay._extract_zstd_archive(
            tmp_path / "archive", _small_asset(raw_tar, pin), destination, zstd
        )

    assert marker.read_bytes() == b"keep"
    assert process.waited


def test_zstd_refuses_link_or_unstartable_executable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    content = b"model"
    pin = _member("variant/model", content)
    raw_tar = _tar([(pin.path, content, None)])
    asset = _small_asset(raw_tar, pin)
    with pytest.raises(ReplayPreparationError, match="absolute regular"):
        pdk_replay._extract_zstd_archive(
            tmp_path / "archive", asset, tmp_path / "selected", Path("zstd")
        )
    zstd = tmp_path / "zstd"
    zstd.write_bytes(b"fixture")
    monkeypatch.setattr(
        pdk_replay.subprocess,
        "Popen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("cannot execute")),
    )
    with pytest.raises(ReplayPreparationError, match="cannot start"):
        pdk_replay._extract_zstd_archive(tmp_path / "archive", asset, tmp_path / "selected", zstd)


def test_prepare_family_publishes_only_verified_members_and_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    model = b"small model"
    member = _member("sky130A/models/device.spice", model)
    asset = AssetPin(
        7,
        "models.tar.zst",
        "https://api.github.com/repos/fossi-foundation/ciel-releases/releases/assets/7",
        "application/zstd",
        1,
        hashlib.sha256(b"a").hexdigest(),
        10240,
        hashlib.sha256(b"tar").hexdigest(),
        (member,),
    )
    release = ReleasePin(
        8,
        "sky130-" + "a" * 40,
        "https://api.github.com/repos/fossi-foundation/ciel-releases/releases/tags/test",
        False,
        False,
        False,
    )
    family = FamilyPin(
        "sky130",
        "sky130A",
        release,
        (asset,),
        {"spdx": "Apache-2.0", "source_commit": "b" * 40, "url": "https://example"},
    )
    decision_pin = DecisionPin(
        "https://raw.githubusercontent.com/example/commit/decision.json",
        1,
        hashlib.sha256(b"d").hexdigest(),
        "1" * 64,
        "TL-test",
        "2" * 64,
        "3" * 64,
        "4" * 64,
    )
    inventory = ReplayInventory(
        "a" * 40,
        "https://github.com/fossi-foundation/ciel-releases",
        966850989,
        {"sky130": family},
        decision_pin,
        {},
        "5" * 64,
    )
    monkeypatch.setattr(pdk_replay, "load_replay_inventory", lambda _path: inventory)
    monkeypatch.setattr(
        pdk_replay, "fetch_repository_observation", lambda _inventory, _token: {"id": 966850989}
    )
    monkeypatch.setattr(pdk_replay, "fetch_release_observation", lambda _family, _token: {"id": 8})

    def fake_download(
        _url: str,
        destination: Path,
        *,
        expected_bytes: int,
        expected_sha256: str,
        **_arguments: Any,
    ) -> DownloadObservation:
        payload = b"a" if destination.suffix == ".zst" else b"d"
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
        assert len(payload) == expected_bytes
        assert hashlib.sha256(payload).hexdigest() == expected_sha256
        return DownloadObservation(
            len(payload),
            expected_sha256,
            "example",
            False,
            pdk_replay._path_identity(destination),
        )

    def fake_extract(
        _archive: Path, _asset: AssetPin, destination: Path, _zstd: Path
    ) -> list[dict[str, object]]:
        output = destination / member.path
        output.parent.mkdir(parents=True)
        output.write_bytes(model)
        return [{"path": member.path, "bytes": len(model), "sha256": member.sha256}]

    monkeypatch.setattr(pdk_replay, "download_exact", fake_download)
    monkeypatch.setattr(pdk_replay, "_extract_zstd_archive", fake_extract)
    monkeypatch.setattr(
        pdk_replay,
        "load_sizing_decision",
        lambda *_args, **_kwargs: SimpleNamespace(
            digest="1" * 64,
            topology_id="TL-test",
            topology_signature="2" * 64,
        ),
    )
    evidence = tmp_path / "pdk-fetch.json"
    decision = tmp_path / "decision.json"
    target = prepare_ciel_family(
        tmp_path / "inventory.json",
        "sky130",
        pdk_base=tmp_path / "pdks",
        download_directory=tmp_path / "downloads",
        decision_output=decision,
        evidence_output=evidence,
        zstd=tmp_path / "zstd",
    )
    assert (target / "models" / "device.spice").read_bytes() == model
    assert decision.read_bytes() == b"d"
    recorded = json.loads(evidence.read_text(encoding="ascii"))
    assert recorded["inventory_sha256"] == "5" * 64
    assert recorded["assets"][0]["tar_bytes"] == 10240
    assert not (tmp_path / "downloads" / "sky130-models.tar.zst").exists()


def test_prepare_family_refuses_existing_target_without_clobbering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inventory = load_replay_inventory(INVENTORY)
    target = tmp_path / "pdks" / "versions" / inventory.revision / "sky130A"
    target.mkdir(parents=True)
    marker = target / "marker"
    marker.write_text("keep", encoding="ascii")
    monkeypatch.setattr(pdk_replay, "load_replay_inventory", lambda _path: inventory)
    with pytest.raises(ReplayPreparationError, match="overwrite"):
        prepare_ciel_family(
            INVENTORY,
            "sky130",
            pdk_base=tmp_path / "pdks",
            download_directory=tmp_path / "downloads",
            decision_output=tmp_path / "decision",
            evidence_output=tmp_path / "evidence",
        )
    assert marker.read_text(encoding="ascii") == "keep"
