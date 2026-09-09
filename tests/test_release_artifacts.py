from __future__ import annotations

import base64
import copy
import hashlib
import json
import zipfile
from io import BytesIO
from pathlib import Path

import pytest

import simcairn.release_artifacts as release_artifacts
from simcairn.release_artifacts import (
    ReleaseArtifactError,
    bind_installed_wheel,
    distribution_asset_names,
    main,
    validate_spdx,
    validate_spdx_path,
    verify_release,
    write_checksums,
)

NAME = "simcairn"
VERSION = "0.4.0"
SYFT_VERSION = "1.51.1"


def rewrite_wheel(
    wheel: Path,
    *,
    record_transform: object | None = None,
    additions: dict[str, bytes | zipfile.ZipInfo] | None = None,
) -> None:
    with zipfile.ZipFile(wheel) as source:
        entries: list[tuple[zipfile.ZipInfo, bytes]] = [
            (item, source.read(item)) for item in source.infolist() if not item.is_dir()
        ]
    record_name = "simcairn-0.4.0.dist-info/RECORD"
    if record_transform is not None:
        entries = [
            (
                item,
                record_transform(payload) if item.filename == record_name else payload,  # type: ignore[operator]
            )
            for item, payload in entries
        ]
    with zipfile.ZipFile(wheel, "w") as destination:
        for item, payload in entries:
            destination.writestr(item, payload)
        for name, value in (additions or {}).items():
            if isinstance(value, zipfile.ZipInfo):
                destination.writestr(value, b"target")
            else:
                destination.writestr(name, value)


def checksums(payload: bytes) -> list[dict[str, str]]:
    return [
        {
            "algorithm": "SHA1",
            "checksumValue": hashlib.sha1(payload, usedforsecurity=False).hexdigest(),
        },
        {"algorithm": "SHA256", "checksumValue": hashlib.sha256(payload).hexdigest()},
    ]


def verification_code(payloads: list[bytes]) -> str:
    sha1_values = sorted(
        hashlib.sha1(payload, usedforsecurity=False).hexdigest() for payload in payloads
    )
    return hashlib.sha1("".join(sha1_values).encode("ascii"), usedforsecurity=False).hexdigest()


def spdx_document(*, package_name: str = NAME) -> dict[str, object]:
    package_id = "SPDXRef-Package-python-simcairn"
    file_id = "SPDXRef-File-simcairn-init-py"
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{NAME} installed environment",
        "documentNamespace": f"https://example.invalid/spdx/{NAME}/{VERSION}",
        "creationInfo": {
            "creators": [f"Tool: syft-{SYFT_VERSION}"],
            "created": "2026-09-08T00:00:00Z",
        },
        "packages": [
            {
                "name": package_name,
                "versionInfo": VERSION,
                "SPDXID": package_id,
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": f"pkg:pypi/{NAME}@{VERSION}",
                    }
                ],
                "filesAnalyzed": True,
                "packageVerificationCode": {
                    "packageVerificationCodeValue": verification_code([b""])
                },
            }
        ],
        "files": [
            {
                "fileName": "simcairn/__init__.py",
                "SPDXID": file_id,
                "checksums": checksums(b""),
            }
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": package_id,
            },
            {
                "spdxElementId": package_id,
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": file_id,
            },
        ],
    }


@pytest.mark.parametrize("package_name", ["simcairn", "simcairn"])
def test_spdx_accepts_normalized_name_and_required_relationships(package_name: str) -> None:
    validate_spdx(
        spdx_document(package_name=package_name),
        expected_name=NAME,
        expected_version=VERSION,
        expected_syft_version=SYFT_VERSION,
    )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda data: data.pop("dataLicense"), "dataLicense"),
        (lambda data: data.update(dataLicense="MIT"), "dataLicense"),
        (lambda data: data.update(name=""), "name"),
        (lambda data: data.update(name="unsafe\nname"), "name"),
        (lambda data: data.update(documentNamespace="relative/path"), "documentNamespace"),
        (
            lambda data: data.update(documentNamespace="https://example.invalid/spdx#fragment"),
            "documentNamespace",
        ),
        (lambda data: data["creationInfo"].pop("created"), "created"),
        (lambda data: data["creationInfo"].update(created="2026-02-30T00:00:00Z"), "created"),
        (
            lambda data: data["creationInfo"].update(created="2026-09-08T00:00:00+00:00"),
            "created",
        ),
    ],
)
def test_spdx_rejects_invalid_document_header(mutation: object, message: str) -> None:
    document = spdx_document()
    mutation(document)  # type: ignore[operator]
    with pytest.raises(ReleaseArtifactError, match=message):
        validate_spdx(
            document,
            expected_name=NAME,
            expected_version=VERSION,
            expected_syft_version=SYFT_VERSION,
        )


@pytest.mark.parametrize(
    "locator",
    [
        f"pkg:pypi/{NAME}@{VERSION}?",
        f"pkg:pypi/{NAME}@{VERSION}?evil=1",
        f"pkg:pypi/{NAME}@{VERSION}#../../x",
        f"PKG:PYPI/SIMCAIRN@{VERSION}",
        f"pkg:pypi/sim_cairn@{VERSION}",
        None,
        [],
    ],
)
def test_spdx_requires_exact_canonical_package_locator(locator: object) -> None:
    document = spdx_document()
    document["packages"][0]["externalRefs"][0]["referenceLocator"] = locator
    with pytest.raises(ReleaseArtifactError, match="package URL"):
        validate_spdx(
            document,
            expected_name=NAME,
            expected_version=VERSION,
            expected_syft_version=SYFT_VERSION,
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda data: data.update(spdxVersion="SPDX-2.2"), "SPDX-2.3"),
        (lambda data: data["creationInfo"].update(creators=[]), "pinned generator"),
        (lambda data: data["packages"][0].update(versionInfo=""), "version must"),
        (lambda data: data["packages"][0].update(externalRefs=[]), "package URL"),
        (
            lambda data: data["packages"][0]["externalRefs"][0].update(
                referenceCategory="SECURITY"
            ),
            "package URL",
        ),
        (lambda data: data.update(relationships=[]), "DESCRIBED"),
        (
            lambda data: data["relationships"].pop(),
            "directly CONTAIN",
        ),
        (lambda data: data.update(files=[]), "at least one file"),
    ],
)
def test_spdx_rejects_missing_release_semantics(mutation: object, message: str) -> None:
    document = spdx_document()
    mutation(document)  # type: ignore[operator]
    with pytest.raises(ReleaseArtifactError, match=message):
        validate_spdx(
            document,
            expected_name=NAME,
            expected_version=VERSION,
            expected_syft_version=SYFT_VERSION,
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda data: data.update(creationInfo=[]), "creationInfo"),
        (lambda data: data.update(packages={}), "packages must"),
        (lambda data: data.update(files={}), "files must"),
        (lambda data: data.update(relationships={}), "relationships must"),
        (lambda data: data["packages"][0].update(name="other"), "does not contain"),
        (lambda data: data["packages"][0].update(versionInfo="9"), "version must"),
        (
            lambda data: data["packages"][0]["externalRefs"][0].update(
                referenceLocator="pkg:pypi/other@0.4.0"
            ),
            "exactly one installed",
        ),
        (
            lambda data: data["files"][0]["checksums"].append(
                copy.deepcopy(data["files"][0]["checksums"][0])
            ),
            "repeats checksum",
        ),
        (
            lambda data: data["files"][0].update(checksums=[{"algorithm": "SHA1"}]),
            "exact SHA1",
        ),
        (
            lambda data: data["relationships"].append(copy.deepcopy(data["relationships"][0])),
            "repeats a relationship",
        ),
        (
            lambda data: data["relationships"][0].update(relationshipType=None),
            "incomplete",
        ),
        (lambda data: data["packages"][0].update(filesAnalyzed=False), "verification code"),
        (
            lambda data: data["packages"][0]["packageVerificationCode"].update(
                packageVerificationCodeExcludedFiles=["ignored"]
            ),
            "verification code",
        ),
    ],
)
def test_spdx_rejects_malformed_graph_details(mutation: object, message: str) -> None:
    document = spdx_document()
    mutation(document)  # type: ignore[operator]
    with pytest.raises(ReleaseArtifactError, match=message):
        validate_spdx(
            document,
            expected_name=NAME,
            expected_version=VERSION,
            expected_syft_version=SYFT_VERSION,
        )


def test_spdx_rejects_package_file_identifier_collision(tmp_path: Path) -> None:
    document = raw_syft_document()
    package_id = document["packages"][0]["SPDXID"]  # type: ignore[index]
    document["files"][0]["SPDXID"] = package_id  # type: ignore[index]
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps(document), encoding="utf-8")
    site_packages, wheel = installed_tree(tmp_path / "site-packages")

    with pytest.raises(ReleaseArtifactError, match="reuses SPDXID"):
        bind_installed_wheel(
            sbom, site_packages, wheel, expected_name=NAME, expected_version=VERSION
        )


def test_spdx_rejects_duplicate_package_identifier_and_unknown_relationship() -> None:
    duplicate = spdx_document()
    duplicate["packages"].append(copy.deepcopy(duplicate["packages"][0]))  # type: ignore[union-attr,index]
    with pytest.raises(ReleaseArtifactError, match="reuses SPDXID"):
        validate_spdx(
            duplicate,
            expected_name=NAME,
            expected_version=VERSION,
            expected_syft_version=SYFT_VERSION,
        )

    invalid_identifier = spdx_document()
    invalid_identifier["files"][0]["SPDXID"] = "SPDXRef-"  # type: ignore[index]
    with pytest.raises(ReleaseArtifactError, match="invalid SPDXID"):
        validate_spdx(
            invalid_identifier,
            expected_name=NAME,
            expected_version=VERSION,
            expected_syft_version=SYFT_VERSION,
        )

    unknown = spdx_document()
    unknown["relationships"].append(  # type: ignore[union-attr]
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-unknown",
        }
    )
    with pytest.raises(ReleaseArtifactError, match="unknown SPDX element"):
        validate_spdx(
            unknown,
            expected_name=NAME,
            expected_version=VERSION,
            expected_syft_version=SYFT_VERSION,
        )


def populate_release_payloads(directory: Path) -> None:
    wheel, sdist = distribution_asset_names(NAME, VERSION)
    (directory / wheel).write_bytes(b"wheel bytes")
    (directory / sdist).write_bytes(b"source bytes")
    (directory / "SBOM.spdx.json").write_text(json.dumps(spdx_document()), encoding="utf-8")


def raw_syft_document() -> dict[str, object]:
    package_id = "SPDXRef-Package-python-simcairn"
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{NAME} installed environment",
        "documentNamespace": f"https://example.invalid/spdx/{NAME}/{VERSION}",
        "creationInfo": {
            "creators": [f"Tool: syft-{SYFT_VERSION}"],
            "created": "2026-09-08T00:00:00Z",
        },
        "packages": [
            {
                "name": NAME,
                "versionInfo": VERSION,
                "SPDXID": package_id,
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": f"pkg:pypi/{NAME}@{VERSION}",
                    }
                ],
            }
        ],
        "files": [
            {"fileName": "/simcairn/__init__.py", "SPDXID": "SPDXRef-File-code"},
            {
                "fileName": "/simcairn-0.4.0.dist-info/METADATA",
                "SPDXID": "SPDXRef-File-metadata",
            },
            {
                "fileName": "/simcairn-0.4.0.dist-info/RECORD",
                "SPDXID": "SPDXRef-File-record",
            },
        ],
        "relationships": [],
    }


def installed_tree(directory: Path) -> tuple[Path, Path]:
    package = directory / "simcairn"
    package.mkdir(parents=True)
    init_payload = b""
    (package / "__init__.py").write_bytes(init_payload)
    dist_info = directory / "simcairn-0.4.0.dist-info"
    dist_info.mkdir()
    metadata_payload = b"Metadata-Version: 2.4\nName: simcairn\nVersion: 0.4.0\n"
    (dist_info / "METADATA").write_bytes(metadata_payload)

    def row(path: str, payload: bytes) -> str:
        encoded = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).decode().rstrip("=")
        return f"{path},sha256={encoded},{len(payload)}\n"

    record_payload = (
        row("simcairn/__init__.py", init_payload)
        + row("simcairn-0.4.0.dist-info/METADATA", metadata_payload)
        + "simcairn-0.4.0.dist-info/RECORD,,\n"
    ).encode()
    (dist_info / "RECORD").write_bytes(record_payload)
    wheel_name, _sdist_name = distribution_asset_names(NAME, VERSION)
    wheel = directory.parent / wheel_name
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("simcairn/__init__.py", init_payload)
        archive.writestr("simcairn-0.4.0.dist-info/METADATA", metadata_payload)
        archive.writestr("simcairn-0.4.0.dist-info/RECORD", record_payload)
    return directory, wheel


def test_release_names_reject_unsafe_components() -> None:
    with pytest.raises(ReleaseArtifactError, match="distribution name"):
        distribution_asset_names("../escape", VERSION)
    with pytest.raises(ReleaseArtifactError, match="distribution version"):
        distribution_asset_names(NAME, "1/2")


def test_record_digest_parser_rejects_bad_base64_and_wrong_length() -> None:
    with pytest.raises(ReleaseArtifactError, match="invalid SHA-256"):
        release_artifacts._record_sha256("sha256=***", "file")
    with pytest.raises(ReleaseArtifactError, match="invalid SHA-256"):
        release_artifacts._record_sha256("sha256=YQ", "file")


@pytest.mark.parametrize(
    ("transform", "message"),
    [
        (lambda record: b"bad,row\n", "exactly three"),
        (
            lambda record: record.replace(
                b"simcairn-0.4.0.dist-info/RECORD,,",
                b"simcairn-0.4.0.dist-info/RECORD,sha256=bad,1",
            ),
            "self-hash",
        ),
        (
            lambda record: record.replace(
                b"simcairn/__init__.py,sha256=",
                b"simcairn/__init__.py,md5=",
            ),
            "lacks SHA-256",
        ),
        (
            lambda record: record.replace(
                record.split(b"sha256=", maxsplit=1)[1].split(b",", maxsplit=1)[0],
                b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                1,
            ),
            "does not match RECORD",
        ),
        (
            lambda record: record.replace(b",0\n", b",bad\n", 1),
            "lacks a size",
        ),
        (
            lambda record: (
                record + b"simcairn/missing.py,sha256="
                b"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU,0\n"
            ),
            "absent from the archive",
        ),
        (
            lambda record: record + record.splitlines(keepends=True)[0],
            "repeats",
        ),
        (
            lambda record: record.replace(b"simcairn/__init__.py", b"simcairn/../__init__.py", 1),
            "non-canonical path",
        ),
    ],
)
def test_wheel_record_rejects_malformed_claims(tmp_path: Path, transform, message: str) -> None:
    _site_packages, wheel = installed_tree(tmp_path / "site-packages")
    rewrite_wheel(wheel, record_transform=transform)
    with pytest.raises(ReleaseArtifactError, match=message):
        release_artifacts._wheel_distribution(
            wheel, NAME, VERSION, "simcairn", "simcairn-0.4.0.dist-info"
        )


def test_wheel_inspection_rejects_bad_archive_shapes(tmp_path: Path) -> None:
    _site_packages, wheel = installed_tree(tmp_path / "site-packages")
    wheel.write_bytes(b"not a zip")
    with pytest.raises(ReleaseArtifactError, match="cannot inspect"):
        release_artifacts._wheel_distribution(
            wheel, NAME, VERSION, "simcairn", "simcairn-0.4.0.dist-info"
        )

    _site_packages, wheel = installed_tree(tmp_path / "noncanonical-site-packages")
    with zipfile.ZipFile(wheel, "a") as archive:
        archive.writestr("../escape", b"x")
    with pytest.raises(ReleaseArtifactError, match="non-canonical archive path"):
        release_artifacts._wheel_distribution(
            wheel, NAME, VERSION, "simcairn", "simcairn-0.4.0.dist-info"
        )

    wrong_name = tmp_path / "wrong.whl"
    wrong_name.write_bytes(b"not relevant")
    with pytest.raises(ReleaseArtifactError, match="exact regular"):
        release_artifacts._wheel_distribution(
            wrong_name, NAME, VERSION, "simcairn", "simcairn-0.4.0.dist-info"
        )

    _site_packages, wheel = installed_tree(tmp_path / "second-site-packages")
    with pytest.warns(UserWarning, match="Duplicate name"), zipfile.ZipFile(wheel, "a") as archive:
        archive.writestr("simcairn/__init__.py", b"duplicate")
    with pytest.raises(ReleaseArtifactError, match="duplicate entries"):
        release_artifacts._wheel_distribution(
            wheel, NAME, VERSION, "simcairn", "simcairn-0.4.0.dist-info"
        )


def test_wheel_inspection_rejects_symbolic_link_entry(tmp_path: Path) -> None:
    _site_packages, wheel = installed_tree(tmp_path / "site-packages")
    link = zipfile.ZipInfo("simcairn/link.py")
    link.create_system = 3
    link.external_attr = 0o120777 << 16
    rewrite_wheel(wheel, additions={link.filename: link})
    with pytest.raises(ReleaseArtifactError, match="symbolic-link"):
        release_artifacts._wheel_distribution(
            wheel, NAME, VERSION, "simcairn", "simcairn-0.4.0.dist-info"
        )


def test_wheel_record_must_contain_the_project_package(tmp_path: Path) -> None:
    wheel_name, _sdist = distribution_asset_names(NAME, VERSION)
    wheel = tmp_path / wheel_name
    metadata_name = "simcairn-0.4.0.dist-info/METADATA"
    record_name = "simcairn-0.4.0.dist-info/RECORD"
    metadata = b"Name: simcairn\nVersion: 0.4.0\n"
    encoded = base64.urlsafe_b64encode(hashlib.sha256(metadata).digest()).decode().rstrip("=")
    record = f"{metadata_name},sha256={encoded},{len(metadata)}\n{record_name},,\n".encode()
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(metadata_name, metadata)
        archive.writestr(record_name, record)
    with pytest.raises(ReleaseArtifactError, match="does not contain the project package"):
        release_artifacts._wheel_distribution(
            wheel, NAME, VERSION, "simcairn", "simcairn-0.4.0.dist-info"
        )


def test_installed_distribution_rejects_missing_duplicate_and_bad_record(tmp_path: Path) -> None:
    site_packages, wheel = installed_tree(tmp_path / "site-packages")
    metadata = site_packages / "simcairn-0.4.0.dist-info" / "METADATA"
    metadata.write_text("Name: other\nVersion: 0.4.0\n", encoding="utf-8")
    with pytest.raises(ReleaseArtifactError, match="exactly one"):
        release_artifacts._installed_distribution(site_packages, wheel, NAME, VERSION)

    site_packages, wheel = installed_tree(tmp_path / "second-site-packages")
    duplicate = site_packages / "duplicate.dist-info"
    duplicate.mkdir()
    (duplicate / "METADATA").write_text("Name: simcairn\nVersion: 0.4.0\n", encoding="utf-8")
    with pytest.raises(ReleaseArtifactError, match="exactly one"):
        release_artifacts._installed_distribution(site_packages, wheel, NAME, VERSION)

    site_packages, wheel = installed_tree(tmp_path / "third-site-packages")
    record = site_packages / "simcairn-0.4.0.dist-info" / "RECORD"
    record.write_text("bad,row\n", encoding="utf-8")
    with pytest.raises(ReleaseArtifactError, match="exactly three"):
        release_artifacts._installed_distribution(site_packages, wheel, NAME, VERSION)


def test_installed_distribution_binds_allowlisted_external_script(tmp_path: Path) -> None:
    installation_root = tmp_path / "venv"
    site_packages, wheel = installed_tree(installation_root / "site-packages")
    script = installation_root / "bin" / "simcairn"
    script.parent.mkdir()
    script_payload = b"#!/bin/sh\nexit 0\n"
    script.write_bytes(script_payload)
    encoded = base64.urlsafe_b64encode(hashlib.sha256(script_payload).digest()).decode().rstrip("=")
    record = site_packages / "simcairn-0.4.0.dist-info" / "RECORD"
    with record.open("a", encoding="utf-8", newline="") as stream:
        stream.write(f"../bin/simcairn,sha256={encoded},{len(script_payload)}\n")
    document = raw_syft_document()
    for item in document["files"]:  # type: ignore[union-attr]
        item["fileName"] = f"/site-packages/{str(item['fileName']).lstrip('/')}"
    document["files"].append(  # type: ignore[union-attr]
        {"fileName": "/bin/simcairn", "SPDXID": "SPDXRef-File-cli"}
    )
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps(document), encoding="utf-8")

    assert (
        bind_installed_wheel(
            sbom,
            site_packages,
            wheel,
            expected_name=NAME,
            expected_version=VERSION,
            installation_root=installation_root,
            expected_external_paths=("bin/simcairn",),
        )
        == 4
    )
    validate_spdx_path(
        sbom,
        expected_name=NAME,
        expected_version=VERSION,
        expected_syft_version=SYFT_VERSION,
    )
    _dist_info, files = release_artifacts._installed_distribution(
        site_packages,
        wheel,
        NAME,
        VERSION,
        installation_root=installation_root,
        expected_external_paths=("bin/simcairn",),
    )
    assert set(files) == {
        "bin/simcairn",
        "site-packages/simcairn/__init__.py",
        "site-packages/simcairn-0.4.0.dist-info/METADATA",
        "site-packages/simcairn-0.4.0.dist-info/RECORD",
    }


def test_installed_distribution_rejects_external_script_outside_default_root(
    tmp_path: Path,
) -> None:
    installation_root = tmp_path / "venv"
    site_packages, wheel = installed_tree(installation_root / "site-packages")
    script = installation_root / "bin" / "simcairn"
    script.parent.mkdir()
    script.write_bytes(b"launcher")
    record = site_packages / "simcairn-0.4.0.dist-info" / "RECORD"
    with record.open("a", encoding="utf-8", newline="") as stream:
        stream.write("../bin/simcairn,,\n")
    with pytest.raises(ReleaseArtifactError, match="escapes the installation root"):
        release_artifacts._installed_distribution(site_packages, wheel, NAME, VERSION)


def test_installed_distribution_rejects_unexpected_or_missing_external_script(
    tmp_path: Path,
) -> None:
    installation_root = tmp_path / "venv"
    site_packages, wheel = installed_tree(installation_root / "site-packages")
    script = installation_root / "bin" / "simcairn"
    script.parent.mkdir()
    script.write_bytes(b"launcher")
    record = site_packages / "simcairn-0.4.0.dist-info" / "RECORD"
    with record.open("a", encoding="utf-8", newline="") as stream:
        stream.write("../bin/simcairn,,\n")
    with pytest.raises(ReleaseArtifactError, match="unexpected external path"):
        release_artifacts._installed_distribution(
            site_packages, wheel, NAME, VERSION, installation_root=installation_root
        )

    record.write_text(
        "\n".join(
            line
            for line in record.read_text(encoding="utf-8").splitlines()
            if "bin/simcairn" not in line
        )
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ReleaseArtifactError, match="external file set differs"):
        release_artifacts._installed_distribution(
            site_packages,
            wheel,
            NAME,
            VERSION,
            installation_root=installation_root,
            expected_external_paths=("bin/simcairn",),
        )


@pytest.mark.parametrize(
    "external_paths",
    [
        ("../bin/simcairn",),
        ("bin\\simcairn",),
        ("bin/./simcairn",),
        ("bin/simcairn", "bin/simcairn"),
    ],
)
def test_installed_distribution_rejects_invalid_external_allowlist(
    tmp_path: Path, external_paths: tuple[str, ...]
) -> None:
    site_packages, wheel = installed_tree(tmp_path / "site-packages")
    with pytest.raises(ReleaseArtifactError, match=r"not canonical|is repeated"):
        release_artifacts._installed_distribution(
            site_packages,
            wheel,
            NAME,
            VERSION,
            expected_external_paths=external_paths,
        )


def test_installed_distribution_rejects_external_escape_and_bad_claim(tmp_path: Path) -> None:
    installation_root = tmp_path / "venv"
    site_packages, wheel = installed_tree(installation_root / "site-packages")
    outside = tmp_path / "outside-launcher"
    outside.write_bytes(b"outside")
    record = site_packages / "simcairn-0.4.0.dist-info" / "RECORD"
    with record.open("a", encoding="utf-8", newline="") as stream:
        stream.write("../../outside-launcher,,\n")
    with pytest.raises(ReleaseArtifactError, match="escapes the installation root"):
        release_artifacts._installed_distribution(
            site_packages, wheel, NAME, VERSION, installation_root=installation_root
        )

    launcher = installation_root / "bin" / "simcairn"
    launcher.parent.mkdir()
    launcher.write_bytes(b"launcher")
    record.write_text(
        record.read_text(encoding="utf-8").replace(
            "../../outside-launcher,,", "../bin/simcairn,sha256=bad,8"
        ),
        encoding="utf-8",
    )
    with pytest.raises(ReleaseArtifactError, match="invalid SHA-256"):
        release_artifacts._installed_distribution(
            site_packages,
            wheel,
            NAME,
            VERSION,
            installation_root=installation_root,
            expected_external_paths=("bin/simcairn",),
        )


@pytest.mark.parametrize(
    "claim",
    ["rogue.py,,\n", "rogue.py,sha256=NOT-A-DIGEST,12\n"],
)
def test_installed_record_rejects_unexpected_external_path(tmp_path: Path, claim: str) -> None:
    site_packages, wheel = installed_tree(tmp_path / "site-packages")
    (site_packages / "rogue.py").write_text("rogue\n", encoding="utf-8")
    record = site_packages / "simcairn-0.4.0.dist-info" / "RECORD"
    with record.open("a", encoding="utf-8", newline="") as stream:
        stream.write(claim)
    with pytest.raises(ReleaseArtifactError, match="unexpected external path"):
        release_artifacts._installed_distribution(site_packages, wheel, NAME, VERSION)


@pytest.mark.parametrize(
    ("line", "message"),
    [
        ("simcairn\\__init__.py,,\n", "not portable"),
        ("simcairn/__init__.py,,\n", "aliases an installed path"),
        ("simcairn/missing.py,,\n", "missing"),
    ],
)
def test_installed_record_rejects_unsafe_or_conflicting_rows(
    tmp_path: Path, line: str, message: str
) -> None:
    site_packages, wheel = installed_tree(tmp_path / "site-packages")
    record = site_packages / "simcairn-0.4.0.dist-info" / "RECORD"
    with record.open("a", encoding="utf-8", newline="") as stream:
        stream.write(line)
    with pytest.raises(ReleaseArtifactError, match=message):
        release_artifacts._installed_distribution(site_packages, wheel, NAME, VERSION)


def test_installed_record_rejects_a_self_hash(tmp_path: Path) -> None:
    site_packages, wheel = installed_tree(tmp_path / "site-packages")
    record = site_packages / "simcairn-0.4.0.dist-info" / "RECORD"
    record.write_text(
        record.read_text(encoding="utf-8").replace(
            "simcairn-0.4.0.dist-info/RECORD,,",
            "simcairn-0.4.0.dist-info/RECORD,sha256=bad,1",
        ),
        encoding="utf-8",
    )
    with pytest.raises(ReleaseArtifactError, match="self-hash"):
        release_artifacts._installed_distribution(site_packages, wheel, NAME, VERSION)


def test_installed_record_read_failure_is_actionable(tmp_path: Path) -> None:
    site_packages, wheel = installed_tree(tmp_path / "site-packages")
    (site_packages / "simcairn-0.4.0.dist-info" / "RECORD").unlink()
    with pytest.raises(ReleaseArtifactError, match="must be a regular file"):
        release_artifacts._installed_distribution(site_packages, wheel, NAME, VERSION)


def test_installed_record_rejects_empty_rows_and_size_limit(tmp_path: Path) -> None:
    site_packages, wheel = installed_tree(tmp_path / "site-packages")
    record = site_packages / "simcairn-0.4.0.dist-info" / "RECORD"
    record.write_text(
        record.read_text(encoding="utf-8").replace(
            "simcairn-0.4.0.dist-info/RECORD,,\n",
            "\nsimcairn-0.4.0.dist-info/RECORD,,\n",
        ),
        encoding="utf-8",
    )
    with pytest.raises(ReleaseArtifactError, match="empty row"):
        release_artifacts._installed_distribution(site_packages, wheel, NAME, VERSION)

    record.write_bytes(b"x" * (8 * 1024 * 1024 + 1))
    with pytest.raises(ReleaseArtifactError, match="exceeds the supported size"):
        release_artifacts._installed_distribution(site_packages, wheel, NAME, VERSION)


def test_bind_installed_wheel_adds_record_backed_spdx_relationships(tmp_path: Path) -> None:
    site_packages, wheel = installed_tree(tmp_path / "site-packages")
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps(raw_syft_document()), encoding="utf-8")

    assert (
        bind_installed_wheel(
            sbom,
            site_packages,
            wheel,
            expected_name=NAME,
            expected_version=VERSION,
        )
        == 3
    )
    validate_spdx_path(
        sbom,
        expected_name=NAME,
        expected_version=VERSION,
        expected_syft_version=SYFT_VERSION,
    )
    relationships = json.loads(sbom.read_text(encoding="utf-8"))["relationships"]
    assert {relationship["relationshipType"] for relationship in relationships} == {
        "CONTAINS",
        "DESCRIBES",
    }
    document = json.loads(sbom.read_text(encoding="utf-8"))
    contained = {
        relationship["relatedSpdxElement"]
        for relationship in relationships
        if relationship["relationshipType"] == "CONTAINS"
    }
    assert len(contained) == 3
    assert all(
        {checksum["algorithm"] for checksum in item["checksums"]} == {"SHA1", "SHA256"}
        and all(set(checksum["checksumValue"]) != {"0"} for checksum in item["checksums"])
        for item in document["files"]
        if item["SPDXID"] in contained
    )


def test_bind_installed_wheel_rejects_invalid_document_header(tmp_path: Path) -> None:
    site_packages, wheel = installed_tree(tmp_path / "site-packages")
    document = raw_syft_document()
    document.pop("dataLicense")
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ReleaseArtifactError, match="dataLicense"):
        bind_installed_wheel(
            sbom,
            site_packages,
            wheel,
            expected_name=NAME,
            expected_version=VERSION,
        )


def test_bind_installed_wheel_rejects_record_content_mismatch(tmp_path: Path) -> None:
    site_packages, wheel = installed_tree(tmp_path / "site-packages")
    (site_packages / "simcairn" / "__init__.py").write_bytes(b"tampered")
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps(raw_syft_document()), encoding="utf-8")
    with pytest.raises(ReleaseArtifactError, match="does not match wheel RECORD"):
        bind_installed_wheel(
            sbom, site_packages, wheel, expected_name=NAME, expected_version=VERSION
        )


def test_bind_installed_wheel_rejects_unrecorded_wheel_entry(tmp_path: Path) -> None:
    site_packages, wheel = installed_tree(tmp_path / "site-packages")
    with zipfile.ZipFile(wheel, "a") as archive:
        archive.writestr("simcairn/unrecorded_probe.py", b"probe = True\n")
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps(raw_syft_document()), encoding="utf-8")

    with pytest.raises(ReleaseArtifactError, match="archive and RECORD file sets differ"):
        bind_installed_wheel(
            sbom, site_packages, wheel, expected_name=NAME, expected_version=VERSION
        )


@pytest.mark.parametrize(
    "rogue_path",
    ["rogue.py", "simcairn-0.4.0.data/purelib/rogue.py"],
)
def test_bind_installed_wheel_rejects_unsupported_recorded_wheel_layout(
    tmp_path: Path, rogue_path: str
) -> None:
    site_packages, wheel = installed_tree(tmp_path / "site-packages")
    with zipfile.ZipFile(wheel) as source:
        entries = {
            item.filename: source.read(item) for item in source.infolist() if not item.is_dir()
        }
    record_name = "simcairn-0.4.0.dist-info/RECORD"
    entries[rogue_path] = b"untrusted\n"
    entries[record_name] += f"{rogue_path},sha256=NOT-A-DIGEST,not-a-size\n".encode()
    with zipfile.ZipFile(wheel, "w") as destination:
        for filename, payload in entries.items():
            destination.writestr(filename, payload)
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps(raw_syft_document()), encoding="utf-8")

    with pytest.raises(ReleaseArtifactError, match="unsupported path"):
        bind_installed_wheel(
            sbom, site_packages, wheel, expected_name=NAME, expected_version=VERSION
        )


def test_bind_installed_wheel_rejects_unrecorded_installed_file(tmp_path: Path) -> None:
    site_packages, wheel = installed_tree(tmp_path / "site-packages")
    (site_packages / "simcairn" / "post_install_probe.py").write_text(
        "probe = True\n", encoding="utf-8"
    )
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps(raw_syft_document()), encoding="utf-8")

    with pytest.raises(ReleaseArtifactError, match="tree and RECORD file sets differ"):
        bind_installed_wheel(
            sbom, site_packages, wheel, expected_name=NAME, expected_version=VERSION
        )


@pytest.mark.parametrize(
    "alias_template",
    [
        "simcairn/../simcairn/__init__.py",
        "../{site_packages}/simcairn/__init__.py",
    ],
)
def test_bind_installed_wheel_rejects_target_tree_record_alias(
    tmp_path: Path, alias_template: str
) -> None:
    site_packages, wheel = installed_tree(tmp_path / "site-packages")
    record = site_packages / "simcairn-0.4.0.dist-info" / "RECORD"
    with record.open("a", encoding="utf-8", newline="") as stream:
        stream.write(f"{alias_template.format(site_packages=site_packages.name)},,\n")
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps(raw_syft_document()), encoding="utf-8")

    with pytest.raises(
        ReleaseArtifactError, match=r"interior parent path|aliases an installed path"
    ):
        bind_installed_wheel(
            sbom, site_packages, wheel, expected_name=NAME, expected_version=VERSION
        )


def test_bind_installed_wheel_measures_installer_generated_pyc(tmp_path: Path) -> None:
    site_packages, wheel = installed_tree(tmp_path / "site-packages")
    cache = site_packages / "simcairn" / "__pycache__"
    cache.mkdir()
    generated = cache / "__init__.cpython-311.pyc"
    generated.write_bytes(b"installer generated")
    record = site_packages / "simcairn-0.4.0.dist-info" / "RECORD"
    with record.open("a", encoding="utf-8", newline="") as stream:
        stream.write("simcairn/__pycache__/__init__.cpython-311.pyc,,\n")
    document = raw_syft_document()
    document["files"].append(  # type: ignore[union-attr]
        {
            "fileName": f"/{generated.relative_to(site_packages).as_posix()}",
            "SPDXID": "SPDXRef-File-pyc",
        }
    )
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps(document), encoding="utf-8")
    assert (
        bind_installed_wheel(
            sbom, site_packages, wheel, expected_name=NAME, expected_version=VERSION
        )
        == 4
    )
    validate_spdx_path(
        sbom,
        expected_name=NAME,
        expected_version=VERSION,
        expected_syft_version=SYFT_VERSION,
    )


def test_bind_installed_wheel_verifies_hashed_installer_metadata(tmp_path: Path) -> None:
    site_packages, wheel = installed_tree(tmp_path / "site-packages")
    dist_info = site_packages / "simcairn-0.4.0.dist-info"
    generated_payloads = {
        "INSTALLER": b"pip\n",
        "direct_url.json": b'{"dir_info": {}, "url": "file:///source"}',
    }
    record = dist_info / "RECORD"
    with record.open("a", encoding="utf-8", newline="") as stream:
        for filename, payload in generated_payloads.items():
            (dist_info / filename).write_bytes(payload)
            encoded = (
                base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).decode().rstrip("=")
            )
            stream.write(f"simcairn-0.4.0.dist-info/{filename},sha256={encoded},{len(payload)}\n")
    document = raw_syft_document()
    for filename in generated_payloads:
        document["files"].append(  # type: ignore[union-attr]
            {
                "fileName": f"/simcairn-0.4.0.dist-info/{filename}",
                "SPDXID": f"SPDXRef-File-{filename.replace('.', '-').replace('_', '-')}",
            }
        )
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps(document), encoding="utf-8")

    assert (
        bind_installed_wheel(
            sbom, site_packages, wheel, expected_name=NAME, expected_version=VERSION
        )
        == 5
    )
    validate_spdx_path(
        sbom,
        expected_name=NAME,
        expected_version=VERSION,
        expected_syft_version=SYFT_VERSION,
    )


@pytest.mark.parametrize(
    ("record_hash", "record_size"),
    [
        ("sha256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "4"),
        ("sha256=47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU", ""),
        ("", "4"),
    ],
)
def test_bind_installed_wheel_rejects_bad_installer_metadata_claim(
    tmp_path: Path, record_hash: str, record_size: str
) -> None:
    site_packages, wheel = installed_tree(tmp_path / "site-packages")
    dist_info = site_packages / "simcairn-0.4.0.dist-info"
    (dist_info / "INSTALLER").write_bytes(b"pip\n")
    record = dist_info / "RECORD"
    with record.open("a", encoding="utf-8", newline="") as stream:
        stream.write(f"simcairn-0.4.0.dist-info/INSTALLER,{record_hash},{record_size}\n")
    document = raw_syft_document()
    document["files"].append(  # type: ignore[union-attr]
        {
            "fileName": "/simcairn-0.4.0.dist-info/INSTALLER",
            "SPDXID": "SPDXRef-File-installer",
        }
    )
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ReleaseArtifactError, match="installer-generated RECORD entry"):
        bind_installed_wheel(
            sbom, site_packages, wheel, expected_name=NAME, expected_version=VERSION
        )


def test_bind_installed_wheel_rejects_a_syft_file_omission(tmp_path: Path) -> None:
    site_packages, wheel = installed_tree(tmp_path / "site-packages")
    document = raw_syft_document()
    document["files"].pop()  # type: ignore[union-attr]
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ReleaseArtifactError, match="omitted installed wheel files"):
        bind_installed_wheel(
            sbom,
            site_packages,
            wheel,
            expected_name=NAME,
            expected_version=VERSION,
        )


def test_bind_installed_wheel_accepts_existing_graph_edges_without_duplication(
    tmp_path: Path,
) -> None:
    site_packages, wheel = installed_tree(tmp_path / "site-packages")
    document = raw_syft_document()
    package_id = document["packages"][0]["SPDXID"]  # type: ignore[index]
    document["relationships"] = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": package_id,
        },
        {
            "spdxElementId": package_id,
            "relationshipType": "CONTAINS",
            "relatedSpdxElement": "SPDXRef-File-code",
        },
    ]
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps(document), encoding="utf-8")
    bind_installed_wheel(sbom, site_packages, wheel, expected_name=NAME, expected_version=VERSION)
    relationships = json.loads(sbom.read_text(encoding="utf-8"))["relationships"]
    identities = {
        (
            item["spdxElementId"],
            item["relationshipType"],
            item["relatedSpdxElement"],
        )
        for item in relationships
    }
    assert len(relationships) == len(identities) == 4


def test_bind_installed_wheel_rejects_bad_syft_file_and_relationship_shapes(tmp_path: Path) -> None:
    site_packages, wheel = installed_tree(tmp_path / "site-packages")
    duplicate = raw_syft_document()
    duplicate["files"].append(  # type: ignore[union-attr]
        {"fileName": "/simcairn/__init__.py", "SPDXID": "SPDXRef-File-copy"}
    )
    sbom = tmp_path / "duplicate.json"
    sbom.write_text(json.dumps(duplicate), encoding="utf-8")
    with pytest.raises(ReleaseArtifactError, match="repeats file identity"):
        bind_installed_wheel(
            sbom, site_packages, wheel, expected_name=NAME, expected_version=VERSION
        )

    malformed = raw_syft_document()
    malformed["relationships"] = ["not-an-object"]
    sbom = tmp_path / "relationships.json"
    sbom.write_text(json.dumps(malformed), encoding="utf-8")
    with pytest.raises(ReleaseArtifactError, match="relationships must"):
        bind_installed_wheel(
            sbom, site_packages, wheel, expected_name=NAME, expected_version=VERSION
        )


def test_bind_installed_wheel_reports_atomic_write_failure(tmp_path: Path, monkeypatch) -> None:
    site_packages, wheel = installed_tree(tmp_path / "site-packages")
    sbom = tmp_path / "sbom.json"
    original = json.dumps(raw_syft_document())
    sbom.write_text(original, encoding="utf-8")

    def fail_replace(_source, _destination):
        raise PermissionError("injected")

    monkeypatch.setattr(release_artifacts.os, "replace", fail_replace)
    with pytest.raises(ReleaseArtifactError, match="cannot write bound SBOM"):
        bind_installed_wheel(
            sbom, site_packages, wheel, expected_name=NAME, expected_version=VERSION
        )
    assert sbom.read_text(encoding="utf-8") == original
    assert not tuple(tmp_path.glob(".sbom.json.*.tmp"))


def test_checksum_writer_and_release_verifier_enforce_exact_four_assets(tmp_path: Path) -> None:
    populate_release_payloads(tmp_path)
    checksum_path = write_checksums(tmp_path, name=NAME, version=VERSION)
    assert checksum_path.name == "SHA256SUMS"
    assert len(checksum_path.read_text(encoding="ascii").splitlines()) == 3
    verify_release(tmp_path, name=NAME, version=VERSION, syft_version=SYFT_VERSION)

    (tmp_path / "unexpected.txt").write_text("not releasable", encoding="utf-8")
    with pytest.raises(ReleaseArtifactError, match="unexpected"):
        verify_release(tmp_path, name=NAME, version=VERSION, syft_version=SYFT_VERSION)


def test_release_verifier_rejects_tampered_payload(tmp_path: Path) -> None:
    populate_release_payloads(tmp_path)
    write_checksums(tmp_path, name=NAME, version=VERSION)
    wheel, _sdist = distribution_asset_names(NAME, VERSION)
    (tmp_path / wheel).write_bytes(b"tampered wheel")
    with pytest.raises(ReleaseArtifactError, match="SHA-256 mismatch"):
        verify_release(tmp_path, name=NAME, version=VERSION, syft_version=SYFT_VERSION)


def test_checksum_manifest_rejects_malformed_duplicate_and_wrong_subjects(tmp_path: Path) -> None:
    populate_release_payloads(tmp_path)
    checksum = tmp_path / "SHA256SUMS"
    checksum.write_text("malformed\n", encoding="ascii")
    with pytest.raises(ReleaseArtifactError, match="malformed"):
        release_artifacts.verify_checksums(tmp_path, name=NAME, version=VERSION)

    wheel, sdist = distribution_asset_names(NAME, VERSION)
    digest = "0" * 64
    checksum.write_text(
        f"{digest}  {wheel}\n{digest}  {wheel}\n{digest}  {sdist}\n",
        encoding="ascii",
    )
    with pytest.raises(ReleaseArtifactError, match="repeats"):
        release_artifacts.verify_checksums(tmp_path, name=NAME, version=VERSION)

    checksum.write_text(f"{digest}  {wheel}\n", encoding="ascii")
    with pytest.raises(ReleaseArtifactError, match="subjects"):
        release_artifacts.verify_checksums(tmp_path, name=NAME, version=VERSION)

    checksum.unlink()
    with pytest.raises(ReleaseArtifactError, match="cannot read checksum"):
        release_artifacts.verify_checksums(tmp_path, name=NAME, version=VERSION)


def test_checksum_writer_refuses_existing_manifest_and_nonregular_asset(tmp_path: Path) -> None:
    populate_release_payloads(tmp_path)
    (tmp_path / "SHA256SUMS").write_text("existing\n", encoding="ascii")
    with pytest.raises(ReleaseArtifactError, match="asset set mismatch"):
        write_checksums(tmp_path, name=NAME, version=VERSION)

    (tmp_path / "SHA256SUMS").unlink()
    wheel, _sdist = distribution_asset_names(NAME, VERSION)
    (tmp_path / wheel).unlink()
    (tmp_path / wheel).mkdir()
    with pytest.raises(ReleaseArtifactError, match="non-regular"):
        write_checksums(tmp_path, name=NAME, version=VERSION)


def test_checksum_writer_reports_a_manifest_creation_race(tmp_path: Path, monkeypatch) -> None:
    populate_release_payloads(tmp_path)
    original = release_artifacts._require_exact_files

    def race(directory: Path, expected: frozenset[str]) -> None:
        original(directory, expected)
        (directory / "SHA256SUMS").write_text("racer\n", encoding="ascii")

    monkeypatch.setattr(release_artifacts, "_require_exact_files", race)
    with pytest.raises(ReleaseArtifactError, match="cannot create"):
        write_checksums(tmp_path, name=NAME, version=VERSION)


def test_spdx_loader_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    populate_release_payloads(tmp_path)
    (tmp_path / "SBOM.spdx.json").write_text(
        '{"spdxVersion":"SPDX-2.3","spdxVersion":"SPDX-2.2"}', encoding="utf-8"
    )
    with pytest.raises(ReleaseArtifactError, match="duplicate JSON key"):
        validate_spdx_path(
            tmp_path / "SBOM.spdx.json",
            expected_name=NAME,
            expected_version=VERSION,
            expected_syft_version=SYFT_VERSION,
        )


def test_spdx_loader_rejects_non_standard_json_constants(tmp_path: Path) -> None:
    sbom = tmp_path / "sbom.json"
    sbom.write_text('{"spdxVersion":"SPDX-2.3","unexpected":NaN}', encoding="utf-8")
    with pytest.raises(ReleaseArtifactError, match="non-standard JSON constant"):
        validate_spdx_path(
            sbom,
            expected_name=NAME,
            expected_version=VERSION,
            expected_syft_version=SYFT_VERSION,
        )


def test_spdx_loader_rejects_invalid_root_and_size_limit(tmp_path: Path, monkeypatch) -> None:
    sbom = tmp_path / "sbom.json"
    sbom.write_text("[]", encoding="utf-8")
    with pytest.raises(ReleaseArtifactError, match="root must"):
        release_artifacts.load_spdx(sbom)
    sbom.write_text("{", encoding="utf-8")
    with pytest.raises(ReleaseArtifactError, match="JSON"):
        release_artifacts.load_spdx(sbom)
    monkeypatch.setattr(release_artifacts, "_MAX_SBOM_BYTES", 1)
    sbom.write_text("{}", encoding="utf-8")
    with pytest.raises(ReleaseArtifactError, match="exceeds"):
        release_artifacts.load_spdx(sbom)


def test_spdx_loader_bounds_the_file_read(tmp_path: Path, monkeypatch) -> None:
    sbom = tmp_path / "sbom.json"
    sbom.write_text("{}", encoding="utf-8")
    observed_reads: list[int] = []
    original_open = Path.open

    class ReadSpy(BytesIO):
        def read(self, size: int = -1) -> bytes:
            observed_reads.append(size)
            return super().read(size)

    def open_spy(path: Path, mode: str = "r", *args: object, **kwargs: object):
        if path == sbom and mode == "rb":
            return ReadSpy(b"{}")
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(release_artifacts, "_MAX_SBOM_BYTES", 7)
    monkeypatch.setattr(Path, "open", open_spy)

    assert release_artifacts.load_spdx(sbom) == {}
    assert observed_reads == [8]


def test_spdx_loader_normalizes_excessive_json_nesting(tmp_path: Path) -> None:
    sbom = tmp_path / "sbom.json"
    sbom.write_text("[" * 2_000 + "0" + "]" * 2_000, encoding="utf-8")

    with pytest.raises(ReleaseArtifactError, match="JSON"):
        release_artifacts.load_spdx(sbom)


def test_spdx_loader_bounds_json_nodes(tmp_path: Path, monkeypatch) -> None:
    sbom = tmp_path / "sbom.json"
    sbom.write_text('{"first": 1, "second": 2}', encoding="utf-8")
    monkeypatch.setattr(release_artifacts, "_MAX_JSON_NODES", 2)

    with pytest.raises(ReleaseArtifactError, match="complexity"):
        release_artifacts.load_spdx(sbom)


@pytest.mark.parametrize("parser_error", [OverflowError("depth"), ValueError("parser")])
def test_spdx_loader_normalizes_json_parser_errors(
    tmp_path: Path, monkeypatch, parser_error: Exception
) -> None:
    sbom = tmp_path / "sbom.json"
    sbom.write_text("{}", encoding="utf-8")

    def fail_parser(*args: object, **kwargs: object) -> object:
        raise parser_error

    monkeypatch.setattr(release_artifacts.json, "loads", fail_parser)
    with pytest.raises(ReleaseArtifactError, match="valid UTF-8 JSON"):
        release_artifacts.load_spdx(sbom)


def test_spdx_validation_does_not_mutate_input() -> None:
    document = spdx_document()
    original = copy.deepcopy(document)
    validate_spdx(
        document,
        expected_name=NAME,
        expected_version=VERSION,
        expected_syft_version=SYFT_VERSION,
    )
    assert document == original


def test_release_artifact_cli_exercises_every_operation(tmp_path: Path) -> None:
    bind_root = tmp_path / "bind"
    bind_root.mkdir()
    site_packages, wheel = installed_tree(bind_root / "site-packages")
    sbom = bind_root / "sbom.json"
    sbom.write_text(json.dumps(raw_syft_document()), encoding="utf-8")
    assert (
        main(
            [
                "bind-installed-wheel",
                "--sbom",
                str(sbom),
                "--site-packages",
                str(site_packages),
                "--installation-root",
                str(site_packages),
                "--wheel",
                str(wheel),
                "--name",
                NAME,
                "--version",
                VERSION,
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "validate-sbom",
                "--sbom",
                str(sbom),
                "--name",
                NAME,
                "--version",
                VERSION,
                "--syft-version",
                SYFT_VERSION,
            ]
        )
        == 0
    )

    release = tmp_path / "release"
    release.mkdir()
    populate_release_payloads(release)
    assert (
        main(
            [
                "write-checksums",
                "--directory",
                str(release),
                "--name",
                NAME,
                "--version",
                VERSION,
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "verify-release",
                "--directory",
                str(release),
                "--name",
                NAME,
                "--version",
                VERSION,
                "--syft-version",
                SYFT_VERSION,
            ]
        )
        == 0
    )


def test_release_artifact_cli_reports_validation_error(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"
    with pytest.raises(SystemExit, match="2"):
        main(
            [
                "validate-sbom",
                "--sbom",
                str(missing),
                "--name",
                NAME,
                "--version",
                VERSION,
                "--syft-version",
                SYFT_VERSION,
            ]
        )
