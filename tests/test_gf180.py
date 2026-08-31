from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from simcairn import configure_gf180 as public_configure_gf180
from simcairn.cli import main
from simcairn.gf180 import (
    GF180ConfigurationError,
    GF180Pins,
    configure_gf180,
)
from simcairn.manifest import load_manifest
from simcairn.sky130 import Sky130ConfigurationError
from simcairn.sweeps import expand_sweep

REVISION = "a" * 40
SIGNATURE = "b" * 64
NODEINFO = b'{"fixture":"fake GF180 provenance"}\n'


def _decision(path: Path, *, width: float = 4.5, length: float = 0.6) -> Path:
    body: dict[str, Any] = {
        "schema": "org.biasweave.sizing-decision",
        "version": 1,
        "source": {
            "benchmark_sha256": "1" * 64,
            "comparison_sha256": "2" * 64,
            "topology_id": "TL-test",
            "topology_signature": SIGNATURE,
        },
        "selection": {
            "algorithm": "biasweave",
            "budget": 8,
            "seed": 4,
            "policy": "normalized-l1-to-observed-ideal-v1",
            "point_key": "3" * 64,
        },
        "variables": {
            "bias_ua": 50.0,
            "compensation_pf": 1.0,
            "length_um": length,
            "width_um": width,
        },
        "proxy_metrics": {
            "gain_db": 20.0,
            "phase_margin_deg": 50.0,
            "power_mw": 0.1,
            "area_um2": 10.0,
            "bandwidth_mhz": 100.0,
        },
        "disclaimer": "Proxy only.",
    }
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    body["decision_sha256"] = hashlib.sha256(encoded.encode("ascii")).hexdigest()
    path.write_text(json.dumps(body), encoding="utf-8")
    return path


def _anchors(path: Path) -> dict[str, str]:
    value = json.loads(path.read_text(encoding="utf-8"))
    return {
        "expected_decision_sha256": value["decision_sha256"],
        "expected_benchmark_sha256": value["source"]["benchmark_sha256"],
        "expected_comparison_sha256": value["source"]["comparison_sha256"],
    }


def _pdk(root: Path) -> Path:
    pdk = root / "versions" / REVISION / "gf180mcuC"
    models = pdk / "libs.tech" / "ngspice"
    models.mkdir(parents=True)
    config = pdk / ".config"
    config.mkdir()
    (config / "nodeinfo.json").write_bytes(NODEINFO)
    (models / "design.ngspice").write_text("* deterministic switches\n", encoding="ascii")
    (models / "sm141064.spice").write_text("* deterministic models\n", encoding="ascii")
    return pdk


def _pins(pdk: Path, *, revision: str = REVISION) -> GF180Pins:
    model_directory = pdk / "libs.tech" / "ngspice"
    return GF180Pins(
        revision=revision,
        nodeinfo_sha256=hashlib.sha256(NODEINFO).hexdigest(),
        common_asset_sha256="c" * 64,
        primitive_asset_sha256="d" * 64,
        model_sha256={
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in model_directory.iterdir()
        },
    )


def _configure(decision: Path, output: Path, pdk: Path, pins: GF180Pins | None = None) -> Path:
    return configure_gf180(
        decision,
        output,
        expected_topology="TL-test",
        expected_signature=SIGNATURE,
        **_anchors(decision),
        pdk_root=pdk,
        pins=_pins(pdk) if pins is None else pins,
    )


def test_configures_content_bound_27_point_gf180_manifest(tmp_path: Path) -> None:
    decision = _decision(tmp_path / "decision.json")
    pdk = _pdk(tmp_path / "pdk")
    manifest_path = _configure(decision, tmp_path / "configured", pdk)
    output = manifest_path.parent
    manifest = load_manifest(manifest_path)
    assert len(expand_sweep(manifest.sweep)) == 27
    assert len(manifest.measures) == 5
    deck = (output / "gf180_common_source.sp.tmpl").read_text(encoding="ascii")
    assert ".control" not in deck
    assert "w=4.5u l=0.6u" in deck
    assert "RLOAD vdd out 33000" in deck
    assert "CLOAD out 0 1p" in deck
    assert ".include @{CORNER}.corner.spice" in deck
    assert (output / "tt.corner.spice").read_text(encoding="ascii").endswith(" typical\n")
    provenance = json.loads((output / "pdk-provenance.json").read_text(encoding="ascii"))
    assert provenance["pdk"]["variant"] == "gf180mcuC"
    assert provenance["pdk"]["nodeinfo_sha256"] == _pins(pdk).nodeinfo_sha256
    assert set(provenance["pdk"]["model_sha256"]) == {
        "design.ngspice",
        "sm141064.spice",
    }


def test_products_are_byte_identical_across_pdk_roots(tmp_path: Path) -> None:
    decision = _decision(tmp_path / "decision.json")
    products: list[dict[str, bytes]] = []
    for index in range(2):
        pdk = _pdk(tmp_path / f"pdk-{index}")
        output = tmp_path / f"output-{index}"
        _configure(decision, output, pdk)
        products.append(
            {
                path.relative_to(output).as_posix(): path.read_bytes()
                for path in output.rglob("*")
                if path.is_file()
            }
        )
    assert products[0] == products[1]


def test_rejects_geometry_below_gf180_bounds(tmp_path: Path) -> None:
    decision = _decision(tmp_path / "decision.json", length=0.27)
    with pytest.raises(GF180ConfigurationError, match="geometry bounds"):
        _configure(decision, tmp_path / "output", _pdk(tmp_path / "pdk"))


def test_rejects_unrepresentable_decision_number(tmp_path: Path) -> None:
    decision = _decision(tmp_path / "decision.json", width=10**400)
    with pytest.raises(Sky130ConfigurationError, match="representable"):
        _configure(decision, tmp_path / "output", _pdk(tmp_path / "pdk"))


def test_rejects_untrusted_resigned_decision(tmp_path: Path) -> None:
    decision = _decision(tmp_path / "decision.json")
    anchors = _anchors(decision)
    value = json.loads(decision.read_text(encoding="utf-8"))
    value["variables"]["width_um"] = 9.0
    del value["decision_sha256"]
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    value["decision_sha256"] = hashlib.sha256(encoded.encode("ascii")).hexdigest()
    decision.write_text(json.dumps(value), encoding="utf-8")
    pdk = _pdk(tmp_path / "pdk")
    with pytest.raises(Sky130ConfigurationError, match="external trust anchor"):
        configure_gf180(
            decision,
            tmp_path / "output",
            expected_topology="TL-test",
            expected_signature=SIGNATURE,
            **anchors,
            pdk_root=pdk,
            pins=_pins(pdk),
        )


def test_rejects_wrong_variant_revision_and_metadata(tmp_path: Path) -> None:
    decision = _decision(tmp_path / "decision.json")
    pdk = _pdk(tmp_path / "pdk")
    pins = _pins(pdk)
    with pytest.raises(GF180ConfigurationError, match="pinned revision"):
        _configure(decision, tmp_path / "bad-revision", pdk, _pins(pdk, revision="e" * 40))
    wrong = tmp_path / "versions" / REVISION / "gf180mcuA"
    wrong.mkdir(parents=True)
    with pytest.raises(GF180ConfigurationError, match="gf180mcuC"):
        _configure(decision, tmp_path / "bad-variant", wrong, pins)
    (pdk / ".config" / "nodeinfo.json").write_text("tampered", encoding="ascii")
    with pytest.raises(GF180ConfigurationError, match="nodeinfo"):
        _configure(decision, tmp_path / "bad-nodeinfo", pdk, pins)


def test_rejects_missing_tampered_and_symbolic_models(tmp_path: Path) -> None:
    decision = _decision(tmp_path / "decision.json")
    pdk = _pdk(tmp_path / "pdk")
    pins = _pins(pdk)
    model = pdk / "libs.tech" / "ngspice" / "sm141064.spice"
    model.write_text("tampered\n", encoding="ascii")
    with pytest.raises(GF180ConfigurationError, match="pin"):
        _configure(decision, tmp_path / "tampered", pdk, pins)
    model.unlink()
    with pytest.raises(GF180ConfigurationError, match="absent"):
        _configure(decision, tmp_path / "missing", pdk, pins)
    try:
        model.symlink_to(pdk / "libs.tech" / "ngspice" / "design.ngspice")
    except OSError:
        pytest.skip("symbolic links are not available to this Windows account")
    with pytest.raises(GF180ConfigurationError, match="symbolic"):
        _configure(decision, tmp_path / "symbolic", pdk, pins)


def test_refuses_existing_destination_without_altering_it(tmp_path: Path) -> None:
    decision = _decision(tmp_path / "decision.json")
    output = tmp_path / "output"
    output.mkdir()
    marker = output / "keep"
    marker.write_text("untouched", encoding="ascii")
    with pytest.raises(GF180ConfigurationError, match="overwrite"):
        _configure(decision, output, _pdk(tmp_path / "pdk"))
    assert marker.read_text(encoding="ascii") == "untouched"


def test_rejects_symbolic_destination_ancestor(tmp_path: Path) -> None:
    decision = _decision(tmp_path / "decision.json")
    pdk = _pdk(tmp_path / "pdk")
    real = tmp_path / "real-parent"
    real.mkdir()
    symbolic = tmp_path / "symbolic-parent"
    try:
        symbolic.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("symbolic links are not available to this Windows account")
    with pytest.raises(GF180ConfigurationError, match="symlink"):
        _configure(decision, symbolic / "output", pdk)


def test_public_api_and_cli_report_unpinned_pdk(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert public_configure_gf180 is configure_gf180
    decision = _decision(tmp_path / "decision.json")
    anchors = _anchors(decision)
    code = main(
        [
            "configure-gf180",
            str(decision),
            str(tmp_path / "output"),
            "--expected-topology",
            "TL-test",
            "--expected-signature",
            SIGNATURE,
            "--expected-decision-sha256",
            anchors["expected_decision_sha256"],
            "--expected-benchmark-sha256",
            anchors["expected_benchmark_sha256"],
            "--expected-comparison-sha256",
            anchors["expected_comparison_sha256"],
            "--pdk-root",
            str(_pdk(tmp_path / "pdk")),
        ]
    )
    assert code == 2
    assert "pinned revision" in capsys.readouterr().err
