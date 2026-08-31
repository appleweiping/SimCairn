from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from simcairn.cli import main
from simcairn.manifest import load_manifest
from simcairn.sky130 import (
    Sky130ConfigurationError,
    Sky130Pins,
    _archive_digest,
    configure_sky130,
    load_sizing_decision,
)
from simcairn.sweeps import expand_sweep

REVISION = "a" * 40
SIGNATURE = "b" * 64
SOURCE_BYTES = b'{"fixture":"fake SKY130 provenance"}\n'
SOURCE = hashlib.sha256(SOURCE_BYTES).hexdigest()


def _body() -> dict[str, Any]:
    return {
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
        "variables": {"bias_ua": 50.0, "compensation_pf": 1.0, "length_um": 0.6, "width_um": 4.5},
        "proxy_metrics": {
            "gain_db": 20.0,
            "phase_margin_deg": 50.0,
            "power_mw": 0.1,
            "area_um2": 10.0,
            "bandwidth_mhz": 100.0,
        },
        "disclaimer": "Proxy only.",
    }


def _decision(path: Path, mutate: Any = None) -> Path:
    body = _body()
    if mutate is not None:
        mutate(body)
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


def _load(path: Path, *, topology: str = "TL-test", signature: str = SIGNATURE) -> Any:
    return load_sizing_decision(
        path,
        expected_topology=topology,
        expected_signature=signature,
        **_anchors(path),
    )


def _pdk(root: Path) -> Path:
    pdk = root / "versions" / REVISION / "sky130A"
    spice = pdk / "libs.ref" / "sky130_fd_pr" / "spice"
    spice.mkdir(parents=True)
    config = pdk / ".config"
    config.mkdir()
    (config / "nodeinfo.json").write_bytes(SOURCE_BYTES)
    for suffix in ("mismatch.corner", "tt.pm3", "ss.pm3", "ff.pm3"):
        (spice / f"sky130_fd_pr__nfet_01v8__{suffix}.spice").write_text(
            f"* {suffix}\n", encoding="ascii"
        )
    return pdk


def _archive(pdk: Path) -> str:
    spice = pdk / "libs.ref" / "sky130_fd_pr" / "spice"
    digests = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(spice.iterdir())
    }
    return _archive_digest(digests)


def _pins(pdk: Path, *, revision: str = REVISION) -> Sky130Pins:
    spice = pdk / "libs.ref" / "sky130_fd_pr" / "spice"
    return Sky130Pins(
        revision=revision,
        nodeinfo_sha256=SOURCE,
        common_asset_sha256="c" * 64,
        primitive_asset_sha256="d" * 64,
        model_sha256={
            path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in spice.iterdir()
        },
    )


def _configure_with(
    decision: Path,
    output: Path,
    pdk: Path,
    pins: Sky130Pins,
) -> Path:
    return configure_sky130(
        decision,
        output,
        expected_topology="TL-test",
        expected_signature=SIGNATURE,
        **_anchors(decision),
        pdk_root=pdk,
        pins=pins,
    )


def _configure(tmp_path: Path) -> Path:
    pdk = _pdk(tmp_path / "pdk")
    decision = _decision(tmp_path / "decision-source.json")
    return configure_sky130(
        decision,
        tmp_path / "configured",
        expected_topology="TL-test",
        expected_signature=SIGNATURE,
        **_anchors(decision),
        pdk_root=pdk,
        pins=_pins(pdk),
    )


def test_configures_content_bound_27_point_manifest(tmp_path: Path) -> None:
    manifest_path = _configure(tmp_path)
    configured = manifest_path.parent
    manifest = load_manifest(manifest_path)
    assert len(expand_sweep(manifest.sweep)) == 27
    assert len(manifest.measures) == 5
    deck = (configured / "sky130_common_source.sp.tmpl").read_text(encoding="ascii")
    assert ".control" not in deck and "\nlet " not in deck and "\nprint " not in deck
    assert "w=4.5u l=0.6u" in deck
    assert "RLOAD vdd out 15000" in deck
    assert "CLOAD out 0 1p" in deck
    provenance = json.loads((configured / "pdk-provenance.json").read_text(encoding="ascii"))
    assert provenance["decision_sha256"] == _load(tmp_path / "decision-source.json").digest
    assert provenance["pdk"]["nodeinfo_sha256"] == SOURCE
    assert set(provenance["pdk"]["model_sha256"]) == {
        "sky130_fd_pr__nfet_01v8__mismatch.corner.spice",
        "sky130_fd_pr__nfet_01v8__tt.pm3.spice",
        "sky130_fd_pr__nfet_01v8__ss.pm3.spice",
        "sky130_fd_pr__nfet_01v8__ff.pm3.spice",
    }


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(version=True),
        lambda value: value.update(version=1.0),
        lambda value: value["source"].update(topology_id="wrong"),
        lambda value: value["source"].update(topology_signature="0" * 64),
        lambda value: value["variables"].update(width_um=float("inf")),
        lambda value: value["variables"].update(width_um=10**400),
        lambda value: value["variables"].update(extra=1),
        lambda value: value["selection"].update(budget=True),
        lambda value: value["selection"].update(budget=0),
        lambda value: value["selection"].update(algorithm="random"),
        lambda value: value["selection"].update(policy="unknown"),
        lambda value: value["variables"].update(width_um=40.1),
        lambda value: value["variables"].update(length_um=0.17),
        lambda value: value["variables"].update(bias_ua=501.0),
        lambda value: value["variables"].update(compensation_pf=0.09),
        lambda value: value["proxy_metrics"].update(extra=1.0),
        lambda value: value.update(disclaimer=""),
        lambda value: value["variables"].update(bias_ua="50"),
        lambda value: value["variables"].update(bias_ua=0.0),
        lambda value: value["source"].update(benchmark_sha256="bad"),
    ],
)
def test_rejects_adversarial_decisions(tmp_path: Path, mutation: Any) -> None:
    path = _decision(tmp_path / "decision.json", mutation)
    with pytest.raises(Sky130ConfigurationError):
        _load(path)


def test_rejects_tampered_digest_and_duplicate_keys(tmp_path: Path) -> None:
    path = _decision(tmp_path / "decision.json")
    value = json.loads(path.read_text(encoding="utf-8"))
    value["variables"]["width_um"] = 9.0
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(Sky130ConfigurationError, match="does not match"):
        _load(path)


def test_rejects_attacker_resigned_decision_against_external_anchor(tmp_path: Path) -> None:
    path = _decision(tmp_path / "decision.json")
    anchors = _anchors(path)
    value = json.loads(path.read_text(encoding="utf-8"))
    value["variables"]["width_um"] = 9.0
    del value["decision_sha256"]
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    value["decision_sha256"] = hashlib.sha256(canonical.encode("ascii")).hexdigest()
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(Sky130ConfigurationError, match="external trust anchor"):
        load_sizing_decision(
            path,
            expected_topology="TL-test",
            expected_signature=SIGNATURE,
            **anchors,
        )


def test_rejects_oversized_decision_before_parsing(tmp_path: Path) -> None:
    path = tmp_path / "oversized.json"
    path.write_bytes(b" " * (1024 * 1024 + 1))
    with pytest.raises(Sky130ConfigurationError, match="1 MiB"):
        load_sizing_decision(
            path,
            expected_topology="TL-test",
            expected_signature=SIGNATURE,
            expected_decision_sha256="0" * 64,
            expected_benchmark_sha256="1" * 64,
            expected_comparison_sha256="2" * 64,
        )


def test_wraps_deep_json_parser_resource_error(tmp_path: Path) -> None:
    path = tmp_path / "deep.json"
    path.write_text("[" * 1500 + "0" + "]" * 1500, encoding="ascii")
    with pytest.raises(Sky130ConfigurationError):
        load_sizing_decision(
            path,
            expected_topology="TL-test",
            expected_signature=SIGNATURE,
            expected_decision_sha256="0" * 64,
            expected_benchmark_sha256="1" * 64,
            expected_comparison_sha256="2" * 64,
        )


def test_rejects_missing_malformed_and_nonfinite_decision(tmp_path: Path) -> None:
    for content in ("{", '{"value":NaN}'):
        path = tmp_path / f"bad-{len(content)}.json"
        path.write_text(content, encoding="utf-8")
        with pytest.raises(Sky130ConfigurationError):
            load_sizing_decision(
                path,
                expected_topology="TL-test",
                expected_signature=SIGNATURE,
                expected_decision_sha256="0" * 64,
                expected_benchmark_sha256="1" * 64,
                expected_comparison_sha256="2" * 64,
            )
    with pytest.raises(Sky130ConfigurationError, match="cannot read"):
        load_sizing_decision(
            tmp_path / "missing.json",
            expected_topology="TL-test",
            expected_signature=SIGNATURE,
            expected_decision_sha256="0" * 64,
            expected_benchmark_sha256="1" * 64,
            expected_comparison_sha256="2" * 64,
        )
    path.write_text('{"schema":"x","schema":"y"}', encoding="utf-8")
    with pytest.raises(Sky130ConfigurationError, match="duplicate"):
        load_sizing_decision(
            path,
            expected_topology="TL-test",
            expected_signature=SIGNATURE,
            expected_decision_sha256="0" * 64,
            expected_benchmark_sha256="1" * 64,
            expected_comparison_sha256="2" * 64,
        )


def test_rejects_wrong_revision_path_missing_and_symbolic_models(tmp_path: Path) -> None:
    decision = _decision(tmp_path / "decision.json")
    pdk = _pdk(tmp_path / "pdk")
    with pytest.raises(Sky130ConfigurationError, match="pinned revision"):
        _configure_with(decision, tmp_path / "out", pdk, _pins(pdk, revision="e" * 40))
    with pytest.raises(Sky130ConfigurationError, match="40 lowercase"):
        _configure_with(decision, tmp_path / "out", pdk, _pins(pdk, revision="ABC"))
    wrong = tmp_path / "not-sky130A"
    wrong.mkdir()
    with pytest.raises(Sky130ConfigurationError, match="sky130A"):
        _configure_with(decision, tmp_path / "out", wrong, _pins(pdk))
    model = pdk / "libs.ref" / "sky130_fd_pr" / "spice" / "sky130_fd_pr__nfet_01v8__ff.pm3.spice"
    model.unlink()
    with pytest.raises(Sky130ConfigurationError, match="absent"):
        _configure_with(decision, tmp_path / "out", pdk, _pins(pdk))
    try:
        model.symlink_to(
            pdk / "libs.ref" / "sky130_fd_pr" / "spice" / "sky130_fd_pr__nfet_01v8__tt.pm3.spice"
        )
    except OSError:
        pytest.skip("symbolic links are not available to this Windows account")
    with pytest.raises(Sky130ConfigurationError, match="symbolic"):
        _configure_with(decision, tmp_path / "out", pdk, _pins(pdk))


def test_refuses_overwrite_without_altering_existing_directory(tmp_path: Path) -> None:
    output = tmp_path / "configured"
    output.mkdir()
    marker = output / "keep"
    marker.write_text("untouched", encoding="ascii")
    decision = _decision(tmp_path / "decision.json")
    pdk = _pdk(tmp_path / "pdk")
    with pytest.raises(Sky130ConfigurationError, match="overwrite"):
        _configure_with(decision, output, pdk, _pins(pdk))
    assert marker.read_text(encoding="ascii") == "untouched"


def test_rejects_unverified_nodeinfo_and_model_bytes(tmp_path: Path) -> None:
    decision = _decision(tmp_path / "decision.json")
    pdk = _pdk(tmp_path / "pdk")
    with pytest.raises(Sky130ConfigurationError, match="nodeinfo"):
        _configure_with(
            decision,
            tmp_path / "source-fail",
            pdk,
            Sky130Pins(REVISION, "0" * 64, "c" * 64, "d" * 64, _pins(pdk).model_sha256),
        )
    bad_models = dict(_pins(pdk).model_sha256)
    bad_models["sky130_fd_pr__nfet_01v8__tt.pm3.spice"] = "0" * 64
    with pytest.raises(Sky130ConfigurationError, match="model"):
        _configure_with(
            decision,
            tmp_path / "model-fail",
            pdk,
            Sky130Pins(REVISION, SOURCE, "c" * 64, "d" * 64, bad_models),
        )
    assert not (tmp_path / "model-fail").exists()


def test_provenance_is_independent_of_pdk_root(tmp_path: Path) -> None:
    decision = _decision(tmp_path / "decision.json")
    products: list[bytes] = []
    for index in range(2):
        pdk = _pdk(tmp_path / f"pdk-{index}")
        output = tmp_path / f"out-{index}"
        _configure_with(decision, output, pdk, _pins(pdk))
        products.append((output / "pdk-provenance.json").read_bytes())
    assert products[0] == products[1]


def test_cli_reports_unpinned_pdk_without_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    decision = _decision(tmp_path / "decision.json")
    code = main(
        [
            "configure-sky130",
            str(decision),
            str(tmp_path / "out"),
            "--expected-topology",
            "TL-test",
            "--expected-signature",
            SIGNATURE,
            "--expected-decision-sha256",
            _anchors(decision)["expected_decision_sha256"],
            "--expected-benchmark-sha256",
            _anchors(decision)["expected_benchmark_sha256"],
            "--expected-comparison-sha256",
            _anchors(decision)["expected_comparison_sha256"],
            "--pdk-root",
            str(_pdk(tmp_path / "pdk")),
        ]
    )
    assert code == 2
    assert "pinned revision" in capsys.readouterr().err
