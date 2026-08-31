"""Offline, content-bound GF180MCU common-source benchmark configurator."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from simcairn.fingerprints import stable_json
from simcairn.sky130 import SizingDecision, load_sizing_decision

_HEX = frozenset("0123456789abcdef")
_MODEL_NAMES = ("design.ngspice", "sm141064.spice")
_CORNER_FILES = {
    "tt.corner.spice": ".lib sm141064.spice typical\n",
    "ss.corner.spice": ".lib sm141064.spice ss\n",
    "ff.corner.spice": ".lib sm141064.spice ff\n",
}


@dataclass(frozen=True)
class GF180Pins:
    """Trusted content pins for one official Ciel GF180MCU release."""

    revision: str
    nodeinfo_sha256: str
    common_asset_sha256: str
    primitive_asset_sha256: str
    model_sha256: Mapping[str, str]


GF180_PINS = GF180Pins(
    revision="1689ac3f2dc763876eaf967227c7dfe831b031ae",
    nodeinfo_sha256="8b96003d04744651f80946144035a78ed8862c25e87e879c4ee573bee08f7705",
    common_asset_sha256="256586ecaea68886ce57942d83a86f82e6e1bc081badf6c9c9b70755f3456a41",
    primitive_asset_sha256="6b26fbf4aed755bddefcdb3610f5f957cc0a8a019e72c3abc9c611f9947d1f62",
    model_sha256={
        "design.ngspice": "7e222f050318388f37543a64fbd0be55cc15e4b93f57501a09f7c159c4c9e561",
        "sm141064.spice": "69a7ab877344a6d477fdd11440457f64e7ad88a624504a737a161da463de8bc8",
    },
)


class GF180ConfigurationError(ValueError):
    """A PDK, sizing decision, or destination violates the GF180 contract."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _hex_digest(value: str, name: str) -> str:
    if len(value) != 64 or any(character not in _HEX for character in value):
        raise GF180ConfigurationError(f"{name} must be 64 lowercase hexadecimal characters")
    return value


def _revision(value: str) -> str:
    if len(value) != 40 or any(character not in _HEX for character in value):
        raise GF180ConfigurationError("PDK revision must be 40 lowercase hexadecimal characters")
    return value


def _model_set_digest(model_digests: Mapping[str, str]) -> str:
    encoded = json.dumps(model_digests, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("ascii")).hexdigest()


def _safe_pdk(pdk_root: Path, pins: GF180Pins) -> tuple[Path, Path]:
    _revision(pins.revision)
    _hex_digest(pins.common_asset_sha256, "common asset SHA-256")
    _hex_digest(pins.primitive_asset_sha256, "primitive asset SHA-256")
    if set(pins.model_sha256) != set(_MODEL_NAMES):
        raise GF180ConfigurationError("model SHA-256 pins have missing or unknown files")
    for name, digest in pins.model_sha256.items():
        _hex_digest(digest, f"model SHA-256 for {name}")
    resolved = pdk_root.resolve(strict=True)
    if not resolved.is_dir() or resolved.name != "gf180mcuC":
        raise GF180ConfigurationError("PDK root must resolve to a gf180mcuC directory")
    if pins.revision not in resolved.parts:
        raise GF180ConfigurationError("PDK root does not resolve inside the pinned revision")
    model_directory = resolved / "libs.tech" / "ngspice"
    if not model_directory.is_dir():
        raise GF180ConfigurationError("PDK does not contain the expected ngspice model directory")
    nodeinfo = resolved / ".config" / "nodeinfo.json"
    if (
        nodeinfo.is_symlink()
        or not nodeinfo.is_file()
        or _sha256(nodeinfo) != _hex_digest(pins.nodeinfo_sha256, "nodeinfo SHA-256")
    ):
        raise GF180ConfigurationError("PDK nodeinfo.json does not match the pinned release")
    return resolved, model_directory


def _validate_gf180_geometry(decision: SizingDecision) -> None:
    if decision.width_um < 0.22 or decision.length_um < 0.28:
        raise GF180ConfigurationError("sizing decision is below GF180MCU 3.3 V geometry bounds")


def _safe_destination(output: str | Path) -> Path:
    raw = Path(output).absolute()
    current = raw
    while current != current.parent:
        if current.exists() and current.is_symlink():
            raise GF180ConfigurationError("destination path must not traverse a symlink")
        current = current.parent
    return raw.resolve(strict=False)


def _deck(decision: SizingDecision) -> str:
    resistance = 1_650_000.0 / decision.bias_ua
    return f"""* GF180MCU 3.3 V common-source sizing characterization; generated offline.
.include design.ngspice
.param sw_stat_global=0 sw_stat_mismatch=0
.include @{{CORNER}}.corner.spice
.param VDD=@{{VDD}} TEMP_C=@{{TEMP_C}}
.temp {{TEMP_C}}
VSUPPLY vdd 0 {{VDD}}
VIN in 0 dc 1.0 ac 1 sin(1.0 1m 100k)
RLOAD vdd out {resistance:.12g}
XMN out in 0 0 nfet_03v3 w={decision.width_um:.12g}u l={decision.length_um:.12g}u nf=1 m=1
CLOAD out 0 {decision.compensation_pf:.12g}p
.save all
.ac dec 40 10 1G
.tran 50n 100u
.measure tran output_v_raw avg v(out) from=50u to=100u
.measure tran output_pp_v_raw pp v(out) from=50u to=100u
.measure tran supply_current_a_raw avg par('-i(VSUPPLY)') from=50u to=100u
.measure tran power_w_raw avg par('v(vdd)*-i(VSUPPLY)') from=50u to=100u
.measure tran output_v param='output_v_raw'
.measure tran output_pp_v param='output_pp_v_raw'
.measure tran gain_100khz param='output_pp_v_raw/0.002'
.measure tran supply_current_a param='supply_current_a_raw'
.measure tran power_w param='power_w_raw'
.end
"""


def _manifest() -> str:
    inputs = (
        "decision.json",
        "pdk-provenance.json",
        "design.ngspice",
        "sm141064.spice",
        *_CORNER_FILES,
    )
    text = """version = 1
[simulator]
adapter = "ngspice"
executable = "ngspice"
[template]
deck = "gf180_common_source.sp.tmpl"
inputs = [
"""
    text += "".join(f'  "{name}",\n' for name in inputs)
    text += """]
[sweep]
mode = "product"
CORNER = ["tt", "ss", "ff"]
VDD = ["2.97", "3.30", "3.63"]
TEMP_C = ["-40", "27", "125"]
[run]
timeout_seconds = 90
jobs = 4
fail_fast = false
[run.resources]
simulator = 4
"""
    for name, unit in (
        ("output_v", "V"),
        ("output_pp_v", "V"),
        ("gain_100khz", "1"),
        ("supply_current_a", "A"),
        ("power_w", "W"),
    ):
        text += (
            f'[[measure]]\nname = "{name}"\nsource = "metrics.json"\n'
            f'field = "{name}"\nunit = "{unit}"\n'
        )
    return text


def configure_gf180(
    decision_path: str | Path,
    output: str | Path,
    *,
    expected_topology: str,
    expected_signature: str,
    expected_decision_sha256: str,
    expected_benchmark_sha256: str,
    expected_comparison_sha256: str,
    pdk_root: str | Path,
    pins: GF180Pins = GF180_PINS,
) -> Path:
    """Create a self-contained, deterministic 27-point GF180MCU configuration."""
    decision = load_sizing_decision(
        decision_path,
        expected_topology=expected_topology,
        expected_signature=expected_signature,
        expected_decision_sha256=expected_decision_sha256,
        expected_benchmark_sha256=expected_benchmark_sha256,
        expected_comparison_sha256=expected_comparison_sha256,
    )
    _validate_gf180_geometry(decision)
    _, model_directory = _safe_pdk(Path(pdk_root), pins)
    destination = _safe_destination(output)
    if destination.exists():
        raise GF180ConfigurationError("destination already exists; refusing to overwrite")
    temporary = destination.with_name(f".{destination.name}.tmp-{os.getpid()}")
    if temporary.exists():
        raise GF180ConfigurationError("temporary destination already exists")
    try:
        temporary.mkdir(parents=True)
        model_digests: dict[str, str] = {}
        for name in _MODEL_NAMES:
            source = model_directory / name
            if source.is_symlink() or not source.is_file():
                raise GF180ConfigurationError(f"required PDK model is absent or symbolic: {name}")
            target = temporary / name
            shutil.copyfile(source, target)
            digest = _sha256(target)
            if digest != pins.model_sha256.get(name):
                raise GF180ConfigurationError(f"PDK model does not match its pin: {name}")
            model_digests[name] = digest
        for name, content in _CORNER_FILES.items():
            (temporary / name).write_text(content, encoding="ascii", newline="\n")
        (temporary / "decision.json").write_text(decision.canonical, encoding="ascii", newline="\n")
        provenance = {
            "schema": "org.simcairn.gf180-provenance",
            "version": 1,
            "decision_sha256": decision.digest,
            "topology_id": decision.topology_id,
            "topology_signature": decision.topology_signature,
            "pdk": {
                "variant": "gf180mcuC",
                "revision": pins.revision,
                "nodeinfo_sha256": pins.nodeinfo_sha256,
                "official_asset_sha256": {
                    "common.tar.zst": pins.common_asset_sha256,
                    "gf180mcu_fd_pr.tar.zst": pins.primitive_asset_sha256,
                },
                "selected_model_set_sha256": _model_set_digest(model_digests),
                "model_sha256": model_digests,
            },
        }
        (temporary / "pdk-provenance.json").write_text(
            stable_json(provenance), encoding="ascii", newline="\n"
        )
        (temporary / "gf180_common_source.sp.tmpl").write_text(
            _deck(decision), encoding="ascii", newline="\n"
        )
        (temporary / "simcairn.toml").write_text(_manifest(), encoding="ascii", newline="\n")
        temporary.replace(destination)
    except Exception:
        if temporary.exists():
            shutil.rmtree(temporary)
        raise
    return destination / "simcairn.toml"
