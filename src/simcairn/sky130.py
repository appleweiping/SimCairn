"""Offline, content-bound SKY130 common-source benchmark configurator."""

from __future__ import annotations

import hashlib
import json
import math
import os
import shutil
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from simcairn.fingerprints import stable_json

_SCHEMA = "org.biasweave.sizing-decision"
_MODEL_NAMES = (
    "sky130_fd_pr__nfet_01v8__mismatch.corner.spice",
    "sky130_fd_pr__nfet_01v8__tt.pm3.spice",
    "sky130_fd_pr__nfet_01v8__ss.pm3.spice",
    "sky130_fd_pr__nfet_01v8__ff.pm3.spice",
)
_HEX = frozenset("0123456789abcdef")
_POLICY = "normalized-l1-to-observed-ideal-v1"
_MAX_DECISION_BYTES = 1024 * 1024


@dataclass(frozen=True)
class Sky130Pins:
    """Trusted content pins for one official Ciel release."""

    revision: str
    nodeinfo_sha256: str
    common_asset_sha256: str
    primitive_asset_sha256: str
    model_sha256: Mapping[str, str]


SKY130_PINS = Sky130Pins(
    revision="1689ac3f2dc763876eaf967227c7dfe831b031ae",
    nodeinfo_sha256="22173652261ed85a27f9edad6f7bb670bb8cc92f5a672f2c4e3bdcd6be502ea7",
    common_asset_sha256="92e3deed352b9a1aa53d47bc8f3de75e40dec013809c109d36ed4e8d13f74036",
    primitive_asset_sha256="79ac105aa2710acf358572aa3762b065bcdd9ed408dc64f3c32d9fb71cdd287e",
    model_sha256={
        "sky130_fd_pr__nfet_01v8__mismatch.corner.spice": (
            "24a3b29d7d7f26f99098811c31eb5497950a3aed520ab83768a96f35467fe818"
        ),
        "sky130_fd_pr__nfet_01v8__tt.pm3.spice": (
            "459eca963a134574cf7c842ad6d3814e7e0752bfb5de8e581c2f483534b5ad06"
        ),
        "sky130_fd_pr__nfet_01v8__ss.pm3.spice": (
            "4a70607ef6e016b426e9b447fe75ca417cdb7e44fe98ca6d7f0319656e65ed0c"
        ),
        "sky130_fd_pr__nfet_01v8__ff.pm3.spice": (
            "abbf671996e76bf3e75ea2bb26036fa17b99f92599330e25bb814ac498b600fe"
        ),
    },
)


class Sky130ConfigurationError(ValueError):
    """A decision, PDK, or destination violates the offline contract."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise Sky130ConfigurationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _hex_digest(value: object, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(c not in _HEX for c in value):
        raise Sky130ConfigurationError(f"{name} must be 64 lowercase hexadecimal characters")
    return value


def _number(value: object, name: str, *, positive: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise Sky130ConfigurationError(f"{name} must be numeric")
    try:
        converted = float(value)
    except (OverflowError, ValueError) as error:
        raise Sky130ConfigurationError(f"{name} must be a finite representable number") from error
    if not math.isfinite(converted) or (positive and converted <= 0.0):
        raise Sky130ConfigurationError(f"{name} must be finite and positive")
    return converted


def _exact(value: object, keys: set[str], name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise Sky130ConfigurationError(f"{name} has missing or unknown fields")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _archive_digest(model_digests: Mapping[str, str]) -> str:
    """Digest a deterministic logical archive without filesystem metadata."""
    payload = json.dumps(model_digests, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("ascii")).hexdigest()


def _safe_destination(output: str | Path) -> Path:
    raw = Path(output).absolute()
    current = raw
    while current != current.parent:
        if current.exists() and current.is_symlink():
            raise Sky130ConfigurationError("destination path must not traverse a symlink")
        current = current.parent
    return raw.resolve(strict=False)


@dataclass(frozen=True)
class SizingDecision:
    """Strictly verified fields needed to configure the characterization deck."""

    digest: str
    topology_id: str
    topology_signature: str
    width_um: float
    length_um: float
    bias_ua: float
    compensation_pf: float
    canonical: str


def load_sizing_decision(
    path: str | Path,
    *,
    expected_topology: str,
    expected_signature: str,
    expected_decision_sha256: str,
    expected_benchmark_sha256: str,
    expected_comparison_sha256: str,
) -> SizingDecision:
    """Load a bounded decision and verify it against caller-supplied trust anchors."""
    decision_path = Path(path)
    try:
        with decision_path.open("rb") as stream:
            payload = stream.read(_MAX_DECISION_BYTES + 1)
        if len(payload) > _MAX_DECISION_BYTES:
            raise Sky130ConfigurationError("sizing decision exceeds the 1 MiB limit")
        raw = payload.decode("utf-8")
        value = json.loads(
            raw,
            object_pairs_hook=_pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                Sky130ConfigurationError(f"non-finite JSON number: {token}")
            ),
        )
    except Sky130ConfigurationError:
        raise
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        RecursionError,
        OverflowError,
        ValueError,
    ) as error:
        raise Sky130ConfigurationError(f"cannot read sizing decision: {error}") from error
    top = _exact(
        value,
        {
            "schema",
            "version",
            "source",
            "selection",
            "variables",
            "proxy_metrics",
            "disclaimer",
            "decision_sha256",
        },
        "decision",
    )
    version = top["version"]
    if top["schema"] != _SCHEMA or type(version) is not int or version != 1:
        raise Sky130ConfigurationError("unsupported sizing-decision schema or version")
    source = _exact(
        top["source"],
        {"benchmark_sha256", "comparison_sha256", "topology_id", "topology_signature"},
        "source",
    )
    benchmark_digest = _hex_digest(source["benchmark_sha256"], "source.benchmark_sha256")
    comparison_digest = _hex_digest(source["comparison_sha256"], "source.comparison_sha256")
    if benchmark_digest != _hex_digest(expected_benchmark_sha256, "expected benchmark SHA-256"):
        raise Sky130ConfigurationError("decision benchmark does not match its trust anchor")
    if comparison_digest != _hex_digest(expected_comparison_sha256, "expected comparison SHA-256"):
        raise Sky130ConfigurationError("decision comparison does not match its trust anchor")
    topology = source["topology_id"]
    signature = _hex_digest(source["topology_signature"], "source.topology_signature")
    if not isinstance(topology, str) or topology != expected_topology:
        raise Sky130ConfigurationError("decision topology does not match the expected topology")
    if signature != _hex_digest(expected_signature, "expected signature"):
        raise Sky130ConfigurationError("decision topology signature does not match")
    selection = _exact(
        top["selection"], {"algorithm", "budget", "seed", "policy", "point_key"}, "selection"
    )
    if selection["algorithm"] != "biasweave" or selection["policy"] != _POLICY:
        raise Sky130ConfigurationError("selection algorithm or policy is unsupported")
    for key in ("budget", "seed"):
        if isinstance(selection[key], bool) or not isinstance(selection[key], int):
            raise Sky130ConfigurationError(f"selection.{key} must be an integer")
    if selection["budget"] <= 0:
        raise Sky130ConfigurationError("selection.budget must be positive")
    _hex_digest(selection["point_key"], "selection.point_key")
    variables = _exact(
        top["variables"], {"bias_ua", "compensation_pf", "length_um", "width_um"}, "variables"
    )
    for key in variables:
        _number(variables[key], f"variables.{key}", positive=True)
    metrics = _exact(
        top["proxy_metrics"],
        {"gain_db", "phase_margin_deg", "power_mw", "area_um2", "bandwidth_mhz"},
        "proxy_metrics",
    )
    for key, metric in metrics.items():
        _number(metric, f"proxy_metrics.{key}")
    if not isinstance(top["disclaimer"], str) or not top["disclaimer"]:
        raise Sky130ConfigurationError("disclaimer must be a non-empty string")
    supplied = _hex_digest(top["decision_sha256"], "decision_sha256")
    body = dict(top)
    del body["decision_sha256"]
    canonical_body = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    actual = hashlib.sha256(canonical_body.encode("ascii")).hexdigest()
    if actual != supplied:
        raise Sky130ConfigurationError("decision_sha256 does not match decision content")
    if supplied != _hex_digest(expected_decision_sha256, "expected decision SHA-256"):
        raise Sky130ConfigurationError("decision does not match its external trust anchor")
    width = _number(variables["width_um"], "variables.width_um", positive=True)
    length = _number(variables["length_um"], "variables.length_um", positive=True)
    bias = _number(variables["bias_ua"], "variables.bias_ua", positive=True)
    compensation = _number(variables["compensation_pf"], "variables.compensation_pf", positive=True)
    if not 0.5 <= width <= 40.0 or not 0.18 <= length <= 2.0:
        raise Sky130ConfigurationError("width or length is outside benchmark bounds")
    if not 5.0 <= bias <= 500.0 or not 0.1 <= compensation <= 10.0:
        raise Sky130ConfigurationError("bias or compensation is outside benchmark bounds")
    return SizingDecision(
        supplied,
        topology,
        signature,
        width,
        length,
        bias,
        compensation,
        stable_json(top),
    )


def _safe_pdk(pdk_root: Path, revision: str) -> tuple[Path, Path]:
    if len(revision) != 40 or any(character not in _HEX for character in revision):
        raise Sky130ConfigurationError("PDK revision must be 40 lowercase hexadecimal characters")
    resolved = pdk_root.resolve(strict=True)
    if not resolved.is_dir() or resolved.name != "sky130A":
        raise Sky130ConfigurationError("PDK root must resolve to a sky130A directory")
    if revision not in resolved.parts:
        raise Sky130ConfigurationError("PDK root does not resolve inside the pinned revision")
    spice = resolved / "libs.ref" / "sky130_fd_pr" / "spice"
    if not spice.is_dir():
        raise Sky130ConfigurationError("PDK does not contain the expected SPICE model directory")
    return resolved, spice


def _deck(decision: SizingDecision) -> str:
    resistance = 750000.0 / decision.bias_ua
    transistor = (
        "XMN out in 0 0 sky130_fd_pr__nfet_01v8 "
        f"w={decision.width_um:.12g}u l={decision.length_um:.12g}u nf=1 mult=1"
    )
    return f"""* SKY130 common-source sizing characterization; generated offline.
.include models/sky130_fd_pr__nfet_01v8__mismatch.corner.spice
.include models/sky130_fd_pr__nfet_01v8__@{{CORNER}}.pm3.spice
.param mc_mm_switch=0 VDD=@{{VDD}}
.temp @{{TEMP_C}}
VSUPPLY vdd 0 {{VDD}}
VIN in 0 dc 0.72 ac 1 sin(0.72 1m 100k)
RLOAD vdd out {resistance:.12g}
{transistor}
CLOAD out 0 {decision.compensation_pf:.12g}p
.save all
.ac dec 40 10 10G
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
    measures = (
        ("output_v", "V"),
        ("output_pp_v", "V"),
        ("gain_100khz", "1"),
        ("supply_current_a", "A"),
        ("power_w", "W"),
    )
    text = """version = 1
[simulator]
adapter = "ngspice"
executable = "ngspice"
[template]
deck = "sky130_common_source.sp.tmpl"
inputs = [
  "decision.json",
  "pdk-provenance.json",
  "models/sky130_fd_pr__nfet_01v8__mismatch.corner.spice",
  "models/sky130_fd_pr__nfet_01v8__tt.pm3.spice",
  "models/sky130_fd_pr__nfet_01v8__ss.pm3.spice",
  "models/sky130_fd_pr__nfet_01v8__ff.pm3.spice",
]
[sweep]
mode = "product"
CORNER = ["tt", "ss", "ff"]
VDD = ["1.62", "1.80", "1.98"]
TEMP_C = ["-40", "27", "125"]
[run]
timeout_seconds = 90
jobs = 2
fail_fast = false
[run.resources]
simulator = 2
"""
    for name, unit in measures:
        text += (
            f'[[measure]]\nname = "{name}"\nsource = "metrics.json"\n'
            f'field = "{name}"\nunit = "{unit}"\n'
        )
    return text


def configure_sky130(
    decision_path: str | Path,
    output: str | Path,
    *,
    expected_topology: str,
    expected_signature: str,
    expected_decision_sha256: str,
    expected_benchmark_sha256: str,
    expected_comparison_sha256: str,
    pdk_root: str | Path,
    pins: Sky130Pins = SKY130_PINS,
) -> Path:
    """Create a new, self-contained 27-point SimCairn run configuration."""
    decision = load_sizing_decision(
        decision_path,
        expected_topology=expected_topology,
        expected_signature=expected_signature,
        expected_decision_sha256=expected_decision_sha256,
        expected_benchmark_sha256=expected_benchmark_sha256,
        expected_comparison_sha256=expected_comparison_sha256,
    )
    resolved_pdk, spice = _safe_pdk(Path(pdk_root), pins.revision)
    nodeinfo = resolved_pdk / ".config" / "nodeinfo.json"
    if nodeinfo.is_symlink() or not nodeinfo.is_file() or _sha256(nodeinfo) != pins.nodeinfo_sha256:
        raise Sky130ConfigurationError("PDK nodeinfo.json does not match the pinned release")
    destination = _safe_destination(output)
    if destination.exists():
        raise Sky130ConfigurationError("destination already exists; refusing to overwrite")
    temporary = destination.with_name(f".{destination.name}.tmp-{os.getpid()}")
    if temporary.exists():
        raise Sky130ConfigurationError("temporary destination already exists")
    try:
        models = temporary / "models"
        models.mkdir(parents=True)
        model_digests: dict[str, str] = {}
        for name in _MODEL_NAMES:
            model = spice / name
            if model.is_symlink() or not model.is_file():
                raise Sky130ConfigurationError(f"required PDK model is absent or symbolic: {name}")
            target = models / name
            shutil.copyfile(model, target)
            model_digests[name] = _sha256(target)
            if model_digests[name] != pins.model_sha256.get(name):
                raise Sky130ConfigurationError(f"PDK model does not match its pin: {name}")
        selected_digest = _archive_digest(model_digests)
        (temporary / "decision.json").write_text(decision.canonical, encoding="ascii", newline="\n")
        provenance = {
            "schema": "org.simcairn.sky130-provenance",
            "version": 1,
            "decision_sha256": decision.digest,
            "topology_id": decision.topology_id,
            "topology_signature": decision.topology_signature,
            "pdk": {
                "variant": "sky130A",
                "revision": pins.revision,
                "nodeinfo_sha256": pins.nodeinfo_sha256,
                "official_asset_sha256": {
                    "common.tar.zst": pins.common_asset_sha256,
                    "sky130_fd_pr.tar.zst": pins.primitive_asset_sha256,
                },
                "selected_model_set_sha256": selected_digest,
                "model_sha256": model_digests,
            },
        }
        (temporary / "pdk-provenance.json").write_text(
            stable_json(provenance), encoding="ascii", newline="\n"
        )
        (temporary / "sky130_common_source.sp.tmpl").write_text(
            _deck(decision), encoding="ascii", newline="\n"
        )
        (temporary / "simcairn.toml").write_text(_manifest(), encoding="ascii", newline="\n")
        temporary.replace(destination)
    except Exception:
        if temporary.exists():
            shutil.rmtree(temporary)
        raise
    return destination / "simcairn.toml"
