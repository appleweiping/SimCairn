import re
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from simcairn.manifest import ManifestError, SweepConfig, load_manifest
from simcairn.mock_simulator import parse_engineering_value, simulate
from simcairn.model import Plan
from simcairn.planner import compile_plan
from simcairn.sweeps import expand_sweep
from simcairn.templates import TemplateError, render_template


def _project(tmp_path: Path, *, mode: str = "product", extra: str = "") -> Path:
    (tmp_path / "deck.sp.tmpl").write_text(
        "R1 in out @{R}\nC1 out 0 @{C}\n.end\n", encoding="utf-8"
    )
    manifest = tmp_path / "simcairn.toml"
    manifest.write_text(
        f"""version = 1
[simulator]
adapter = "mock-rc"
[template]
deck = "deck.sp.tmpl"
inputs = []
[sweep]
mode = "{mode}"
R = ["1k", "2k"]
C = ["1n", "2n"]
[run]
timeout_seconds = 10
jobs = 2
fail_fast = false
[run.resources]
simulator = 1
[[measure]]
name = "cutoff_hz"
source = "metrics.json"
field = "cutoff_hz"
{extra}
""",
        encoding="utf-8",
    )
    return manifest


def test_valid_manifest_and_product_plan(tmp_path):
    manifest = load_manifest(_project(tmp_path))
    assert manifest.simulator.adapter == "mock-rc"
    assert manifest.measures[0].unit == "1"
    assert manifest.template.deck == (tmp_path / "deck.sp.tmpl").resolve()
    points = expand_sweep(manifest.sweep)
    assert [point.as_dict() for point in points] == [
        {"R": "1k", "C": "1n"},
        {"R": "1k", "C": "2n"},
        {"R": "2k", "C": "1n"},
        {"R": "2k", "C": "2n"},
    ]
    plan = compile_plan(manifest)
    assert len(plan.activities) == 13
    assert [activity.kind for activity in plan.activities].count("render") == 4
    assert plan.activities[-1].kind == "aggregate"
    assert len(plan.activities[-1].dependencies) == 4


def test_zip_sweep_pairs_values_instead_of_multiplying(tmp_path):
    manifest = load_manifest(_project(tmp_path, mode="zip"))
    points = expand_sweep(manifest.sweep)
    assert [point.as_dict() for point in points] == [
        {"R": "1k", "C": "1n"},
        {"R": "2k", "C": "2n"},
    ]
    assert len(compile_plan(manifest).activities) == 7


def test_zip_requires_equal_lengths():
    config = SweepConfig("zip", (("R", ("1k", "2k")), ("C", ("1n",))))
    with pytest.raises(ManifestError, match="equal lengths"):
        expand_sweep(config)


def test_duplicate_expanded_point_is_rejected():
    config = SweepConfig("product", (("R", ("1k", "1k")),))
    with pytest.raises(ManifestError, match="duplicate point"):
        expand_sweep(config)


def test_plan_identity_is_checkout_location_independent(tmp_path):
    first_root = tmp_path / "first checkout"
    second_root = tmp_path / "second checkout"
    first_root.mkdir()
    second_root.mkdir()
    first = compile_plan(load_manifest(_project(first_root)))
    second = compile_plan(load_manifest(_project(second_root)))
    assert first.id == second.id
    assert [item.id for item in first.activities] == [item.id for item in second.activities]
    assert first.manifest_path != second.manifest_path


def test_input_content_changes_only_content_dependent_keys(tmp_path):
    manifest_path = _project(tmp_path)
    first = compile_plan(load_manifest(manifest_path))
    (tmp_path / "deck.sp.tmpl").write_text(
        "Rchanged in out @{R}\nC1 out 0 @{C}\n.end\n", encoding="utf-8"
    )
    second = compile_plan(load_manifest(manifest_path))
    assert first.id != second.id
    assert first.activities[0].id != second.activities[0].id
    assert first.activities[-1].id != second.activities[-1].id


def test_simulation_identity_binds_executable_and_requested_measure_fields(tmp_path):
    manifest_path = _project(tmp_path)
    first = compile_plan(load_manifest(manifest_path))
    text = manifest_path.read_text(encoding="utf-8")
    text += (
        '\n[[measure]]\nname = "resistance_ohm"\n'
        'source = "metrics.json"\nfield = "resistance_ohm"\n'
    )
    manifest_path.write_text(text, encoding="utf-8")
    second = compile_plan(load_manifest(manifest_path))
    first_simulate = next(item for item in first.activities if item.kind == "simulate")
    second_simulate = next(item for item in second.activities if item.kind == "simulate")
    assert first_simulate.id != second_simulate.id
    assert first_simulate.identity["measure_fields"] == ["cutoff_hz"]
    assert second_simulate.identity["measure_fields"] == ["cutoff_hz", "resistance_ohm"]


def test_measure_unit_is_strict_and_bound_to_extract_and_aggregate_identity(tmp_path):
    manifest_path = _project(tmp_path, extra='unit = "Hz"')
    plan = compile_plan(load_manifest(manifest_path))
    extract = next(item for item in plan.activities if item.kind == "extract")
    aggregate = plan.activities[-1]
    assert extract.identity["measures"][0]["unit"] == "Hz"
    assert aggregate.identity["measures"][0]["unit"] == "Hz"

    manifest_path = _project(tmp_path, extra='unit = ""')
    with pytest.raises(ManifestError, match="unit must be"):
        load_manifest(manifest_path)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("adapter", "ngspice"),
        ("executable", "other-simulator"),
        ("environment", {"MODE": "changed"}),
        ("measure_fields", ["other_measure"]),
    ],
)
def test_consistent_simulator_configuration_change_requires_new_activity_id(tmp_path, field, value):
    data = compile_plan(load_manifest(_project(tmp_path))).as_dict()
    simulate = next(item for item in data["activities"] if item["kind"] == "simulate")
    simulate["payload"][field] = value
    simulate["identity"][field] = value
    with pytest.raises(ValueError, match="activity id does not match its identity"):
        Plan.from_dict(data)


@pytest.mark.parametrize(
    ("kind", "mutate"),
    [
        ("render", lambda item: item["identity"].update(renderer="forged/1")),
        ("render", lambda item: item["inputs"][0].update(sha256="f" * 64)),
        (
            "render",
            lambda item: item["point"]["values"].__setitem__(0, ("R", "forged")),
        ),
    ],
)
def test_saved_identity_input_and_point_tampering_is_rejected(tmp_path, kind, mutate):
    data = compile_plan(load_manifest(_project(tmp_path))).as_dict()
    activity = next(item for item in data["activities"] if item["kind"] == kind)
    mutate(activity)
    with pytest.raises(ValueError):
        Plan.from_dict(data)


@pytest.mark.parametrize(
    ("kind", "mutate", "message"),
    [
        ("render", lambda item: item["payload"].update(template_path="other.sp"), "template_path"),
        (
            "render",
            lambda item: item["payload"].update(copies=[{"path": "x", "logical_name": "x"}]),
            "copies",
        ),
        ("simulate", lambda item: item["payload"].update(adapter="ngspice"), "simulate payload"),
        ("simulate", lambda item: item["payload"].update(executable="other"), "simulate payload"),
        (
            "simulate",
            lambda item: item["payload"].update(measure_fields=["other"]),
            "simulate payload",
        ),
        ("extract", lambda item: item["payload"].update(point_index=99), "point_index"),
        (
            "extract",
            lambda item: item["payload"].update(point={"R": "9k"}),
            "extract payload point",
        ),
        ("extract", lambda item: item["payload"].update(measures=[]), "extract measures"),
        (
            "aggregate",
            lambda item: item["payload"].update(measures=["other"]),
            "aggregate measures",
        ),
    ],
)
def test_saved_activity_payload_cannot_diverge_from_inputs_point_or_identity(
    tmp_path, kind, mutate, message
):
    data = compile_plan(load_manifest(_project(tmp_path))).as_dict()
    changed = deepcopy(data)
    activity = next(item for item in changed["activities"] if item["kind"] == kind)
    mutate(activity)
    with pytest.raises(ValueError, match=message):
        Plan.from_dict(changed)


@pytest.mark.parametrize(
    ("text", "values", "expected"),
    [
        ("R1 a b @{R}\n", {"R": "1k"}, "R1 a b 1k\n"),
        ("R=@{r} C=@{C}", {"R": "2k", "c": "3n"}, "R=2k C=3n"),
    ],
)
def test_template_substitution_is_case_insensitive_and_literal(text, values, expected):
    assert render_template(text, values) == expected


@pytest.mark.parametrize(
    ("text", "values", "message"),
    [
        ("R=@{missing}", {"R": "1k"}, "unknown parameter"),
        ("R=@{R", {"R": "1k"}, "malformed placeholder"),
        ("fixed", {"R": "1k"}, "unused"),
        ("R=@{R}", {"R": "1k\n.shell"}, "unsafe"),
    ],
)
def test_template_rejects_unknown_malformed_unused_and_unsafe_values(text, values, message):
    with pytest.raises(TemplateError, match=message):
        render_template(text, values)


@pytest.mark.parametrize(
    ("source", "expected"),
    [("1k", 1000.0), ("2meg", 2e6), ("4n", 4e-9), ("0.5", 0.5)],
)
def test_mock_engineering_value_parser(source, expected):
    assert parse_engineering_value(source) == pytest.approx(expected)


@pytest.mark.parametrize("source", ["", "0", "-1", "nan", "1 k", "{1k}"])
def test_mock_engineering_value_rejects_nonpositive_or_unsafe_input(source):
    with pytest.raises(ValueError):
        parse_engineering_value(source)


def test_mock_simulation_is_physically_consistent():
    result = simulate({"R": "1k", "C": "1n"})
    assert result["resistance_ohm"] == 1000
    assert result["capacitance_f"] == 1e-9
    assert result["cutoff_hz"] == pytest.approx(159154.94309189534)
    with pytest.raises(ValueError, match="requires sweep parameters"):
        simulate({"R": "1k"})


@pytest.mark.parametrize(
    ("old", "new", "expected_fragment"),
    [
        ("version = 1", "version = 2", "version must"),
        ('adapter = "mock-rc"', 'adapter = "unknown"', "simulator.adapter"),
        ('deck = "deck.sp.tmpl"', 'deck = "missing.sp"', "not a readable"),
        ('mode = "product"', 'mode = "diagonal"', "sweep.mode"),
        ('R = ["1k", "2k"]', 'R = ["1k", "1k"]', "duplicate canonical"),
        ('C = ["1n", "2n"]', 'C = ["1n", "bad value"]', "unsafe"),
        ("jobs = 2", "jobs = 0", "run.jobs"),
        ("timeout_seconds = 10", "timeout_seconds = -1", "timeout_seconds"),
        ('name = "cutoff_hz"', 'name = "not valid"', "identifier"),
        ('source = "metrics.json"', 'source = "../metrics.json"', "safe relative"),
    ],
)
def test_manifest_validation_reports_precise_invalid_fields(tmp_path, old, new, expected_fragment):
    path = _project(tmp_path)
    text = path.read_text(encoding="utf-8").replace(old, new)
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ManifestError, match=expected_fragment):
        load_manifest(path)


def test_manifest_rejects_escape_unknown_key_duplicate_measure_and_bad_environment(tmp_path):
    path = _project(tmp_path)
    outside = tmp_path.parent / "outside-simcairn.inc"
    outside.write_text("model", encoding="utf-8")
    try:
        text = path.read_text(encoding="utf-8")
        text = text.replace("inputs = []", f'inputs = ["../{outside.name}"]')
        text = "unknown = 1\n" + text
        text = text.replace(
            "[template]",
            '[simulator.environment]\n"bad-name" = 3\n[template]',
        )
        text += '\n[[measure]]\nname="cutoff_hz"\nfield="cutoff_hz"\n'
        path.write_text(text, encoding="utf-8")
        with pytest.raises(ManifestError) as captured:
            load_manifest(path)
        message = str(captured.value)
        assert "unknown top-level" in message
        assert "escapes" in message
        assert "environment" in message
        assert "duplicate measure" in message
    finally:
        outside.unlink()


def test_manifest_objects_can_be_safely_replaced_for_cli_job_override(tmp_path):
    manifest = load_manifest(_project(tmp_path))
    changed = replace(manifest, run=replace(manifest.run, jobs=5))
    assert manifest.run.jobs == 2
    assert changed.run.jobs == 5
    assert compile_plan(changed).jobs == 5


def test_manifest_accepts_scalar_sweeps_environment_executable_and_input(tmp_path):
    path = _project(tmp_path)
    model = tmp_path / "device.inc"
    model.write_text(".model demo d\n", encoding="utf-8")
    text = path.read_text(encoding="utf-8")
    text = text.replace(
        'adapter = "mock-rc"',
        'adapter = "mock-rc"\nexecutable = "custom-simulator"\n'
        '[simulator.environment]\nMODE = "batch"',
    )
    text = text.replace("inputs = []", 'inputs = ["device.inc"]')
    text = text.replace('R = ["1k", "2k"]', "R = [true, 2, 3.5]")
    path.write_text(text, encoding="utf-8")

    manifest = load_manifest(path)
    assert manifest.root == tmp_path.resolve()
    assert manifest.simulator.executable == "custom-simulator"
    assert manifest.simulator.environment == (("MODE", "batch"),)
    assert manifest.template.inputs == (model.resolve(),)
    assert dict(manifest.sweep.parameters)["R"] == ("true", "2", "3.5")


def test_manifest_accumulates_missing_required_tables(tmp_path):
    path = tmp_path / "simcairn.toml"
    path.write_text("version = 1\n", encoding="utf-8")
    with pytest.raises(ManifestError) as captured:
        load_manifest(path)
    message = str(captured.value)
    assert "[simulator] table is required" in message
    assert "[template] table is required" in message
    assert "[sweep] table is required" in message
    assert "[run] table is required" in message
    assert "at least one [[measure]]" in message


def test_manifest_accumulates_wrong_shapes_and_scalar_types(tmp_path):
    path = tmp_path / "simcairn.toml"
    path.write_text(
        """version = 1
measure = [3]
[simulator]
adapter = "mock-rc"
executable = 4
environment = []
[template]
deck = 3
inputs = "not-an-array"
[sweep]
"bad-name" = []
Nested = [[1]]
Infinite = [nan]
[run]
timeout_seconds = true
jobs = false
fail_fast = "yes"
resources = []
""",
        encoding="utf-8",
    )
    with pytest.raises(ManifestError) as captured:
        load_manifest(path)
    message = str(captured.value)
    for fragment in (
        "executable",
        "environment must be a table",
        "template.deck",
        "template.inputs",
        "invalid sweep parameter",
        "finite scalars",
        "non-finite",
        "timeout_seconds",
        "run.jobs",
        "run.fail_fast",
        "run.resources",
        "measure[0] must be a table",
    ):
        assert fragment in message


def test_manifest_rejects_duplicate_inputs_bad_field_and_empty_sweep(tmp_path):
    path = _project(tmp_path)
    model = tmp_path / "same.inc"
    model.write_text("model", encoding="utf-8")
    text = path.read_text(encoding="utf-8")
    text = text.replace("inputs = []", 'inputs = ["same.inc", "same.inc"]')
    text = text.replace(
        '[sweep]\nmode = "product"\nR = ["1k", "2k"]\nC = ["1n", "2n"]',
        '[sweep]\nmode = "product"',
    )
    text = text.replace('field = "cutoff_hz"', 'field = "bad field"')
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ManifestError) as captured:
        load_manifest(path)
    message = str(captured.value)
    assert "duplicate resolved paths" in message
    assert "at least one parameter" in message
    assert "field must be an identifier" in message


def test_planner_rejects_case_variant_of_reserved_render_artifact(tmp_path):
    path = _project(tmp_path)
    collision = tmp_path / "Deck.SP"
    collision.write_text("would overwrite the rendered deck", encoding="utf-8")
    text = path.read_text(encoding="utf-8").replace("inputs = []", 'inputs = ["Deck.SP"]')
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ManifestError, match="reserved artifact"):
        compile_plan(load_manifest(path))


def test_manifest_rejects_casefold_duplicate_sweep_parameters(tmp_path):
    path = _project(tmp_path)
    text = path.read_text(encoding="utf-8").replace(
        'R = ["1k", "2k"]', 'R = ["1k", "2k"]\nr = ["3k", "4k"]'
    )
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ManifestError, match="duplicate sweep parameter"):
        load_manifest(path)


def test_zip_sweep_allows_repeated_columns_when_complete_points_are_unique(tmp_path):
    path = _project(tmp_path, mode="zip")
    text = path.read_text(encoding="utf-8")
    text = text.replace('R = ["1k", "2k"]', 'R = ["1k", "1k", "2k"]')
    text = text.replace('C = ["1n", "2n"]', 'C = ["1n", "2n", "2n"]')
    path.write_text(text, encoding="utf-8")
    points = expand_sweep(load_manifest(path).sweep)
    assert [point.as_dict() for point in points] == [
        {"R": "1k", "C": "1n"},
        {"R": "1k", "C": "2n"},
        {"R": "2k", "C": "2n"},
    ]


def test_zip_rejects_duplicate_complete_points_and_product_rejects_duplicate_columns(tmp_path):
    zip_root = tmp_path / "zip"
    zip_root.mkdir()
    zip_path = _project(zip_root, mode="zip")
    text = zip_path.read_text(encoding="utf-8").replace('R = ["1k", "2k"]', 'R = ["1k", "1k"]')
    text = text.replace('C = ["1n", "2n"]', 'C = ["1n", "1n"]')
    zip_path.write_text(text, encoding="utf-8")
    with pytest.raises(ManifestError, match="duplicate point"):
        expand_sweep(load_manifest(zip_path).sweep)

    product_root = tmp_path / "product"
    product_root.mkdir()
    product_path = _project(product_root)
    product_path.write_text(
        product_path.read_text(encoding="utf-8").replace('R = ["1k", "2k"]', 'R = ["1k", "1k"]'),
        encoding="utf-8",
    )
    with pytest.raises(ManifestError, match="duplicate canonical"):
        load_manifest(product_path)


def test_manifest_rejects_measure_name_that_overwrites_sweep_coordinate(tmp_path):
    path = _project(tmp_path)
    text = path.read_text(encoding="utf-8").replace('name = "cutoff_hz"', 'name = "r"')
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ManifestError, match="conflicts with a sweep parameter"):
        load_manifest(path)


@pytest.mark.parametrize(
    ("needle", "replacement", "message"),
    [
        ("version = 1", "version = true", "version must be the integer 1"),
        ('source = "metrics.json"', "source = 7", "source must be a string"),
        ('field = "cutoff_hz"', "field = false", "field must be a string"),
    ],
)
def test_manifest_rejects_type_coercion_for_version_and_measure_fields(
    tmp_path, needle, replacement, message
):
    path = _project(tmp_path)
    path.write_text(path.read_text(encoding="utf-8").replace(needle, replacement), encoding="utf-8")
    with pytest.raises(ManifestError, match=message):
        load_manifest(path)


@pytest.mark.parametrize("timeout", ["nan", "inf", "31536001", "1" + "0" * 400])
def test_manifest_rejects_nonfinite_or_unreasonably_large_timeout(tmp_path, timeout):
    path = _project(tmp_path)
    text = path.read_text(encoding="utf-8").replace(
        "timeout_seconds = 10", f"timeout_seconds = {timeout}"
    )
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ManifestError, match="timeout_seconds"):
        load_manifest(path)


@pytest.mark.parametrize(
    ("needle", "replacement", "message"),
    [
        ('adapter = "mock-rc"', 'adapter = "mock-rc"\nextra = 1', "unknown simulator key"),
        ("inputs = []", "inputs = []\nextra = 1", "unknown template key"),
        ("fail_fast = false", "fail_fast = false\nextra = 1", "unknown run key"),
        ('field = "cutoff_hz"', 'field = "cutoff_hz"\nextra = 1', "unknown measure[0] key"),
    ],
)
def test_manifest_rejects_unknown_nested_keys(tmp_path, needle, replacement, message):
    path = _project(tmp_path)
    path.write_text(path.read_text(encoding="utf-8").replace(needle, replacement), encoding="utf-8")
    with pytest.raises(ManifestError, match=re.escape(message)):
        load_manifest(path)
