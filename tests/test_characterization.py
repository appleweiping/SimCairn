import json
from dataclasses import replace
from pathlib import Path

import pytest

from simcairn.characterization import (
    ACSweepAnalysis,
    CharacterizationError,
    CharacterizationInput,
    CharacterizationLimits,
    DCSweepAnalysis,
    NoiseAnalysis,
    OperatingPointAnalysis,
    PVTCorner,
    TraceOutput,
    TransientAnalysis,
    load_characterization_plan,
    normalize_result_table,
    render_xyce_deck,
    xyce_analysis_directives,
)

EXAMPLE = Path(__file__).parents[1] / "examples" / "xyce_sram" / "characterization.json"


def test_loads_complete_pvt_plan_and_renders_every_analysis():
    plan = load_characterization_plan(EXAMPLE)
    assert plan.name == "synthetic_sram_like"
    assert len(plan.corners) == 3
    assert [analysis.kind for analysis in plan.analyses] == ["op", "dc", "ac", "tran", "noise"]
    assert len(plan.deck_sha256) == 64
    assert plan.as_identity_dict()["deck_sha256"] == plan.deck_sha256

    rendered = [
        render_xyce_deck(plan, plan.corners[0], analysis).decode("utf-8")
        for analysis in plan.analyses
    ]
    assert all("SIMCAIRN:PVT" not in deck and "SIMCAIRN:ANALYSIS" not in deck for deck in rendered)
    assert all(".PARAM SIMCAIRN_PROCESS_SCALE=0.84999999999999998" in deck for deck in rendered)
    assert ".OP\n.PRINT DC FORMAT=CSV" in rendered[0]
    assert ".DC VBL 0 1.1000000000000001 0.01" in rendered[1]
    assert "PRECISION=17 V(bl) V(q)" in rendered[1]
    assert ".AC DEC 20 1000 10000000000" in rendered[2]
    assert ".TRAN 9.9999999999999994e-12 1e-08 0" in rendered[3]
    assert ".OPTIONS OUTPUT OUTPUTTIMEPOINTS=0,9.9999999999999994e-12" in rendered[3]
    assert "\n+ " in rendered[3]
    assert ".NOISE V(q,0) VBL DEC 20 1000 10000000000" in rendered[4]


def test_directive_output_filename_is_not_an_injection_surface():
    analysis = OperatingPointAnalysis("hold", (TraceOutput("q", "V(q)", "V"),))
    assert "FILE=trace.csv" in xyce_analysis_directives(analysis, result_file="trace.csv")
    with pytest.raises(CharacterizationError, match="result_file"):
        xyce_analysis_directives(analysis, result_file="../trace.csv")


def test_transient_directive_fixes_the_exact_output_grid():
    analysis = TransientAnalysis(
        "read",
        (TraceOutput("q", "V(q)", "V"),),
        step_seconds=0.3,
        stop_seconds=1.0,
        start_seconds=0.1,
    )
    directive = xyce_analysis_directives(analysis)
    assert ".TRAN 0.29999999999999999 1 0.10000000000000001" in directive
    assert (
        ".OPTIONS OUTPUT OUTPUTTIMEPOINTS=0.10000000000000001,0.40000000000000002,"
        "0.69999999999999996,1"
    ) in directive


def _write_plan(tmp_path, mutate):
    data = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    mutate(data)
    deck = tmp_path / "sram_like.cir.tmpl"
    deck.write_bytes(EXAMPLE.with_name("sram_like.cir.tmpl").read_bytes())
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda data: data.pop("name"), "missing fields"),
        (lambda data: data.update(schema_version=True), "schema_version"),
        (lambda data: data.update(schema_version=1.0), "schema_version"),
        (lambda data: data.update(extra=1), "unknown fields"),
        (lambda data: data.update(limits=[]), "limits must be an object"),
        (lambda data: data.update(corners="tt"), "corners must be an array"),
        (lambda data: data.update(corners=[]), "at least one PVT"),
        (lambda data: data.update(corners=[1]), r"corners\[0\] must be an object"),
        (lambda data: data.update(analyses="op"), "analyses must be an array"),
        (lambda data: data.update(analyses=[]), "at least one analysis"),
        (lambda data: data.update(inputs={}), "inputs must be an array"),
        (lambda data: data["corners"].append(data["corners"][0]), "duplicate PVT"),
        (lambda data: data["analyses"].append(data["analyses"][0]), "duplicate analysis"),
        (lambda data: data["limits"].update(max_runs=2), "exceeds limits.max_runs"),
        (lambda data: data["limits"].update(max_rows=0), "limits.max_rows"),
        (lambda data: data["limits"].update(max_rows=2), "exceeds limits.max_rows"),
        (lambda data: data["limits"].update(max_columns=3), "exceeds limits.max_columns"),
        (lambda data: data.update(deck="../escape.cir"), "safe relative"),
        (lambda data: data.update(deck=""), "non-empty relative"),
        (lambda data: data.update(deck="missing.cir"), "not a readable regular file"),
        (lambda data: data["corners"][0].update(process="slow corner"), "ASCII identifier"),
        (lambda data: data["corners"][0].update(voltage=True), "finite"),
        (lambda data: data["corners"][0].update(voltage=0), "positive"),
        (lambda data: data["corners"][0].update(voltage=1001), "at most"),
        (lambda data: data["corners"][0].update(voltage=float("nan")), "finite"),
        (lambda data: data["corners"][0].update(temperature_c=-274), "at least"),
        (lambda data: data["corners"][0].update(parameters=[]), "parameters must be"),
        (
            lambda data: data["corners"][0].update(
                parameters={f"p{index}": index for index in range(33)}
            ),
            "more than 32",
        ),
        (
            lambda data: data["corners"][0].update(parameters={"gain": 1, "GAIN": 2}),
            "duplicate names",
        ),
        (
            lambda data: data["corners"][0].update(parameters={"voltage": 1}),
            "reserved",
        ),
        (lambda data: data["analyses"].__setitem__(0, 1), r"analyses\[0\] must be an object"),
        (lambda data: data["analyses"][0].update(kind="hb"), "must be op"),
        (lambda data: data["analyses"][0].update(surprise=1), "unknown fields"),
        (lambda data: data["analyses"][0].update(outputs=[]), "non-empty array"),
        (lambda data: data["analyses"][0].update(outputs=[1]), r"outputs\[0\] must be an object"),
        (
            lambda data: data["analyses"][0]["outputs"][0].update(expression="V(q) .END"),
            "supported safe probe",
        ),
        (
            lambda data: data["analyses"][0]["outputs"][0].update(unit=1),
            "printable text",
        ),
        (
            lambda data: data["analyses"][0]["outputs"].append(data["analyses"][0]["outputs"][0]),
            "duplicate output",
        ),
        (
            lambda data: data["analyses"][0]["outputs"].append(
                {
                    **data["analyses"][0]["outputs"][0],
                    "name": "same_probe",
                }
            ),
            "duplicate output probes",
        ),
        (lambda data: data["analyses"][1].update(step=-0.1), "move from start"),
        (lambda data: data["analyses"][1].update(source="R1"), "independent voltage"),
        (lambda data: data["analyses"][1].pop("axis_expression"), "missing fields"),
        (
            lambda data: data["analyses"][1].update(axis_expression="I(VBL)"),
            "voltage probe",
        ),
        (
            lambda data: data["analyses"][1].update(axis_expression="V(q)"),
            "distinct",
        ),
        (lambda data: data["analyses"][2].update(sweep="list"), "lin.*dec.*oct"),
        (lambda data: data["analyses"][2].update(stop_hz=1), "greater than"),
        (lambda data: data["analyses"][3].update(start_seconds=2e-8), "must be in"),
        (lambda data: data["analyses"][3].update(step_seconds=2e-8), "exceeds"),
        (lambda data: data["analyses"][4].update(source="V BL"), "safe SPICE"),
    ],
)
def test_plan_rejects_ambiguous_unsafe_or_unbounded_values(tmp_path, mutate, message):
    path = _write_plan(tmp_path, mutate)
    with pytest.raises(CharacterizationError, match=message):
        load_characterization_plan(path)


def test_plan_rejects_duplicate_json_and_oversized_plan(tmp_path):
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
    with pytest.raises(CharacterizationError, match="duplicate"):
        load_characterization_plan(duplicate)
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (256 * 1024 + 1))
    with pytest.raises(CharacterizationError, match="262144"):
        load_characterization_plan(oversized)

    not_object = tmp_path / "array.json"
    not_object.write_text("[]", encoding="utf-8")
    with pytest.raises(CharacterizationError, match="JSON object"):
        load_characterization_plan(not_object)


def test_deck_requires_unique_markers_valid_utf8_and_size(tmp_path):
    plan = load_characterization_plan(EXAMPLE)
    source = plan.deck.read_text(encoding="utf-8")
    deck = tmp_path / "deck.cir"
    deck.write_text(source.replace("* SIMCAIRN:PVT", "* removed"), encoding="utf-8")
    broken = replace(plan, deck=deck)
    with pytest.raises(CharacterizationError, match="exactly one"):
        render_xyce_deck(broken, broken.corners[0], broken.analyses[0])
    deck.write_bytes(b"\xff")
    with pytest.raises(CharacterizationError, match="UTF-8"):
        replace(plan, deck=deck)
    deck.write_text(source, encoding="utf-8")
    with pytest.raises(CharacterizationError, match=r"limits\.max_deck_bytes"):
        replace(broken, limits=replace(plan.limits, max_deck_bytes=10))


def test_deck_include_must_be_declared_and_content_bound(tmp_path):
    model = tmp_path / "models" / "device.inc"
    model.parent.mkdir()
    model.write_text(".MODEL NM NMOS LEVEL=1\n", encoding="utf-8")
    plan_path = _write_plan(tmp_path, lambda data: data.update(inputs=["models/device.inc"]))
    deck = tmp_path / "sram_like.cir.tmpl"
    deck.write_text(
        deck.read_text(encoding="utf-8").replace(
            "* SIMCAIRN:PVT", '.include\t"models/device.inc"\n* SIMCAIRN:PVT'
        ),
        encoding="utf-8",
    )
    plan = load_characterization_plan(plan_path)
    identity = plan.as_identity_dict()
    assert identity["inputs"] == [
        {
            "logical_name": "models/device.inc",
            "sha256": plan.inputs[0].sha256,
            "size": model.stat().st_size,
        }
    ]
    assert '.include\t"models/device.inc"' in render_xyce_deck(
        plan, plan.corners[0], plan.analyses[0]
    ).decode("utf-8")

    with pytest.raises(CharacterizationError, match="undeclared"):
        replace(plan, inputs=())
    model.write_text(".MODEL NM NMOS LEVEL=1 KP=1U\n", encoding="utf-8")
    assert plan.as_identity_dict()["inputs"] == identity["inputs"]
    with pytest.raises(CharacterizationError, match="changed after its snapshot"):
        plan.verify_sources_unchanged()


def test_input_names_are_canonical_and_include_syntax_fails_closed(tmp_path):
    source = tmp_path / "model.inc"
    source.write_text("model\n", encoding="utf-8")
    with pytest.raises(CharacterizationError, match="safe relative"):
        CharacterizationInput("models//model.inc", source)

    plan = load_characterization_plan(EXAMPLE)
    deck = tmp_path / "deck.cir"
    deck.write_text(
        plan.deck.read_text(encoding="utf-8").replace(
            "* SIMCAIRN:PVT", ".include\tbad path.inc\n* SIMCAIRN:PVT"
        ),
        encoding="utf-8",
    )
    with pytest.raises(CharacterizationError, match="unsupported include"):
        replace(plan, deck=deck)


def test_transitive_include_aliases_and_file_references_must_be_declared(tmp_path):
    data = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    data["inputs"] = ["models/root.inc", "models/nested/device.inc", "vectors/read.dat"]
    (tmp_path / "models" / "nested").mkdir(parents=True)
    (tmp_path / "vectors").mkdir()
    (tmp_path / "models" / "root.inc").write_text(
        ".INCL '../models/nested/device.inc'\n", encoding="utf-8"
    )
    (tmp_path / "models" / "nested" / "device.inc").write_text(
        ".MODEL EXTRA NMOS LEVEL=1\n", encoding="utf-8"
    )
    (tmp_path / "vectors" / "read.dat").write_text("0 0\n1n 1\n", encoding="utf-8")
    deck = tmp_path / "sram_like.cir.tmpl"
    deck.write_text(
        EXAMPLE.with_name("sram_like.cir.tmpl")
        .read_text(encoding="utf-8")
        .replace(
            "* SIMCAIRN:PVT",
            ".include 'models/root.inc'\nVstim x 0 PWL FILE='vectors/read.dat'\n* SIMCAIRN:PVT",
        ),
        encoding="utf-8",
    )
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(data), encoding="utf-8")
    assert len(load_characterization_plan(plan_path).inputs) == 3

    data["inputs"].remove("models/nested/device.inc")
    plan_path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(CharacterizationError, match=r"undeclared.*nested/device"):
        load_characterization_plan(plan_path)


def test_frequency_analyses_require_unambiguous_scalar_probes(tmp_path):
    path = _write_plan(
        tmp_path,
        lambda data: data["analyses"][2]["outputs"][0].update(expression="V(q)"),
    )
    with pytest.raises(CharacterizationError, match="explicit scalar frequency"):
        load_characterization_plan(path)

    path = _write_plan(
        tmp_path,
        lambda data: data["analyses"][0]["outputs"][0].update(expression="VM(q)"),
    )
    with pytest.raises(CharacterizationError, match="frequency-only"):
        load_characterization_plan(path)


def test_xyce_and_ngspice_tables_normalize_to_the_same_contract():
    plan = load_characterization_plan(EXAMPLE)
    analysis = TransientAnalysis(
        "tran", (TraceOutput("q", "V(q)", "V"), TraceOutput("wl", "V(wl)", "V")), 1e-9, 1e-9
    )
    xyce = b"INDEX,TIME,V(q),V(wl)\n0,0,0.1,0\n1,1e-9,0.4,1\n"
    ngspice = b"Index time v(q) v(wl)\n0 0 0.1 0\n1 1e-9 0.4 1\n"
    left = normalize_result_table(xyce, analysis, simulator="xyce", limits=plan.limits)
    right = normalize_result_table(ngspice, analysis, simulator="ngspice", limits=plan.limits)
    assert left == right
    assert left.as_dict()["axis"] == {"name": "time", "unit": "s", "values": [0.0, 1e-9]}


def test_normalization_supports_op_dc_ac_and_noise_axes():
    plan = load_characterization_plan(EXAMPLE)
    output = (TraceOutput("q", "V(q)", "V"),)
    analyses = (
        plan.analyses[0],
        DCSweepAnalysis("dc", output, "VBL", "V(bl)", 0, 1, 1),
        ACSweepAnalysis("ac", (TraceOutput("q", "VM(q)", "V"),), "lin", 2, 1e3, 1e6),
        NoiseAnalysis(
            "noise",
            (TraceOutput("noise", "ONOISE", "V^2/Hz"),),
            "q",
            "0",
            "VBL",
            "lin",
            2,
            1e3,
            1e6,
        ),
    )
    tables = [
        b"INDEX,V(q),V(qb)\n0,0.1,0.9\n",
        b"INDEX,V(bl),V(q)\n0,0,0.1\n1,1,0.8\n",
        b"INDEX,FREQUENCY,VM(q)\n0,1e3,1\n1,1e6,.5\n",
        b"INDEX,FREQ,ONOISE\n0,1e3,1e-18\n1,1e6,2e-18\n",
    ]
    for analysis, table in zip(analyses, tables, strict=True):
        normalized = normalize_result_table(table, analysis, simulator="xyce", limits=plan.limits)
        assert normalized.axis_values


def test_dc_axis_is_required_instead_of_being_fabricated_from_row_count():
    output = (TraceOutput("q", "V(q)", "V"),)
    ascending = DCSweepAnalysis("up", output, "V1", "V(in)", 0, 1, 0.5)
    with pytest.raises(CharacterizationError, match="unambiguous axis"):
        normalize_result_table(
            b"V(q)\n0.1\n0.2\n0.3\n",
            ascending,
            simulator="xyce",
            limits=CharacterizationLimits(),
        )
    with pytest.raises(CharacterizationError, match="unambiguous axis"):
        normalize_result_table(
            b"VBL,V(q)\n0,0.1\n0.5,0.2\n1,0.3\n",
            ascending,
            simulator="xyce",
            limits=CharacterizationLimits(),
        )


def test_dc_current_axis_must_be_the_swept_source_probe():
    output = (TraceOutput("voltage", "V(out)", "V"),)
    assert DCSweepAnalysis("dc", output, "IBIAS", "I(IBIAS)", 0, 1e-3, 1e-3).kind == "dc"
    with pytest.raises(CharacterizationError, match="current-source probe"):
        DCSweepAnalysis("dc", output, "IBIAS", "I(IOTHER)", 0, 1e-3, 1e-3)


@pytest.mark.parametrize(
    ("expression", "unit", "required"),
    [
        ("V(out)", "A", "V"),
        ("I(VDD)", "V", "A"),
        ("VM(out)", "A", "V"),
        ("VDB(out)", "V", "dB"),
        ("VP(out)", "rad", "deg"),
        ("P(M1)", "A", "W"),
        ("ONOISE", "V", "V^2/Hz"),
    ],
)
def test_probe_kind_requires_its_physical_unit(expression, unit, required):
    with pytest.raises(CharacterizationError, match="requires unit") as captured:
        TraceOutput("trace", expression, unit)
    assert required in str(captured.value)


@pytest.mark.parametrize(
    ("table", "message"),
    [
        (b"", "empty"),
        (b"TIME,V(q)\n", "row count"),
        (b"TIME,TIME,V(q)\n0,0,1\n", "duplicate headers"),
        (b"TIME,V(other)\n0,1\n", "missing requested"),
        (b"TIME,V(q)\n0,wat\n1e-9,1\n", "not numeric"),
        (b"TIME,V(q)\n0,nan\n1e-9,1\n", "non-finite"),
        (b"TIME,V(q)\n0,1\n0,2\n", "strictly monotonic"),
        (b"TEMP,V(q)\n25,1\n50,2\n", "unambiguous axis"),
        (b'TIME,"V(q)\n0,1\n', "malformed"),
        (b"TIME,V(q)\n0,1,2\n", "inconsistent"),
    ],
)
def test_normalization_rejects_malformed_or_ambiguous_tables(table, message):
    analysis = TransientAnalysis("tran", (TraceOutput("q", "V(q)", "V"),), 1e-9, 1e-9)
    with pytest.raises(CharacterizationError, match=message):
        normalize_result_table(table, analysis, simulator="xyce", limits=CharacterizationLimits())


@pytest.mark.parametrize(
    "table",
    [
        b"TIME,V(q)\n0,1\n",
        b"TIME,V(q)\n0,1\n5e-10,2\n",
        b"TIME,V(q)\n1e-10,1\n1e-9,2\n",
    ],
)
def test_normalization_rejects_truncated_or_wrong_analysis_axis(table):
    analysis = TransientAnalysis("tran", (TraceOutput("q", "V(q)", "V"),), 1e-9, 1e-9)
    with pytest.raises(CharacterizationError, match="declared analysis"):
        normalize_result_table(table, analysis, simulator="xyce", limits=CharacterizationLimits())


def test_normalization_enforces_bytes_columns_rows_and_op_single_row():
    output = TraceOutput("q", "V(q)", "V")
    tran = TransientAnalysis("tran", (output,), 1e-9, 2e-9)
    with pytest.raises(CharacterizationError, match="max_output_bytes"):
        normalize_result_table(
            b"TIME,V(q)\n0,1\n",
            tran,
            simulator="xyce",
            limits=replace(CharacterizationLimits(), max_output_bytes=4),
        )
    with pytest.raises(CharacterizationError, match="column count"):
        normalize_result_table(
            b"TIME,V(q)\n0,1\n",
            tran,
            simulator="xyce",
            limits=replace(CharacterizationLimits(), max_columns=1),
        )
    with pytest.raises(CharacterizationError, match="row count"):
        normalize_result_table(
            b"TIME,V(q)\n0,1\n1,2\n",
            tran,
            simulator="xyce",
            limits=replace(CharacterizationLimits(), max_rows=1),
        )
    op = OperatingPointAnalysis("op", (output,))
    with pytest.raises(CharacterizationError, match="exactly one"):
        normalize_result_table(
            b"INDEX,V(q)\n0,1\n1,2\n",
            op,
            simulator="xyce",
            limits=CharacterizationLimits(),
        )
    with pytest.raises(CharacterizationError, match="simulator must"):
        normalize_result_table(
            b"INDEX,V(q)\n0,1\n",
            op,
            simulator="other",  # type: ignore[arg-type]
            limits=CharacterizationLimits(),
        )


def test_direct_dataclasses_reject_invalid_cross_field_values():
    output = (TraceOutput("q", "V(q)", "V"),)
    with pytest.raises(CharacterizationError, match="must differ"):
        DCSweepAnalysis("dc", output, "V1", "V(in)", 1, 1, 1)
    with pytest.raises(CharacterizationError, match="exceeds"):
        TransientAnalysis("tran", output, 2, 1)
    with pytest.raises(CharacterizationError, match="safe SPICE"):
        NoiseAnalysis("noise", output, "bad node", "0", "V1", "dec", 1, 1, 10)
    with pytest.raises(CharacterizationError, match="finite"):
        DCSweepAnalysis("dc", output, "V1", "V(in)", 0, 1, float("inf"))
    with pytest.raises(CharacterizationError, match="greater"):
        ACSweepAnalysis("ac", output, "dec", 10, 10, 1)
    with pytest.raises(CharacterizationError, match=r"ac\.sweep"):
        ACSweepAnalysis("ac", output, "list", 10, 1, 10)  # type: ignore[arg-type]
    with pytest.raises(CharacterizationError, match=r"noise\.points"):
        NoiseAnalysis("noise", output, "q", "0", "V1", "dec", 0, 1, 10)
    with pytest.raises(CharacterizationError, match="independent voltage"):
        NoiseAnalysis("noise", output, "q", "0", "R1", "dec", 1, 1, 10)
    with pytest.raises(CharacterizationError, match=r"noise\.sweep"):
        NoiseAnalysis("noise", output, "q", "0", "V1", "list", 1, 1, 10)  # type: ignore[arg-type]
    with pytest.raises(CharacterizationError, match="greater"):
        NoiseAnalysis("noise", output, "q", "0", "V1", "dec", 1, 10, 1)
    with pytest.raises(CharacterizationError, match="at least one output"):
        OperatingPointAnalysis("op", ())
    with pytest.raises(CharacterizationError, match="finite"):
        PVTCorner("tt", 10**1000, 25)
    with pytest.raises(CharacterizationError, match="reserved"):
        CharacterizationInput("results.csv", EXAMPLE.resolve())
    with pytest.raises(CharacterizationError, match="canonical and absolute"):
        CharacterizationInput("model.inc", Path("model.inc"))
    # Concrete structured types are stable API, not anonymous dictionaries.
    assert ACSweepAnalysis("ac", output, "dec", 10, 1, 10).kind == "ac"
    assert PVTCorner("tt", 1.0, 25.0).label == "tt__v1__t25"
