import asyncio
import ctypes
import errno
import hashlib
import json
import shutil
import sys
import time
from dataclasses import replace
from pathlib import Path

import pytest

from simcairn import XyceCommand, characterize_xyce, load_characterization_plan
from simcairn.adapters import AdapterError, XyceAdapter, create_adapter
from simcairn.cli import main
from simcairn.executor import ActivityExecutor, ExecutionError
from simcairn.fingerprints import stable_json
from simcairn.manifest import ManifestError, SimulatorConfig, load_manifest
from simcairn.model import Activity, canonical_json
from simcairn.planner import compile_plan
from simcairn.store import ArtifactStore
from simcairn.xyce import (
    XyceError,
    XyceExecutionError,
    XyceToolIdentity,
    _acquire_cache_claim,
    _atomic_publish_no_replace,
    _remove_materialized_inputs,
    _rename_no_replace_darwin,
    _rename_no_replace_linux,
    _run_process,
    _verify_cache,
    characterize_xyce_async,
    probe_xyce,
    probe_xyce_sync,
)

ROOT = Path(__file__).parents[1]
EXAMPLE = ROOT / "examples" / "xyce_sram" / "characterization.json"
FAKE = Path(__file__).parent / "fixtures" / "fake_xyce.py"
RUN_TIMEOUT = 30.0


def _fake() -> XyceCommand:
    return XyceCommand.controlled_test_double(sys.executable, str(FAKE))


def _small_plan():
    plan = load_characterization_plan(EXAMPLE)
    return replace(plan, corners=plan.corners[:1], analyses=plan.analyses[:1])


def _xyce_measure_log(*results: str) -> str:
    return (
        " ***** Measure Functions ***** \n\n"
        + "\n\n".join(results)
        + "\n\n***** Total Simulation Solvers Run Time: 0.001 seconds\n"
    )


def test_probe_binds_version_executable_and_test_double_label():
    identity = asyncio.run(probe_xyce(_fake()))
    assert identity.version == "7.10.0"
    assert identity.evidence_class == "controlled-test-double"
    assert identity.executable_size > 0
    assert len(identity.executable_sha256) == 64
    assert len(identity.command_sha256) == 64
    assert identity.as_dict()["name"] == "Xyce"


def test_probe_refuses_to_relabel_the_controlled_fixture_as_real():
    mislabeled = XyceCommand((sys.executable, str(FAKE)))
    with pytest.raises(XyceError, match="evidence class"):
        asyncio.run(probe_xyce(mislabeled))
    unmarked = XyceCommand.controlled_test_double(
        sys.executable,
        "-c",
        "print('This is version Xyce Release 7.10.0-opensource')",
    )
    with pytest.raises(XyceError, match="evidence class"):
        asyncio.run(probe_xyce(unmarked))


def test_probe_sync_is_safe_when_the_caller_owns_an_event_loop():
    async def call_sync_probe():
        return probe_xyce_sync(_fake())

    assert asyncio.run(call_sync_probe()).evidence_class == "controlled-test-double"


def test_complete_fake_pvt_run_is_explicitly_nonphysical_and_cached(tmp_path, monkeypatch):
    monkeypatch.setenv("LEAK_SENTINEL", "must-not-reach-child")
    plan = load_characterization_plan(EXAMPLE)
    output = tmp_path / "report.json"
    cache = tmp_path / "cache"
    report = characterize_xyce(
        plan,
        command=_fake(),
        cache=cache,
        output=output,
        timeout_seconds=RUN_TIMEOUT,
    )
    assert report["schema_version"] == 1
    assert report["execution_count"] == 15
    assert report["identity"]["tool"]["evidence_class"] == "controlled-test-double"
    assert report["identity"]["contract"] == "simcairn.xyce-characterization/1"
    assert "LEAK_SENTINEL" not in report["identity"]["environment"]["variables"]
    assert json.loads(output.read_text(encoding="utf-8"))["cache_key"] == report["cache_key"]
    target = cache / report["cache_key"]
    manifest = json.loads((target / "manifest.json").read_text(encoding="utf-8"))
    assert len(manifest["artifacts"]) == 15 * 6 + 1
    assert all(execution["returncode"] == 0 for execution in report["executions"])
    assert all(
        len(execution["normalized_result_sha256"]) == 64 for execution in report["executions"]
    )
    assert "CONTROLLED TEST DOUBLE" in next(target.rglob("xyce.log")).read_text(encoding="utf-8")

    cached_output = tmp_path / "cached.json"
    cached = characterize_xyce(
        plan, command=_fake(), cache=cache, output=cached_output, timeout_seconds=RUN_TIMEOUT
    )
    assert cached == report
    assert cached_output.read_bytes() == output.read_bytes()
    with pytest.raises(XyceError, match="refusing to overwrite"):
        characterize_xyce(
            plan, command=_fake(), cache=cache, output=output, timeout_seconds=RUN_TIMEOUT
        )


def test_fake_output_normalizes_all_analysis_families(tmp_path):
    plan = replace(
        load_characterization_plan(EXAMPLE), corners=load_characterization_plan(EXAMPLE).corners[:1]
    )
    report = characterize_xyce(
        plan, command=_fake(), cache=tmp_path / "cache", timeout_seconds=RUN_TIMEOUT
    )
    assert [item["analysis"]["kind"] for item in report["executions"]] == [
        "op",
        "dc",
        "ac",
        "tran",
        "noise",
    ]
    assert [item["normalized"]["axis"]["name"] for item in report["executions"]] == [
        "index",
        "sweep",
        "frequency",
        "time",
        "frequency",
    ]


@pytest.mark.parametrize(
    ("mode", "message"),
    [
        ("exit", "status 7"),
        ("missing", "missing requested probe"),
        ("oversize", "exceeded"),
        ("precreate", "refusing to overwrite execution artifact"),
        ("mutate-deck", "changed the rendered characterization deck"),
    ],
)
def test_execution_failures_are_actionable_and_never_publish(tmp_path, mode, message):
    cache = tmp_path / mode
    with pytest.raises((XyceError, XyceExecutionError), match=message):
        characterize_xyce(
            _small_plan(),
            command=_fake(),
            cache=cache,
            timeout_seconds=RUN_TIMEOUT,
            environment={"SIMCAIRN_FAKE_MODE": mode},
        )
    assert not [path for path in cache.iterdir() if len(path.name) == 64]
    assert not list(cache.glob(".xyce-publish-*"))


def test_nonzero_exit_preserves_bounded_xyce_log_diagnostic(tmp_path):
    with pytest.raises(XyceExecutionError, match="controlled diagnostic") as raised:
        characterize_xyce(
            _small_plan(),
            command=_fake(),
            cache=tmp_path / "cache",
            timeout_seconds=RUN_TIMEOUT,
            environment={"SIMCAIRN_FAKE_MODE": "exit"},
        )
    assert raised.value.returncode == 7
    assert raised.value.log == b"controlled diagnostic from Xyce log\n"


def test_timeout_terminates_reaps_and_removes_work(tmp_path):
    cache = tmp_path / "timeout"
    with pytest.raises(XyceExecutionError, match="timed out") as raised:
        characterize_xyce(
            _small_plan(),
            command=_fake(),
            cache=cache,
            timeout_seconds=0.05,
            environment={"SIMCAIRN_FAKE_MODE": "sleep"},
        )
    assert raised.value.returncode is not None
    assert not list(cache.glob(".xyce-publish-*"))


def test_cancellation_terminates_reaps_and_removes_work(tmp_path):
    cache = tmp_path / "cancel"

    async def cancel():
        task = asyncio.create_task(
            characterize_xyce_async(
                _small_plan(),
                command=_fake(),
                cache=cache,
                timeout_seconds=10,
                environment={"SIMCAIRN_FAKE_MODE": "sleep"},
            )
        )
        await asyncio.sleep(0.2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(cancel())
    assert not list(cache.glob(".xyce-publish-*"))


def test_log_overflow_terminates_descendant_process_tree(tmp_path):
    plan = _small_plan()
    plan = replace(plan, limits=replace(plan.limits, max_log_bytes=1024))
    sentinel = tmp_path / "orphan.txt"
    started = time.monotonic()
    with pytest.raises(XyceExecutionError, match="stdout exceeded"):
        characterize_xyce(
            plan,
            command=_fake(),
            cache=tmp_path / "cache",
            timeout_seconds=RUN_TIMEOUT,
            environment={
                "SIMCAIRN_FAKE_MODE": "spawn-child-overflow",
                "SIMCAIRN_CHILD_SENTINEL": str(sentinel),
            },
        )
    assert time.monotonic() - started < 6
    time.sleep(0.7)
    assert not sentinel.exists()


def test_corrupt_cache_fails_closed_instead_of_being_relabelled(tmp_path):
    plan = _small_plan()
    cache = tmp_path / "cache"
    report = characterize_xyce(plan, command=_fake(), cache=cache, timeout_seconds=RUN_TIMEOUT)
    normalized = next((cache / report["cache_key"]).rglob("normalized.json"))
    normalized.write_text("tampered\n", encoding="utf-8")
    with pytest.raises(XyceError, match="artifact changed"):
        characterize_xyce(plan, command=_fake(), cache=cache, timeout_seconds=RUN_TIMEOUT)


def test_cache_binds_embedded_normalized_result_to_its_artifact(tmp_path):
    plan = _small_plan()
    cache = tmp_path / "cache"
    report = characterize_xyce(plan, command=_fake(), cache=cache, timeout_seconds=RUN_TIMEOUT)
    target = cache / report["cache_key"]
    report_path = target / "report.json"
    manifest_path = target / "manifest.json"
    altered = json.loads(report_path.read_text(encoding="utf-8"))
    altered["executions"][0]["normalized"]["axis"]["values"][0] = 99
    payload = stable_json(altered).encode("utf-8")
    report_path.write_bytes(payload)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    record = next(item for item in manifest["artifacts"] if item["name"] == "report.json")
    record.update(size=len(payload), sha256=hashlib.sha256(payload).hexdigest())
    manifest_path.write_text(stable_json(manifest), encoding="utf-8", newline="\n")
    with pytest.raises(XyceError, match="normalized result does not match"):
        characterize_xyce(plan, command=_fake(), cache=cache, timeout_seconds=RUN_TIMEOUT)


def test_cache_recomputes_normalized_evidence_from_raw_results(tmp_path):
    plan = _small_plan()
    cache = tmp_path / "cache"
    report = characterize_xyce(plan, command=_fake(), cache=cache, timeout_seconds=RUN_TIMEOUT)
    target = cache / report["cache_key"]
    report_path = target / "report.json"
    manifest_path = target / "manifest.json"
    altered = json.loads(report_path.read_text(encoding="utf-8"))
    execution = altered["executions"][0]
    result_path = target / execution["evidence_prefix"] / "results.csv"
    result_text = result_path.read_text(encoding="utf-8")
    result_path.write_text(result_text.replace("0.1", "9.1", 1), encoding="utf-8", newline="\n")
    result_payload = result_path.read_bytes()
    execution["raw_result_sha256"] = hashlib.sha256(result_payload).hexdigest()
    report_payload = stable_json(altered).encode("utf-8")
    report_path.write_bytes(report_payload)

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    relative_result = result_path.relative_to(target).as_posix()
    for record in manifest["artifacts"]:
        if record["name"] == relative_result:
            record.update(
                size=len(result_payload), sha256=hashlib.sha256(result_payload).hexdigest()
            )
        elif record["name"] == "report.json":
            record.update(
                size=len(report_payload), sha256=hashlib.sha256(report_payload).hexdigest()
            )
    manifest_path.write_bytes(stable_json(manifest).encode("utf-8"))

    with pytest.raises(XyceError, match="does not reproduce"):
        _verify_cache(target, report["cache_key"])


def test_cache_verifier_rejects_malformed_metadata_and_execution_records(tmp_path):
    plan = _small_plan()
    cache = tmp_path / "cache"
    report = characterize_xyce(plan, command=_fake(), cache=cache, timeout_seconds=RUN_TIMEOUT)
    source = cache / report["cache_key"]

    cases = (
        (
            "manifest-fields",
            lambda manifest, _: manifest.update(unexpected=True),
            "manifest fields",
        ),
        ("empty-artifacts", lambda manifest, _: manifest.update(artifacts=[]), "artifact list"),
        (
            "bad-record",
            lambda manifest, _: manifest["artifacts"][-1].update(size=True),
            "artifact record",
        ),
        (
            "traversal-record",
            lambda manifest, _: manifest["artifacts"][0].update(name="../outside"),
            "artifact record",
        ),
        (
            "missing-report-record",
            lambda manifest, _: manifest.update(
                artifacts=[item for item in manifest["artifacts"] if item["name"] != "report.json"]
            ),
            "report is invalid",
        ),
        ("report-fields", lambda _, value: value.update(unexpected=True), "report fields"),
        ("bad-summary", lambda _, value: value.update(execution_count=True), "execution summary"),
        (
            "execution-fields",
            lambda _, value: value["executions"][0].update(unexpected=True),
            "execution is invalid",
        ),
        (
            "bad-prefix",
            lambda _, value: value["executions"][0].update(evidence_prefix="runs/wrong/op"),
            "evidence prefix",
        ),
        (
            "bad-duration",
            lambda _, value: value["executions"][0].update(duration_seconds=-1),
            "execution duration",
        ),
        (
            "bad-digest",
            lambda _, value: value["executions"][0].update(deck_sha256="bad"),
            "execution digest",
        ),
    )

    for name, mutate, message in cases:
        target = tmp_path / name
        shutil.copytree(source, target)
        manifest_path = target / "manifest.json"
        report_path = target / "report.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        altered = json.loads(report_path.read_text(encoding="utf-8"))
        mutate(manifest, altered)
        report_payload = stable_json(altered).encode("utf-8")
        report_path.write_bytes(report_payload)
        for record in manifest.get("artifacts", []):
            if isinstance(record, dict) and record.get("name") == "report.json":
                record.update(
                    size=len(report_payload), sha256=hashlib.sha256(report_payload).hexdigest()
                )
        manifest_path.write_text(stable_json(manifest), encoding="utf-8", newline="\n")
        try:
            _verify_cache(target, report["cache_key"])
        except XyceError as error:
            assert message in str(error), f"unexpected rejection for cache case {name!r}"
        else:
            pytest.fail(f"cache verifier accepted malformed case {name!r}")

    missing = tmp_path / "missing-artifact"
    shutil.copytree(source, missing)
    next(missing.rglob("results.csv")).unlink()
    with pytest.raises(XyceError, match="artifact is unreadable"):
        _verify_cache(missing, report["cache_key"])

    rebound = tmp_path / "rebound-artifact"
    shutil.copytree(source, rebound)
    result_path = next(rebound.rglob("results.csv"))
    result_path.write_bytes(result_path.read_bytes() + b"\n")
    rebound_manifest_path = rebound / "manifest.json"
    rebound_manifest = json.loads(rebound_manifest_path.read_text(encoding="utf-8"))
    relative_result = result_path.relative_to(rebound).as_posix()
    result_record = next(
        item for item in rebound_manifest["artifacts"] if item["name"] == relative_result
    )
    result_record.update(
        size=result_path.stat().st_size,
        sha256=hashlib.sha256(result_path.read_bytes()).hexdigest(),
    )
    rebound_manifest_path.write_text(stable_json(rebound_manifest), encoding="utf-8", newline="\n")
    with pytest.raises(XyceError, match="report digest changed"):
        _verify_cache(rebound, report["cache_key"])

    unexpected = tmp_path / "unexpected-artifact"
    shutil.copytree(source, unexpected)
    (unexpected / "rogue.txt").write_text("not evidence\n", encoding="utf-8")
    with pytest.raises(XyceError, match="unexpected entries"):
        _verify_cache(unexpected, report["cache_key"])


def test_declared_model_input_is_hash_bound_materialized_and_not_published(tmp_path):
    source = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    source["inputs"] = ["models/device.inc"]
    model = tmp_path / "models" / "device.inc"
    model.parent.mkdir()
    model.write_text(".MODEL EXTRA NMOS LEVEL=1\n", encoding="utf-8")
    deck = tmp_path / "sram_like.cir.tmpl"
    deck.write_text(
        EXAMPLE.with_name("sram_like.cir.tmpl")
        .read_text(encoding="utf-8")
        .replace("* SIMCAIRN:PVT", '.include "models/device.inc"\n* SIMCAIRN:PVT'),
        encoding="utf-8",
    )
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(source), encoding="utf-8")
    plan = replace(
        load_characterization_plan(plan_path),
        corners=(_small_plan().corners[0],),
        analyses=(_small_plan().analyses[0],),
    )
    report = characterize_xyce(
        plan, command=_fake(), cache=tmp_path / "cache", timeout_seconds=RUN_TIMEOUT
    )
    target = tmp_path / "cache" / report["cache_key"]
    assert report["identity"]["plan"]["inputs"][0]["sha256"]
    assert not list(target.rglob("device.inc"))


def test_loaded_plan_and_recursive_inputs_are_one_immutable_snapshot(tmp_path):
    source = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    source["inputs"] = ["models/root.inc", "models/nested.inc"]
    models = tmp_path / "models"
    models.mkdir()
    root_input = models / "root.inc"
    root_input.write_text('.include "nested.inc"\n', encoding="utf-8")
    (models / "nested.inc").write_text(".MODEL EXTRA NMOS LEVEL=1\n", encoding="utf-8")
    deck = tmp_path / "sram_like.cir.tmpl"
    deck.write_text(
        EXAMPLE.with_name("sram_like.cir.tmpl")
        .read_text(encoding="utf-8")
        .replace("* SIMCAIRN:PVT", '.include "models/root.inc"\n* SIMCAIRN:PVT'),
        encoding="utf-8",
    )
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(source), encoding="utf-8")
    plan = replace(
        load_characterization_plan(plan_path),
        corners=(_small_plan().corners[0],),
        analyses=(_small_plan().analyses[0],),
    )
    identity = plan.as_identity_dict()

    changed = dict(source)
    changed["corners"] = [{**source["corners"][0], "voltage": 2.0}]
    plan_path.write_text(json.dumps(changed), encoding="utf-8")
    root_input.write_text('.include "D:/outside/secret.lib"\n', encoding="utf-8")

    assert plan.as_identity_dict() == identity
    with pytest.raises(XyceError, match="changed after its snapshot"):
        characterize_xyce(plan, command=_fake(), cache=tmp_path / "cache")


def test_input_cleanup_rejects_redirected_parent_without_touching_external_file(tmp_path):
    run = tmp_path / "run"
    outside = tmp_path / "outside"
    run.mkdir()
    outside.mkdir()
    marker = outside / "model.inc"
    marker.write_text("model\n", encoding="utf-8")
    try:
        (run / "models").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable on this platform")
    expected = [{"sha256": __import__("hashlib").sha256(marker.read_bytes()).hexdigest()}]
    with pytest.raises(XyceExecutionError, match="redirected"):
        _remove_materialized_inputs(run, (run / "models" / "model.inc",), expected)
    assert marker.read_text(encoding="utf-8") == "model\n"


@pytest.mark.parametrize(
    "argv",
    [(), ("",), ("Xyce\n--evil",), tuple("x" for _ in range(17))],
)
def test_command_contract_rejects_invalid_argv(argv):
    with pytest.raises(XyceError, match="command"):
        XyceCommand(argv)


def test_command_contract_rejects_invalid_evidence_class_and_empty_wrapper(tmp_path):
    with pytest.raises(XyceError, match="evidence_class"):
        XyceCommand(("Xyce",), "invented")
    wrapper = tmp_path / "empty-wrapper.py"
    wrapper.touch()
    with pytest.raises(XyceError, match="empty"):
        asyncio.run(probe_xyce(XyceCommand.controlled_test_double(sys.executable, str(wrapper))))


def test_low_level_runner_reports_launch_failure(tmp_path):
    async def run_missing():
        return await _run_process(
            (str(tmp_path / "missing-Xyce"),),
            cwd=tmp_path,
            environment={},
            timeout_seconds=1,
            maximum_log_bytes=1024,
        )

    with pytest.raises(XyceExecutionError, match="cannot launch"):
        asyncio.run(run_missing())


def test_probe_rejects_missing_or_non_xyce_executable():
    with pytest.raises(XyceError, match="resolve"):
        asyncio.run(probe_xyce(XyceCommand.real("definitely-missing-Xyce-command")))
    command = XyceCommand.controlled_test_double(sys.executable, "-c", "print('not xyce')")
    with pytest.raises(XyceError, match="version banner"):
        asyncio.run(probe_xyce(command))


@pytest.mark.parametrize(
    "environment",
    [
        {"bad-name": "x"},
        {"GOOD": "nul\x00value"},
        {"HOME": "not-the-sandbox"},
        {"Path": "one", "PATH": "two"},
        {f"V{index}": "x" for index in range(65)},
    ],
)
def test_environment_contract_rejects_unsafe_or_unbounded_entries(tmp_path, environment):
    with pytest.raises(XyceError, match="environment"):
        characterize_xyce(
            _small_plan(), command=_fake(), cache=tmp_path / "cache", environment=environment
        )


@pytest.mark.parametrize("timeout", [True, 0, -1, float("nan"), 31_536_001])
def test_timeout_contract_is_finite_and_bounded(tmp_path, timeout):
    with pytest.raises(XyceError, match="timeout_seconds"):
        characterize_xyce(
            _small_plan(), command=_fake(), cache=tmp_path / "cache", timeout_seconds=timeout
        )


def test_cache_and_output_parents_must_already_be_canonical(tmp_path):
    plan = _small_plan()
    missing_cache = tmp_path / "missing" / "cache"
    with pytest.raises(XyceError, match="cache parent"):
        characterize_xyce(plan, command=_fake(), cache=missing_cache, timeout_seconds=RUN_TIMEOUT)

    cache = tmp_path / "cache"
    characterize_xyce(plan, command=_fake(), cache=cache, timeout_seconds=RUN_TIMEOUT)
    with pytest.raises(XyceError, match="output parent"):
        characterize_xyce(
            plan,
            command=_fake(),
            cache=cache,
            output=tmp_path / "missing-output" / "report.json",
            timeout_seconds=RUN_TIMEOUT,
        )


def test_preexisting_cache_target_is_never_replaced(tmp_path):
    plan = _small_plan()
    cache = tmp_path / "cache"
    first = characterize_xyce(plan, command=_fake(), cache=cache, timeout_seconds=RUN_TIMEOUT)
    shutil.rmtree(cache / first["cache_key"])
    target = cache / first["cache_key"]
    target.mkdir()
    marker = target / "owner.txt"
    marker.write_text("preexisting\n", encoding="utf-8")
    with pytest.raises(XyceError, match="cache manifest"):
        characterize_xyce(plan, command=_fake(), cache=cache, timeout_seconds=RUN_TIMEOUT)
    assert marker.read_text(encoding="utf-8") == "preexisting\n"


def test_overlapping_cache_claims_have_one_owner_without_aba_cleanup(tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir()
    cache_key = "a" * 64
    target = cache / cache_key

    first = _acquire_cache_claim(cache, cache_key, target)
    assert first is not None
    with pytest.raises(XyceError, match="claimed by another live process"):
        _acquire_cache_claim(cache, cache_key, target)
    first.release()

    claim_directory = cache / ".claims" / cache_key
    assert claim_directory.is_dir()
    assert not (claim_directory / "run.lock").exists()
    second = _acquire_cache_claim(cache, cache_key, target)
    assert second is not None
    second.release()
    assert claim_directory.is_dir()


def test_cache_claim_is_released_if_publish_workspace_creation_fails(tmp_path, monkeypatch):
    import simcairn.xyce as xyce_module

    original_mkdtemp = xyce_module.tempfile.mkdtemp

    def fail_publication_workspace(*args, **kwargs):
        if kwargs.get("prefix") == ".xyce-publish-":
            raise OSError("injected workspace failure")
        return original_mkdtemp(*args, **kwargs)

    monkeypatch.setattr(xyce_module.tempfile, "mkdtemp", fail_publication_workspace)
    cache = tmp_path / "cache"
    with pytest.raises(OSError, match="injected workspace failure"):
        characterize_xyce(_small_plan(), command=_fake(), cache=cache, timeout_seconds=RUN_TIMEOUT)
    claim_directories = list((cache / ".claims").iterdir())
    assert len(claim_directories) == 1
    assert not (claim_directories[0] / "run.lock").exists()


def test_atomic_publication_never_replaces_a_racing_destination(tmp_path):
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    (source / "new.txt").write_text("new\n", encoding="utf-8")
    destination.mkdir()
    marker = destination / "owner.txt"
    marker.write_text("preexisting\n", encoding="utf-8")

    with pytest.raises(FileExistsError):
        _atomic_publish_no_replace(source, destination)

    assert marker.read_text(encoding="utf-8") == "preexisting\n"
    assert (source / "new.txt").read_text(encoding="utf-8") == "new\n"


def test_publish_race_preserves_untrusted_target_and_fails_closed(tmp_path, monkeypatch):
    import simcairn.xyce as xyce_module

    plan = _small_plan()
    cache = tmp_path / "cache"
    original_publish = xyce_module._atomic_publish_no_replace
    marker: Path | None = None

    def inject_target(source: Path, destination: Path) -> None:
        nonlocal marker
        destination.mkdir()
        marker = destination / "untrusted-owner.txt"
        marker.write_text("do not replace\n", encoding="utf-8")
        original_publish(source, destination)

    monkeypatch.setattr(xyce_module, "_atomic_publish_no_replace", inject_target)
    with pytest.raises(XyceError, match="cache manifest"):
        characterize_xyce(plan, command=_fake(), cache=cache, timeout_seconds=RUN_TIMEOUT)

    assert marker is not None
    assert marker.read_text(encoding="utf-8") == "do not replace\n"
    assert not list(cache.glob(".xyce-publish-*"))


class _FakeNativeRename:
    def __init__(self, result: int):
        self.result = result
        self.calls = []
        self.argtypes = None
        self.restype = None

    def __call__(self, *arguments):
        self.calls.append(arguments)
        return self.result


@pytest.mark.parametrize(
    "implementation, library_name",
    [
        (_rename_no_replace_linux, None),
        (_rename_no_replace_darwin, "/usr/lib/libSystem.B.dylib"),
    ],
)
@pytest.mark.parametrize(
    "result, native_errno, exception",
    [
        (0, 0, None),
        (-1, errno.EEXIST, FileExistsError),
        (-1, errno.ENOTSUP, XyceError),
        (-1, errno.EIO, OSError),
    ],
)
def test_native_exclusive_rename_results_are_fail_closed(
    tmp_path, monkeypatch, implementation, library_name, result, native_errno, exception
):
    function = _FakeNativeRename(result)
    requested_libraries = []

    class Library:
        pass

    library = Library()
    setattr(
        library,
        "renameat2" if implementation is _rename_no_replace_linux else "renamex_np",
        function,
    )

    def fake_cdll(name, *, use_errno):
        requested_libraries.append((name, use_errno))
        return library

    monkeypatch.setattr(ctypes, "CDLL", fake_cdll)
    monkeypatch.setattr(ctypes, "set_errno", lambda value: None)
    monkeypatch.setattr(ctypes, "get_errno", lambda: native_errno)
    source = tmp_path / "source"
    destination = tmp_path / "destination"

    if exception is None:
        implementation(source, destination)
    else:
        with pytest.raises(exception):
            implementation(source, destination)
    assert requested_libraries == [(library_name, True)]
    assert function.calls


@pytest.mark.parametrize("implementation", [_rename_no_replace_linux, _rename_no_replace_darwin])
def test_native_exclusive_rename_requires_the_platform_symbol(
    tmp_path, monkeypatch, implementation
):
    monkeypatch.setattr(ctypes, "CDLL", lambda *_args, **_kwargs: object())
    with pytest.raises(XyceError, match="no atomic no-replace rename support"):
        implementation(tmp_path / "source", tmp_path / "destination")


@pytest.mark.parametrize(
    "system, helper_name",
    [("Linux", "_rename_no_replace_linux"), ("Darwin", "_rename_no_replace_darwin")],
)
def test_atomic_publication_dispatches_to_native_exclusive_rename(
    tmp_path, monkeypatch, system, helper_name
):
    import simcairn.xyce as xyce_module

    source = tmp_path / "source"
    source.mkdir()
    destination = tmp_path / "destination"
    calls = []
    monkeypatch.setattr(xyce_module.platform, "system", lambda: system)
    monkeypatch.setattr(xyce_module, helper_name, lambda old, new: calls.append((old, new)))
    _atomic_publish_no_replace(source, destination)
    assert calls == [(source, destination)]


def test_atomic_publication_rejects_unsupported_or_invalid_paths(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    other = tmp_path / "other"
    other.mkdir()
    with pytest.raises(XyceError, match="share a parent"):
        _atomic_publish_no_replace(source, other / "destination")

    missing = tmp_path / "missing"
    with pytest.raises(XyceError, match="source is unreadable"):
        _atomic_publish_no_replace(missing, tmp_path / "destination")

    monkeypatch.setattr("simcairn.xyce.platform.system", lambda: "Plan9")
    with pytest.raises(XyceError, match="unsupported on Plan9"):
        _atomic_publish_no_replace(source, tmp_path / "destination")


def test_existing_adapter_registry_supports_xyce_measure_files(tmp_path, monkeypatch):
    adapter = create_adapter(SimulatorConfig("xyce", "custom-Xyce", (("LICENSE", "path"),), "tran"))
    assert isinstance(adapter, XyceAdapter)
    assert adapter.environment == (("LICENSE", "path"),)
    (tmp_path / "deck.sp").write_text(
        "title\n.tran 1n 1n\n.measure tran delay FIND V(q) AT=1n\n"
        ".measure tran power AVG P(VDD)\n.end\n",
        encoding="utf-8",
    )
    assert adapter.command(tmp_path, {"measure_fields": ["delay", "power"]}) == [
        "custom-Xyce",
        "-l",
        "xyce.log",
        "-o",
        "xyce_output",
        "deck.sp",
    ]
    assert adapter.expected_artifacts()[-2:] == ("xyce.log", "xyce_output.mt0")
    (tmp_path / "xyce.log").write_text(
        _xyce_measure_log("DELAY = 1.25e-9 for AT = 1e-9", "POWER = .002"),
        encoding="utf-8",
    )
    (tmp_path / "xyce_output.mt0").write_text("delay = 1.25e-9\npower = .002\n", encoding="utf-8")
    adapter.collect(tmp_path, {"measure_fields": ["delay", "power"]})
    assert json.loads((tmp_path / "metrics.json").read_text(encoding="utf-8")) == {
        "delay": 1.25e-9,
        "power": 0.002,
    }

    identity = XyceToolIdentity(
        "7.10",
        "Xyce",
        "b" * 64,
        123,
        "a" * 64,
        "real",
    )
    observed = {}

    def fake_probe(*args, **kwargs):
        observed.update(kwargs)
        return identity

    monkeypatch.setattr("simcairn.adapters.probe_xyce_sync", fake_probe)
    configured = XyceAdapter("Xyce", "tran", (("XYCE_LICENSE", "explicit"),))
    assert configured.identity() == (
        "simcairn-xyce-measure/4:tran:xyce_output.mt0:Xyce-7.10:command-sha256-" + "a" * 64
    )
    assert observed["environment"] == {"XYCE_LICENSE": "explicit"}


def test_xyce_measure_adapter_rejects_missing_duplicate_and_oversized_results(tmp_path):
    adapter = XyceAdapter("Xyce", "tran")
    with pytest.raises(AdapterError, match="mt0"):
        adapter.collect(tmp_path, {"measure_fields": ["delay"]})
    (tmp_path / "xyce.log").write_text("ok\n", encoding="utf-8")
    output = tmp_path / "xyce_output.mt0"
    output.write_text("delay = 1\ndelay = 2\n", encoding="utf-8")
    with pytest.raises(AdapterError, match="duplicated"):
        adapter.collect(tmp_path, {"measure_fields": ["delay"]})
    output.write_text("other = 1\n", encoding="utf-8")
    with pytest.raises(AdapterError, match="missing requested"):
        adapter.collect(tmp_path, {"measure_fields": ["delay"]})
    output.write_text("delay = 1e999\n", encoding="utf-8")
    with pytest.raises(AdapterError, match="non-finite"):
        adapter.collect(tmp_path, {"measure_fields": ["delay"]})
    with output.open("wb") as stream:
        stream.truncate(16 * 1024 * 1024 + 1)
    with pytest.raises(AdapterError, match="exceeds"):
        adapter.collect(tmp_path, {"measure_fields": ["delay"]})


@pytest.mark.parametrize(
    ("diagnostic_name", "diagnostic"),
    [
        ("stdout.log", "delay = FAILED\n"),
        ("stderr.log", "DELAY = failed\n"),
        ("xyce.log", "DeLaY = FaIlEd at time = 0\n"),
    ],
)
def test_xyce_measure_adapter_rejects_numeric_default_for_failed_measure(
    tmp_path, diagnostic_name, diagnostic
):
    adapter = XyceAdapter("Xyce", "tran")
    (tmp_path / "xyce.log").write_text(
        _xyce_measure_log("DELAY = 1e-9 for AT = 1e-9"), encoding="utf-8"
    )
    (tmp_path / diagnostic_name).write_text(diagnostic, encoding="utf-8")
    (tmp_path / "xyce_output.mt0").write_text("delay = 0\n", encoding="utf-8")

    with pytest.raises(AdapterError, match="measurement 'delay' failed"):
        adapter.collect(tmp_path, {"measure_fields": ["delay"]})
    assert not (tmp_path / "metrics.json").exists()


def test_xyce_measure_adapter_rejects_suppressed_failed_measure_without_positive_evidence(
    tmp_path,
):
    """Real Xyce 7.10 MEASPRINT=NONE can hide failure behind DEFAULT_VAL=0."""

    adapter = XyceAdapter("Xyce", "tran")
    (tmp_path / "xyce.log").write_text(
        "***** Total Simulation Solvers Run Time: 0.001 seconds\n"
        "***** End of Xyce(TM) Simulation\n",
        encoding="utf-8",
    )
    (tmp_path / "xyce_output.mt0").write_text("NEVER = 0.000000e+00\n", encoding="utf-8")

    with pytest.raises(AdapterError, match="positive success evidence"):
        adapter.collect(tmp_path, {"measure_fields": ["never"]})
    assert not (tmp_path / "metrics.json").exists()


@pytest.mark.parametrize(
    ("log", "message"),
    [
        (
            "delay = 1e-9\n" + _xyce_measure_log("other = 1"),
            "lacks positive success evidence",
        ),
        (
            _xyce_measure_log("delay = 1e-9", "DELAY = 1e-9"),
            "ambiguous success evidence",
        ),
        (
            _xyce_measure_log("delay = 1e-9") + _xyce_measure_log("delay = 1e-9"),
            "ambiguous Measure Functions sections",
        ),
        (
            " ***** Measure Functions ***** \n\ndelay = 1e-9\n",
            "success evidence section is incomplete",
        ),
        (
            _xyce_measure_log("delay = 1e999"),
            "success evidence for measurement 'delay' is non-finite",
        ),
    ],
)
def test_xyce_measure_adapter_requires_unique_bounded_verbose_success_evidence(
    tmp_path, log, message
):
    adapter = XyceAdapter("Xyce", "tran")
    (tmp_path / "xyce.log").write_text(log, encoding="utf-8")
    (tmp_path / "xyce_output.mt0").write_text("delay = 1e-9\n", encoding="utf-8")

    with pytest.raises(AdapterError, match=message):
        adapter.collect(tmp_path, {"measure_fields": ["delay"]})
    assert not (tmp_path / "metrics.json").exists()


def test_xyce_measure_adapter_requires_log_and_measure_file_values_to_agree(tmp_path):
    adapter = XyceAdapter("Xyce", "tran")
    (tmp_path / "xyce.log").write_text(
        _xyce_measure_log("DELAY = 2e-9 for AT = 1e-9"), encoding="utf-8"
    )
    (tmp_path / "xyce_output.mt0").write_text("delay = 1e-9\n", encoding="utf-8")

    with pytest.raises(AdapterError, match=r"disagrees between xyce\.log and xyce_output\.mt0"):
        adapter.collect(tmp_path, {"measure_fields": ["delay"]})
    assert not (tmp_path / "metrics.json").exists()


def test_xyce_measure_adapter_rejects_additional_step_result_file(tmp_path):
    adapter = XyceAdapter("Xyce", "tran")
    (tmp_path / "xyce.log").write_text(
        _xyce_measure_log("DELAY = 1e-9 for AT = 1e-9"), encoding="utf-8"
    )
    (tmp_path / "xyce_output.mt0").write_text("delay = 1e-9\n", encoding="utf-8")
    (tmp_path / "xyce_output.mt1").write_text("delay = 2e-9\n", encoding="utf-8")

    with pytest.raises(AdapterError, match=r"unsupported \.STEP output"):
        adapter.collect(tmp_path, {"measure_fields": ["delay"]})
    assert not (tmp_path / "metrics.json").exists()


def test_xyce_measure_adapter_does_not_misread_unrelated_failure_text(tmp_path):
    adapter = XyceAdapter("Xyce", "tran")
    (tmp_path / "stdout.log").write_text(
        "0 failed nonlinear iterations\nother = FAILED at time = 0\n",
        encoding="utf-8",
    )
    (tmp_path / "stderr.log").write_text("no requested measure failed\n", encoding="utf-8")
    (tmp_path / "xyce.log").write_text(
        _xyce_measure_log("DELAY = 1e-9 for AT = 1e-9"), encoding="utf-8"
    )
    (tmp_path / "xyce_output.mt0").write_text("delay = 1e-9\n", encoding="utf-8")

    adapter.collect(tmp_path, {"measure_fields": ["delay"]})
    assert json.loads((tmp_path / "metrics.json").read_text(encoding="utf-8")) == {"delay": 1e-9}


@pytest.mark.parametrize(
    ("analysis", "filename"),
    [
        ("tran", "xyce_output.mt0"),
        ("dc", "xyce_output.ms0"),
        ("ac", "xyce_output.ma0"),
        ("noise", "xyce_output.ma0"),
    ],
)
def test_xyce_measure_adapter_selects_declared_output_family(tmp_path, analysis, filename):
    adapter = XyceAdapter("Xyce", analysis)
    assert adapter.expected_artifacts()[-1] == filename
    (tmp_path / "xyce.log").write_text(_xyce_measure_log("GAIN = 2.5"), encoding="utf-8")
    (tmp_path / filename).write_text("gain = 2.5\n", encoding="utf-8")
    adapter.collect(tmp_path, {"measure_fields": ["gain"]})
    assert json.loads((tmp_path / "metrics.json").read_text(encoding="utf-8")) == {"gain": 2.5}


def test_xyce_measure_adapter_does_not_guess_another_output_family(tmp_path):
    adapter = XyceAdapter("Xyce", "dc")
    (tmp_path / "xyce.log").write_text("ok\n", encoding="utf-8")
    (tmp_path / "xyce_output.mt0").write_text("gain = 2.5\n", encoding="utf-8")
    with pytest.raises(AdapterError, match=r"xyce_output\.ms0"):
        adapter.collect(tmp_path, {"measure_fields": ["gain"]})


@pytest.mark.parametrize(
    ("deck", "fields", "message"),
    [
        ("title\n.tran 1n 1n\n.end\n", ["delay"], "no scalar"),
        (
            "title\n.dc V1 0 1 1\n.measure dc delay FIND V(q) AT=1\n.end\n",
            ["delay"],
            "family",
        ),
        ("title\n.measure op delay FIND V(q)\n.end\n", ["delay"], "unsupported"),
        (
            "title\n.measure tran other FIND V(q) AT=1n\n.end\n",
            ["delay"],
            "names",
        ),
        (
            "title\n.measure tran delay FIND V(q) AT=1n\n"
            ".measure tran DELAY FIND V(q) AT=1n\n.end\n",
            ["delay"],
            "repeats",
        ),
        (
            "title\nV1 q 0 0\n.tran 1n 1n\n.step V1 0 1 1\n"
            ".measure tran delay FIND V(q) AT=1n\n.end\n",
            ["delay"],
            r"\.STEP",
        ),
    ],
)
def test_xyce_command_binds_measure_cards_to_declared_contract(tmp_path, deck, fields, message):
    (tmp_path / "deck.sp").write_text(deck, encoding="utf-8")
    with pytest.raises(AdapterError, match=message):
        XyceAdapter("Xyce", "tran").command(tmp_path, {"measure_fields": fields})


def test_xyce_measure_identity_wraps_probe_errors(monkeypatch):
    def fail(*args, **kwargs):
        raise XyceError("missing or invalid")

    monkeypatch.setattr("simcairn.adapters.probe_xyce_sync", fail)
    with pytest.raises(ManifestError, match="cannot identify"):
        XyceAdapter("Xyce", "tran").identity()


def test_manifest_defaults_xyce_executable_and_binds_plan_identity(tmp_path, monkeypatch):
    deck = tmp_path / "deck.sp"
    deck.write_text(
        "title\n.tran 1n 1n\n.measure tran q FIND V(q) AT=1n\n.end\n",
        encoding="utf-8",
    )
    manifest_path = tmp_path / "simcairn.toml"
    manifest_path.write_text(
        """version=1
[simulator]
adapter="xyce"
measure_analysis="tran"
[template]
deck="deck.sp"
[sweep]
corner=["tt"]
[run]
jobs=1
[[measure]]
name="q"
""",
        encoding="utf-8",
    )
    manifest = load_manifest(manifest_path)
    assert manifest.simulator.executable == "Xyce"
    assert manifest.simulator.measure_analysis == "tran"
    monkeypatch.setattr(XyceAdapter, "identity", lambda self: "xyce-test-identity")
    plan = compile_plan(manifest)
    simulate = plan.activities[1]
    assert simulate.payload["adapter"] == "xyce"
    assert simulate.payload["measure_analysis"] == "tran"
    assert simulate.identity["adapter_identity"] == "xyce-test-identity"


@pytest.mark.parametrize(
    ("adapter", "analysis", "message"),
    [
        ("xyce", "", "required for xyce"),
        ("xyce", 'measure_analysis="op"\n', "required for xyce"),
        ("mock-rc", 'measure_analysis="tran"\n', "only valid"),
    ],
)
def test_manifest_measure_analysis_contract(tmp_path, adapter, analysis, message):
    (tmp_path / "deck.sp").write_text("title\n.end\n", encoding="utf-8")
    (tmp_path / "simcairn.toml").write_text(
        f'''version=1
[simulator]
adapter="{adapter}"
{analysis}[template]
deck="deck.sp"
[sweep]
corner=["tt"]
[run]
jobs=1
[[measure]]
name="q"
''',
        encoding="utf-8",
    )
    with pytest.raises(ManifestError, match=message):
        load_manifest(tmp_path / "simcairn.toml")


def test_manifest_xyce_execution_uses_the_bounded_process_path(tmp_path, monkeypatch):
    class ControlledScalarAdapter:
        name = "xyce"

        def identity(self):
            return "controlled-scalar-identity"

        def command(self, sandbox, payload):
            del sandbox, payload
            script = (
                "from pathlib import Path;"
                "Path('xyce.log').write_text('controlled\\n');"
                "Path('xyce_output.mt0').write_text('delay = 1e-9\\n')"
            )
            return [sys.executable, "-c", script]

        def collect(self, sandbox, payload):
            del payload
            assert (sandbox / "xyce_output.mt0").read_text() == "delay = 1e-9\n"
            (sandbox / "metrics.json").write_text('{"delay":1e-9}\n', encoding="utf-8")

    monkeypatch.setattr(
        "simcairn.executor.create_adapter", lambda config: ControlledScalarAdapter()
    )
    payload = {
        "adapter": "xyce",
        "executable": "controlled",
        "environment": {},
        "measure_analysis": "tran",
        "measure_fields": ["delay"],
    }
    identity = {**payload, "adapter_identity": "controlled-scalar-identity"}
    activity = Activity(
        "f" * 64,
        "simulate",
        None,
        (),
        (),
        ("metrics.json", "stdout.log", "stderr.log", "xyce.log", "xyce_output.mt0"),
        (),
        5,
        canonical_json(payload),
        canonical_json(identity),
    )
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    executor = ActivityExecutor(ArtifactStore(tmp_path / "store"))
    asyncio.run(executor._simulate(activity, sandbox))
    assert json.loads((sandbox / "metrics.json").read_text(encoding="utf-8"))["delay"] == 1e-9
    assert (sandbox / "stdout.log").read_bytes() == b""
    assert (sandbox / "stderr.log").read_bytes() == b""

    mismatched = replace(
        activity, identity_json=canonical_json({**identity, "adapter_identity": "old"})
    )
    with pytest.raises(ExecutionError, match="identity changed"):
        asyncio.run(executor._simulate(mismatched, sandbox))


@pytest.mark.parametrize(
    ("stdout", "xyce_log", "message"),
    [
        (
            "DeLaY = FaIlEd at time = 0\n",
            "controlled failure diagnostic\n",
            "measurement 'delay' failed",
        ),
        (
            "",
            "***** Total Simulation Solvers Run Time: 0.001 seconds\n"
            "***** End of Xyce(TM) Simulation\n",
            "no positive success evidence section",
        ),
    ],
)
def test_failed_xyce_measure_default_is_not_published_to_cache(
    tmp_path, monkeypatch, stdout, xyce_log, message
):
    class ControlledFailedScalarAdapter:
        name = "xyce"

        def identity(self):
            return "controlled-failed-scalar-identity"

        def command(self, sandbox, payload):
            del sandbox, payload
            script = (
                "from pathlib import Path;"
                f"print({stdout!r}, end='');"
                f"Path('xyce.log').write_text({xyce_log!r});"
                "Path('xyce_output.mt0').write_text('delay = 0\\n')"
            )
            return [sys.executable, "-c", script]

        def collect(self, sandbox, payload):
            XyceAdapter("controlled", "tran").collect(sandbox, payload)

    monkeypatch.setattr(
        "simcairn.executor.create_adapter", lambda config: ControlledFailedScalarAdapter()
    )
    payload = {
        "adapter": "xyce",
        "executable": "controlled",
        "environment": {},
        "measure_analysis": "tran",
        "measure_fields": ["delay"],
    }
    identity = {**payload, "adapter_identity": "controlled-failed-scalar-identity"}
    activity = Activity(
        "e" * 64,
        "simulate",
        None,
        (),
        (),
        ("metrics.json", "stdout.log", "stderr.log", "xyce.log", "xyce_output.mt0"),
        (),
        5,
        canonical_json(payload),
        canonical_json(identity),
    )
    store = ArtifactStore(tmp_path / "store")

    outcome = asyncio.run(ActivityExecutor(store).execute(activity))

    assert outcome.status == "failed"
    assert message in outcome.message
    assert not store.cache_path(activity.id).exists()


def test_cli_characterize_uses_real_command_surface_and_reports_errors(
    tmp_path, monkeypatch, capsys
):
    observed = {}

    def fake_characterize(plan, **kwargs):
        observed.update(kwargs)
        Path(kwargs["output"]).write_text("{}\n", encoding="utf-8")
        return {"cache_key": "a" * 64, "execution_count": 15}

    monkeypatch.setattr("simcairn.cli.characterize_xyce", fake_characterize)
    output = tmp_path / "report.json"
    assert (
        main(
            [
                "characterize-xyce",
                str(EXAMPLE),
                "--xyce",
                "custom-Xyce",
                "--cache",
                str(tmp_path / "cache"),
                "--output",
                str(output),
                "--timeout",
                "12",
            ]
        )
        == 0
    )
    assert observed["command"] == XyceCommand.real("custom-Xyce")
    assert observed["timeout_seconds"] == 12
    assert "15 executions" in capsys.readouterr().out

    monkeypatch.setattr(
        "simcairn.cli.characterize_xyce",
        lambda *args, **kwargs: (_ for _ in ()).throw(XyceError("bad Xyce")),
    )
    assert main(["characterize-xyce", str(EXAMPLE), "--output", str(tmp_path / "x")]) == 2
    assert "bad Xyce" in capsys.readouterr().err


def test_real_xyce_presence_is_reported_without_fabricating_numbers():
    executable = shutil.which("Xyce")
    if executable is None:
        pytest.skip("Xyce is not installed; controlled fixtures are explicitly nonphysical")
    identity = asyncio.run(probe_xyce(XyceCommand.real(executable)))
    assert identity.evidence_class == "real"
