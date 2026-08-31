import json
import os
import socket
from datetime import UTC, datetime

import pytest

from simcairn.fingerprints import fingerprint, sha256_file
from simcairn.journal import (
    Journal,
    JournalError,
    RunLock,
    clear_run_lock,
    latest_activity_states,
    replay,
)
from simcairn.model import Activity, InputDigest, Plan, SweepPoint, canonical_json
from simcairn.provenance import current_producer_identity
from simcairn.store import ArtifactStore, StoreError


def _activity(artifacts=("result.txt",)) -> Activity:
    point = SweepPoint(0, (("R", "1k"),))
    identity = {
        "producer_identity": current_producer_identity().as_dict(),
        "renderer": "test-renderer/1",
    }
    inputs = (InputDigest("template.sp", "__template__", "d" * 64),)
    identifier = fingerprint(
        {
            "activity_schema": 2,
            "kind": "render",
            "point": list(point.values),
            "dependencies": [],
            "inputs": [{"logical_name": "__template__", "sha256": "d" * 64}],
            "expected_artifacts": list(artifacts),
            "identity": identity,
        }
    )
    return Activity(
        identifier,
        "render",
        point,
        (),
        inputs,
        tuple(artifacts),
        (),
        10.0,
        canonical_json(
            {
                "template_path": "template.sp",
                "point": {"R": "1k"},
                "copies": [],
            }
        ),
        canonical_json(identity),
    )


def _plan(activity: Activity | None = None) -> Plan:
    item = activity or _activity()
    plan_id = fingerprint(
        {
            "plan_schema": 2,
            "activities": [item.id],
            "jobs": 1,
            "resources": {"simulator": 1},
            "fail_fast": False,
        }
    )
    return Plan(plan_id, "manifest.toml", (item,), 1, (("simulator", 1),), False)


def test_publish_verify_materialize_and_explain(tmp_path):
    store = ArtifactStore(tmp_path / "store")
    activity = _activity()
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    (sandbox / "result.txt").write_text("deterministic\n", encoding="utf-8")
    target = store.publish(activity, sandbox)
    assert target == store.cache_path(activity.id)
    assert store.verify(activity.id) == (True, "verified")
    manifest = store.explain(activity.id)
    assert manifest["activity"]["kind"] == "render"
    assert manifest["artifacts"][0]["name"] == "result.txt"
    destination = tmp_path / "materialized"
    paths = store.materialize(activity.id, destination)
    assert paths == (destination / "result.txt",)
    assert paths[0].read_text(encoding="utf-8") == "deterministic\n"


def test_nested_artifacts_are_preserved(tmp_path):
    store = ArtifactStore(tmp_path / "store")
    activity = _activity(artifacts=("models/device.inc", "logs/run.log"))
    sandbox = tmp_path / "sandbox"
    (sandbox / "models").mkdir(parents=True)
    (sandbox / "logs").mkdir()
    (sandbox / "models" / "device.inc").write_text("model", encoding="utf-8")
    (sandbox / "logs" / "run.log").write_text("ok", encoding="utf-8")
    store.publish(activity, sandbox)
    destination = tmp_path / "copy"
    store.materialize(activity.id, destination)
    assert (destination / "models" / "device.inc").read_text(encoding="utf-8") == "model"


def test_corrupt_cache_is_detected_and_replaced(tmp_path):
    store = ArtifactStore(tmp_path / "store")
    activity = _activity()
    first = tmp_path / "first"
    first.mkdir()
    (first / "result.txt").write_text("first", encoding="utf-8")
    store.publish(activity, first)
    cached = store.cache_path(activity.id) / "files" / "result.txt"
    cached.write_text("corrupt and longer", encoding="utf-8")
    valid, reason = store.verify(activity.id)
    assert not valid
    assert "size changed" in reason
    second = tmp_path / "second"
    second.mkdir()
    (second / "result.txt").write_text("second", encoding="utf-8")
    store.publish(activity, second)
    assert store.verify(activity.id)[0]
    assert cached.read_text(encoding="utf-8") == "second"


def test_publish_requires_all_declared_artifacts(tmp_path):
    store = ArtifactStore(tmp_path / "store")
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    with pytest.raises(StoreError, match="did not create"):
        store.publish(_activity(), sandbox)


@pytest.mark.parametrize("identifier", ["short", "g" * 64, "../" + "a" * 61])
def test_cache_ids_are_validated(tmp_path, identifier):
    store = ArtifactStore(tmp_path / "store")
    with pytest.raises(StoreError, match="invalid activity id"):
        store.cache_path(identifier)


@pytest.mark.parametrize("artifact", ["../escape", "/absolute", "folder/../../escape"])
def test_artifact_paths_cannot_escape_sandbox(tmp_path, artifact):
    store = ArtifactStore(tmp_path / "store")
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    with pytest.raises(StoreError, match="unsafe artifact"):
        store.publish(_activity(artifacts=(artifact,)), sandbox)


def test_run_ids_increment_and_saved_plan_round_trips(tmp_path):
    store = ArtifactStore(tmp_path / "store")
    plan = _plan()
    first_id, first_directory = store.create_run(plan)
    second_id, _ = store.create_run(plan)
    assert first_id.endswith("-0001")
    assert second_id.endswith("-0002")
    assert store.load_plan(first_id) == plan
    assert store.run_directory(first_id) == first_directory


def test_invalid_run_ids_and_saved_plans_are_rejected(tmp_path):
    store = ArtifactStore(tmp_path / "store")
    with pytest.raises(StoreError, match="invalid run id"):
        store.run_directory("../outside")
    with pytest.raises(StoreError, match="cannot load run"):
        store.load_plan("missing-0001")
    run_id, directory = store.create_run(_plan())
    (directory / "plan.json").write_text("not json", encoding="utf-8")
    with pytest.raises(StoreError, match="cannot load run"):
        store.load_plan(run_id)


def test_saved_plan_rejects_duplicate_json_keys(tmp_path):
    store = ArtifactStore(tmp_path / "store")
    run_id, directory = store.create_run(_plan())
    path = directory / "plan.json"
    text = path.read_text(encoding="utf-8")
    path.write_text(
        text.replace('"manifest_path":', '"manifest_path":"forged","manifest_path":', 1),
        encoding="utf-8",
    )
    with pytest.raises(StoreError, match="duplicate JSON object key"):
        store.load_plan(run_id)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda data: data.update(jobs=True), "jobs must be a positive integer"),
        (lambda data: data.update(fail_fast=1), "fail_fast must be boolean"),
        (lambda data: data.update(id="0" * 64), "id does not match"),
        (
            lambda data: data["activities"][0].update(timeout_seconds=float("nan")),
            "non-finite JSON number",
        ),
        (
            lambda data: data["activities"][0].update(id="not-a-digest"),
            "activity id must be",
        ),
        (
            lambda data: data["activities"][0].update(dependencies=["c" * 64]),
            "activity id does not match its identity",
        ),
        (
            lambda data: data["activities"][0].update(payload={"value": float("inf")}),
            "non-finite",
        ),
        (
            lambda data: data["activities"][0].update(unexpected=True),
            "activity fields are invalid",
        ),
    ],
)
def test_saved_plan_rejects_type_coercion_nonfinite_values_and_identity_tampering(
    tmp_path, mutate, message
):
    store = ArtifactStore(tmp_path / "store")
    run_id, directory = store.create_run(_plan())
    path = directory / "plan.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    mutate(data)
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(StoreError, match=message):
        store.load_plan(run_id)


def test_journal_append_replay_and_latest_state(tmp_path):
    path = tmp_path / "events.jsonl"
    times = iter([datetime(2026, 1, 1, tzinfo=UTC), datetime(2026, 1, 2, tzinfo=UTC)])
    journal = Journal(path, clock=lambda: next(times))
    journal.append("started", activity_id="a" * 64)
    journal.append("succeeded", activity_id="a" * 64, duration_seconds=1.5)
    events = replay(path)
    assert [event["sequence"] for event in events] == [0, 1]
    assert events[1]["duration_seconds"] == 1.5
    assert latest_activity_states(events)["a" * 64]["state"] == "succeeded"


@pytest.mark.parametrize(
    "content",
    [
        '{"sequence":0,"sequence":0}\n',
        '{"sequence":0,"duration_seconds":NaN}\n',
    ],
)
def test_journal_rejects_ambiguous_json(content, tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(JournalError, match="invalid journal JSON"):
        replay(path)


@pytest.mark.parametrize(
    "event",
    [
        [],
        {
            "sequence": 0,
            "time": "now",
            "state": "started",
            "activity_id": None,
            "message": "",
            "extra": 1,
        },
        {"sequence": 0, "time": "", "state": "started", "activity_id": None, "message": ""},
        {"sequence": 0, "time": "now", "state": "", "activity_id": None, "message": ""},
        {"sequence": 0, "time": "now", "state": "started", "activity_id": "", "message": ""},
        {"sequence": 0, "time": "now", "state": "started", "activity_id": None, "message": 1},
        {
            "sequence": 0,
            "time": "now",
            "state": "started",
            "activity_id": None,
            "message": "",
            "duration_seconds": True,
        },
        {
            "sequence": 0,
            "time": "now",
            "state": "started",
            "activity_id": None,
            "message": "",
            "duration_seconds": -1,
        },
    ],
)
def test_journal_rejects_invalid_event_schema(event, tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text(json.dumps(event) + "\n", encoding="utf-8")
    with pytest.raises(JournalError, match="invalid journal"):
        replay(path)


def test_truncated_final_event_is_ignored_but_internal_corruption_is_not(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text(
        canonical_json(
            {
                "sequence": 0,
                "time": "now",
                "state": "started",
                "activity_id": "a",
                "message": "",
            }
        )
        + "\n"
        + '{"sequence":1',
        encoding="utf-8",
    )
    assert len(replay(path)) == 1
    path.write_text("not-json\n{}\n", encoding="utf-8")
    with pytest.raises(JournalError, match="line 1"):
        replay(path)


def test_journal_sequence_corruption_is_rejected(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text(json.dumps({"sequence": 4}) + "\n", encoding="utf-8")
    with pytest.raises(JournalError, match="sequence"):
        replay(path)


def test_run_lock_is_single_writer_and_cleans_up(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    with RunLock(run):
        assert (run / "run.lock").is_dir()
        with pytest.raises(JournalError, match="already locked"), RunLock(run):
            pass
    assert not (run / "run.lock").exists()


def test_run_lock_payload_has_nonce_and_process_start_marker(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    with RunLock(run):
        owner = json.loads(next((run / "run.lock").iterdir()).read_text(encoding="utf-8"))
        assert owner["schema_version"] == 1
        assert len(owner["nonce"]) == 32
        assert isinstance(owner["process_start"], str)


def test_old_owner_does_not_remove_successor_lock_after_forced_unlock(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    first = RunLock(run)
    first.__enter__()
    clear_run_lock(run, force=True)
    successor = RunLock(run)
    successor.__enter__()
    successor_marker = next((run / "run.lock").iterdir())
    successor_payload = successor_marker.read_bytes()

    first.__exit__(None, None, None)

    assert successor_marker.read_bytes() == successor_payload
    successor.__exit__(None, None, None)
    assert not (run / "run.lock").exists()


@pytest.mark.parametrize(
    ("probe", "expected_state"),
    [(("dead", None), "stale"), (("alive", "new-start"), "stale")],
)
def test_run_lock_recovers_dead_owner_and_pid_reuse(tmp_path, monkeypatch, probe, expected_state):
    run = tmp_path / "run"
    run.mkdir()
    lock = run / "run.lock"
    lock.write_text(
        canonical_json(
            {
                "schema_version": 1,
                "pid": 123,
                "host": socket.gethostname(),
                "process_start": "old-start",
                "nonce": "a" * 32,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "simcairn.journal._probe_process",
        lambda pid: ("alive", "current-start") if pid == os.getpid() else probe,
    )
    with RunLock(run):
        replacement = json.loads(next(lock.iterdir()).read_text(encoding="utf-8"))
        assert replacement["process_start"] == "current-start"
    assert expected_state == "stale"


def test_run_lock_recovers_stale_directory_protocol_owner(tmp_path, monkeypatch):
    run = tmp_path / "run"
    lock = run / "run.lock"
    lock.mkdir(parents=True)
    marker = lock / f"owner-{'a' * 32}.json"
    marker.write_text(
        canonical_json(
            {
                "schema_version": 1,
                "pid": 123,
                "host": socket.gethostname(),
                "process_start": "old-start",
                "nonce": "a" * 32,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "simcairn.journal._probe_process",
        lambda pid: ("alive", "current-start") if pid == os.getpid() else ("dead", None),
    )
    with RunLock(run):
        replacement = json.loads(next(lock.iterdir()).read_text(encoding="utf-8"))
        assert replacement["nonce"] != "a" * 32


def test_force_unlock_rejects_malformed_lock_directory(tmp_path):
    run = tmp_path / "run"
    lock = run / "run.lock"
    lock.mkdir(parents=True)
    (lock / "unexpected.txt").write_text("not an owner", encoding="utf-8")
    with pytest.raises(JournalError, match="invalid owner marker"):
        clear_run_lock(run, force=True)


def test_foreign_lock_requires_force_and_writes_audit(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    lock = run / "run.lock"
    lock.write_text(
        canonical_json(
            {
                "schema_version": 1,
                "pid": 42,
                "host": "different-host",
                "process_start": "remote-start",
                "nonce": "a" * 32,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(JournalError, match="refusing to unlock foreign"):
        clear_run_lock(run)
    result = clear_run_lock(run, force=True)
    assert result["removed"] is True
    assert not lock.exists()
    audit = json.loads((run / "unlock-audit.jsonl").read_text(encoding="utf-8"))
    assert audit["action"] == "forced-unlock"
    assert audit["observed_state"] == "foreign"


def test_unlock_reports_when_run_is_not_locked(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    assert clear_run_lock(run) == {"removed": False, "reason": "run is not locked"}


def test_lock_owner_rejects_duplicate_json_keys(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    (run / "run.lock").write_text(
        '{"pid":1,"pid":2,"host":"local","process_start":"x"}', encoding="utf-8"
    )
    with pytest.raises(JournalError, match="unknown owner"):
        clear_run_lock(run)


@pytest.mark.parametrize(
    "owner",
    [
        {"schema_version": 1},
        {"schema_version": True, "pid": 1, "host": "x", "process_start": "x", "nonce": "a" * 32},
        {
            "schema_version": 1,
            "pid": True,
            "host": socket.gethostname(),
            "process_start": "x",
            "nonce": "a" * 32,
        },
        {
            "schema_version": 1,
            "pid": 1,
            "host": socket.gethostname(),
            "process_start": "unknown",
            "nonce": "a" * 32,
        },
    ],
)
def test_malformed_lock_owner_is_conservatively_unknown(owner, tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    (run / "run.lock").write_text(canonical_json(owner), encoding="utf-8")
    with pytest.raises(JournalError, match="unknown owner"):
        clear_run_lock(run)


def test_canonical_json_is_byte_stable():
    assert canonical_json({"b": 2, "a": 1}) == '{"a":1,"b":2}'


def test_verify_rejects_corrupt_manifest_shapes_and_artifacts(tmp_path):
    store = ArtifactStore(tmp_path / "store")
    activity = _activity()
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    (sandbox / "result.txt").write_text("content", encoding="utf-8")
    target = store.publish(activity, sandbox)
    manifest_path = target / "manifest.json"
    original = json.loads(manifest_path.read_text(encoding="utf-8"))

    manifest_path.write_text(
        manifest_path.read_text(encoding="utf-8").replace("{", '{"schema_version":1,', 1),
        encoding="utf-8",
    )
    assert "duplicate JSON object key" in store.verify(activity.id)[1]

    cases = [
        ({**original, "activity": {**original["activity"], "id": "b" * 64}}, "does not match"),
        ({**original, "artifacts": {}}, "artifact list is invalid"),
        ({**original, "artifacts": [3]}, "artifact entry is invalid"),
        (
            {**original, "artifacts": [{**original["artifacts"][0], "name": "../escape"}]},
            "unsafe artifact",
        ),
    ]
    for changed, reason in cases:
        manifest_path.write_text(canonical_json(changed), encoding="utf-8")
        valid, actual_reason = store.verify(activity.id)
        assert valid is False
        assert reason in actual_reason

    manifest_path.write_text(canonical_json(original), encoding="utf-8")
    (target / "files" / "result.txt").unlink()
    assert "artifact is missing" in store.verify(activity.id)[1]


@pytest.mark.parametrize("artifact_records", [[], None])
def test_verify_requires_exactly_the_activity_declared_artifacts(tmp_path, artifact_records):
    store = ArtifactStore(tmp_path / "store")
    activity = _activity()
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    (sandbox / "result.txt").write_text("result", encoding="utf-8")
    target = store.publish(activity, sandbox)
    manifest_path = target / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if artifact_records is None:
        extra = target / "files" / "extra.txt"
        extra.write_text("extra", encoding="utf-8")
        manifest["artifacts"].append(
            {"name": "extra.txt", "sha256": sha256_file(extra), "size": extra.stat().st_size}
        )
    else:
        manifest["artifacts"] = artifact_records
    manifest_path.write_text(canonical_json(manifest), encoding="utf-8")

    valid, reason = store.verify(activity.id)
    assert valid is False
    assert "activity declaration" in reason


def test_verify_detects_same_size_hash_change_and_publish_reuses_valid_cache(tmp_path):
    store = ArtifactStore(tmp_path / "store")
    activity = _activity()
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    artifact = sandbox / "result.txt"
    artifact.write_text("first", encoding="utf-8")
    first = store.publish(activity, sandbox)
    (first / "files" / "result.txt").write_text("other", encoding="utf-8")
    assert "hash changed" in store.verify(activity.id)[1]

    artifact.write_text("fresh", encoding="utf-8")
    replaced = store.publish(activity, sandbox)
    assert replaced == first
    assert store.publish(activity, sandbox) == first


def test_materialize_explain_and_run_directory_report_missing_data(tmp_path):
    store = ArtifactStore(tmp_path / "store")
    with pytest.raises(StoreError, match="cannot materialize"):
        store.materialize("a" * 64, tmp_path / "output")
    target = store.cache_path("a" * 64)
    target.mkdir()
    (target / "manifest.json").write_text("[]", encoding="utf-8")
    with pytest.raises(StoreError, match="fields are invalid"):
        store.explain("a" * 64)
    with pytest.raises(StoreError, match="unknown run id"):
        store.run_directory("missing-0001")


def test_non_numeric_run_directory_suffix_is_ignored(tmp_path):
    store = ArtifactStore(tmp_path / "store")
    plan = _plan()
    (store.run_root / f"{plan.id[:12]}-notes").mkdir()
    assert store.new_run_id(plan.id).endswith("-0001")
