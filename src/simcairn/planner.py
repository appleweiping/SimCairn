"""Compile a validated manifest into a content-addressed activity DAG."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from simcairn.adapters import create_adapter
from simcairn.fingerprints import fingerprint, sha256_file
from simcairn.manifest import Manifest, ManifestError
from simcairn.model import Activity, InputDigest, Plan, SweepPoint, canonical_json
from simcairn.sweeps import expand_sweep


def _logical_input(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _activity(
    *,
    kind: str,
    point: SweepPoint | None,
    dependencies: tuple[str, ...],
    inputs: tuple[InputDigest, ...],
    expected_artifacts: tuple[str, ...],
    resources: tuple[tuple[str, int], ...],
    timeout_seconds: float,
    payload: dict[str, Any],
    identity_payload: dict[str, Any],
) -> Activity:
    identifier = fingerprint(
        {
            "activity_schema": 1,
            "kind": kind,
            "point": None if point is None else list(point.values),
            "dependencies": list(dependencies),
            "inputs": [
                {"logical_name": item.logical_name, "sha256": item.sha256} for item in inputs
            ],
            "expected_artifacts": list(expected_artifacts),
            "identity": identity_payload,
        }
    )
    return Activity(
        identifier,
        kind,
        point,
        dependencies,
        inputs,
        expected_artifacts,
        resources,
        timeout_seconds,
        canonical_json(payload),
        canonical_json(identity_payload),
    )


def _input_digests(manifest: Manifest) -> tuple[InputDigest, ...]:
    result = [
        InputDigest(
            str(manifest.template.deck),
            "__template__",
            sha256_file(manifest.template.deck),
        )
    ]
    reserved = {"deck.sp", "point.json", "stdout.log", "stderr.log", "metrics.json"}
    for path in manifest.template.inputs:
        logical = _logical_input(manifest.root, path)
        if logical.casefold() in reserved or logical.startswith("../"):
            raise ManifestError(f"template input uses reserved artifact name {logical!r}")
        result.append(InputDigest(str(path), logical, sha256_file(path)))
    return tuple(result)


def compile_plan(manifest: Manifest) -> Plan:
    points = expand_sweep(manifest.sweep)
    adapter = create_adapter(manifest.simulator)
    adapter_identity = adapter.identity()
    source_inputs = _input_digests(manifest)
    activities: list[Activity] = []
    extract_ids: list[str] = []
    measure_payload = [
        {"name": item.name, "source": item.source, "field": item.field}
        for item in manifest.measures
    ]
    copied_inputs = tuple(
        item.logical_name for item in source_inputs if item.logical_name != "__template__"
    )

    for point in points:
        render_artifacts = ("deck.sp", "point.json", *copied_inputs)
        render = _activity(
            kind="render",
            point=point,
            dependencies=(),
            inputs=source_inputs,
            expected_artifacts=render_artifacts,
            resources=(),
            timeout_seconds=manifest.run.timeout_seconds,
            payload={
                "template_path": str(manifest.template.deck),
                "point": point.as_dict(),
                "copies": [
                    {"path": item.path, "logical_name": item.logical_name}
                    for item in source_inputs
                    if item.logical_name != "__template__"
                ],
            },
            identity_payload={"renderer": "strict-placeholder/1"},
        )
        activities.append(render)

        simulate = _activity(
            kind="simulate",
            point=point,
            dependencies=(render.id,),
            inputs=(),
            expected_artifacts=adapter.expected_artifacts(),
            resources=(("simulator", 1),),
            timeout_seconds=manifest.run.timeout_seconds,
            payload={
                "adapter": manifest.simulator.adapter,
                "executable": manifest.simulator.executable,
                "environment": dict(manifest.simulator.environment),
                "measure_fields": [item.field for item in manifest.measures],
            },
            identity_payload={
                "adapter_identity": adapter_identity,
                "adapter": manifest.simulator.adapter,
                "executable": manifest.simulator.executable,
                "environment": dict(manifest.simulator.environment),
                "measure_fields": [item.field for item in manifest.measures],
            },
        )
        activities.append(simulate)

        extract = _activity(
            kind="extract",
            point=point,
            dependencies=(simulate.id,),
            inputs=(),
            expected_artifacts=("extracted.json",),
            resources=(),
            timeout_seconds=manifest.run.timeout_seconds,
            payload={
                "measures": measure_payload,
                "point": point.as_dict(),
                "point_index": point.index,
            },
            identity_payload={"extractor": "json-field/1", "measures": measure_payload},
        )
        activities.append(extract)
        extract_ids.append(extract.id)

    aggregate = _activity(
        kind="aggregate",
        point=None,
        dependencies=tuple(extract_ids),
        inputs=(),
        expected_artifacts=("results.json", "results.csv"),
        resources=(),
        timeout_seconds=manifest.run.timeout_seconds,
        payload={"measures": [item.name for item in manifest.measures]},
        identity_payload={"aggregator": "table/1", "measures": measure_payload},
    )
    activities.append(aggregate)

    resource_limits = dict(manifest.run.resources)
    resource_limits.setdefault("simulator", manifest.run.jobs)
    plan_id = fingerprint(
        {
            "plan_schema": 1,
            "activities": [activity.id for activity in activities],
            "jobs": manifest.run.jobs,
            "resources": resource_limits,
            "fail_fast": manifest.run.fail_fast,
        }
    )
    return Plan(
        plan_id,
        str(manifest.path),
        tuple(activities),
        manifest.run.jobs,
        tuple(sorted(resource_limits.items())),
        manifest.run.fail_fast,
    )
