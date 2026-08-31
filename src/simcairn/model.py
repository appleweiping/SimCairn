"""Immutable values used by planning, execution, and reporting."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def strict_json_loads(source: str | bytes) -> Any:
    """Decode persisted JSON while rejecting ambiguous or non-standard values."""

    def object_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON object key {key!r}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON number {value!r}")

    return json.loads(source, object_pairs_hook=object_hook, parse_constant=reject_constant)


def _exact_keys(data: dict[str, Any], expected: set[str], context: str) -> None:
    if set(data) != expected:
        raise ValueError(f"{context} fields are invalid")


def _text(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{context} must be a non-empty string")
    return value


def _digest(value: Any, context: str) -> str:
    text = _text(value, context)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise ValueError(f"{context} must be a lowercase SHA-256 digest")
    return text


def _positive_integer(value: Any, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{context} must be a positive integer")
    return value


def _json_value(value: Any, context: str) -> None:
    if value is None or isinstance(value, bool | str | int):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{context} contains a non-finite number")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _json_value(item, f"{context}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{context} object keys must be strings")
            _json_value(item, f"{context}.{key}")
        return
    raise ValueError(f"{context} contains a non-JSON value")


def _string_list(value: Any, context: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{context} must be an array of non-empty strings")
    if len({item.casefold() for item in value}) != len(value):
        raise ValueError(f"{context} must not contain case-insensitive duplicates")
    return value


def _safe_logical_name(value: str, context: str) -> str:
    path = Path(value)
    if value == "" or "\\" in value or path.anchor or ".." in path.parts or value.startswith("/"):
        raise ValueError(f"{context} must be a safe relative logical path")
    return value


def _string_mapping(value: Any, context: str) -> dict[str, str]:
    if not isinstance(value, dict) or not all(
        isinstance(key, str) and key and isinstance(item, str) for key, item in value.items()
    ):
        raise ValueError(f"{context} must be an object of string pairs")
    return value


def _measure_list(value: Any, context: str) -> list[dict[str, str]]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{context} must be a non-empty array")
    result: list[dict[str, str]] = []
    names: set[str] = set()
    for item in value:
        if not isinstance(item, dict):
            raise ValueError(f"{context} entries must be objects")
        _exact_keys(item, {"name", "source", "field"}, f"{context} entry")
        name = _text(item["name"], f"{context} name")
        source = _safe_logical_name(_text(item["source"], f"{context} source"), context)
        field = _text(item["field"], f"{context} field")
        if _IDENTIFIER.fullmatch(name) is None or _IDENTIFIER.fullmatch(field) is None:
            raise ValueError(f"{context} names and fields must be identifiers")
        if name.casefold() in names:
            raise ValueError(f"{context} measure names must be unique")
        names.add(name.casefold())
        result.append({"name": name, "source": source, "field": field})
    return result


@dataclass(frozen=True, slots=True)
class InputDigest:
    path: str
    logical_name: str
    sha256: str

    def as_dict(self) -> dict[str, str]:
        return {"path": self.path, "logical_name": self.logical_name, "sha256": self.sha256}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InputDigest:
        if not isinstance(data, dict):
            raise ValueError("activity input must be an object")
        _exact_keys(data, {"path", "logical_name", "sha256"}, "activity input")
        return cls(
            _text(data["path"], "activity input path"),
            _safe_logical_name(
                _text(data["logical_name"], "activity input logical_name"),
                "activity input logical_name",
            ),
            _digest(data["sha256"], "activity input sha256"),
        )


@dataclass(frozen=True, slots=True)
class SweepPoint:
    index: int
    values: tuple[tuple[str, str], ...]

    def as_dict(self) -> dict[str, str]:
        return dict(self.values)

    @property
    def label(self) -> str:
        return "__".join(f"{name}={value}" for name, value in self.values) or "default"


def _validate_activity_contract(
    kind: str,
    point: SweepPoint | None,
    inputs: tuple[InputDigest, ...],
    payload: dict[str, Any],
    identity: dict[str, Any],
) -> None:
    if kind == "render":
        if point is None:
            raise ValueError("render activity requires a sweep point")
        _exact_keys(payload, {"template_path", "point", "copies"}, "render payload")
        _exact_keys(identity, {"renderer"}, "render identity")
        _text(identity["renderer"], "render identity renderer")
        template_path = _text(payload["template_path"], "render template_path")
        payload_point = _string_mapping(payload["point"], "render point")
        if payload_point != dict(point.values):
            raise ValueError("render payload point does not match activity point")
        templates = [item for item in inputs if item.logical_name == "__template__"]
        copies_expected = [item for item in inputs if item.logical_name != "__template__"]
        if len(templates) != 1 or templates[0].path != template_path:
            raise ValueError("render template_path does not match its input digest")
        copies = payload["copies"]
        if not isinstance(copies, list):
            raise ValueError("render copies must be an array")
        normalized_copies: list[tuple[str, str]] = []
        for item in copies:
            if not isinstance(item, dict):
                raise ValueError("render copy entries must be objects")
            _exact_keys(item, {"path", "logical_name"}, "render copy")
            normalized_copies.append(
                (
                    _text(item["path"], "render copy path"),
                    _safe_logical_name(
                        _text(item["logical_name"], "render copy logical_name"),
                        "render copy logical_name",
                    ),
                )
            )
        if normalized_copies != [(item.path, item.logical_name) for item in copies_expected]:
            raise ValueError("render copies do not match activity input digests")
        return

    if kind == "simulate":
        if point is None or inputs:
            raise ValueError("simulate activity requires a point and no direct inputs")
        _exact_keys(
            payload,
            {"adapter", "executable", "environment", "measure_fields"},
            "simulate payload",
        )
        _exact_keys(
            identity,
            {"adapter_identity", "adapter", "executable", "environment", "measure_fields"},
            "simulate identity",
        )
        adapter = _text(payload["adapter"], "simulate adapter")
        executable = payload["executable"]
        if executable is not None and (not isinstance(executable, str) or not executable):
            raise ValueError("simulate executable must be a non-empty string or null")
        environment = _string_mapping(payload["environment"], "simulate environment")
        fields = _string_list(payload["measure_fields"], "simulate measure_fields")
        if any(_IDENTIFIER.fullmatch(field) is None for field in fields):
            raise ValueError("simulate measure_fields must be identifiers")
        if (
            identity.get("adapter") != adapter
            or identity.get("executable") != executable
            or identity.get("environment") != environment
            or identity.get("measure_fields") != fields
        ):
            raise ValueError("simulate payload does not match its identity")
        _text(identity["adapter_identity"], "simulate adapter_identity")
        return

    if kind == "extract":
        if point is None or inputs:
            raise ValueError("extract activity requires a point and no direct inputs")
        _exact_keys(payload, {"measures", "point", "point_index"}, "extract payload")
        _exact_keys(identity, {"extractor", "measures"}, "extract identity")
        _text(identity["extractor"], "extract identity extractor")
        measures = _measure_list(payload["measures"], "extract measures")
        identity_measures = _measure_list(identity["measures"], "extract identity measures")
        if measures != identity_measures:
            raise ValueError("extract measures do not match activity identity")
        if _string_mapping(payload["point"], "extract point") != dict(point.values):
            raise ValueError("extract payload point does not match activity point")
        point_index = payload["point_index"]
        if isinstance(point_index, bool) or not isinstance(point_index, int):
            raise ValueError("extract point_index must be an integer")
        if point_index != point.index:
            raise ValueError("extract point_index does not match activity point")
        return

    if kind == "aggregate":
        if point is not None or inputs:
            raise ValueError("aggregate activity must not have a point or direct inputs")
        _exact_keys(payload, {"measures"}, "aggregate payload")
        _exact_keys(identity, {"aggregator", "measures"}, "aggregate identity")
        _text(identity["aggregator"], "aggregate identity aggregator")
        names = _string_list(payload["measures"], "aggregate measures")
        measures = _measure_list(identity["measures"], "aggregate identity measures")
        if names != [item["name"] for item in measures]:
            raise ValueError("aggregate measures do not match activity identity")
        return

    raise ValueError(f"unsupported saved activity kind {kind!r}")


@dataclass(frozen=True, slots=True)
class Activity:
    id: str
    kind: str
    point: SweepPoint | None
    dependencies: tuple[str, ...]
    inputs: tuple[InputDigest, ...]
    expected_artifacts: tuple[str, ...]
    resources: tuple[tuple[str, int], ...]
    timeout_seconds: float
    payload_json: str
    identity_json: str = "{}"

    @property
    def payload(self) -> dict[str, Any]:
        value = strict_json_loads(self.payload_json)
        if not isinstance(value, dict):
            raise ValueError("activity payload must be a JSON object")
        return value

    @property
    def identity(self) -> dict[str, Any]:
        value = strict_json_loads(self.identity_json)
        if not isinstance(value, dict):
            raise ValueError("activity identity must be a JSON object")
        return value

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "point": None
            if self.point is None
            else {"index": self.point.index, "values": list(self.point.values)},
            "dependencies": list(self.dependencies),
            "inputs": [item.as_dict() for item in self.inputs],
            "expected_artifacts": list(self.expected_artifacts),
            "resources": dict(self.resources),
            "timeout_seconds": self.timeout_seconds,
            "payload": self.payload,
            "identity": self.identity,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Activity:
        if not isinstance(data, dict):
            raise ValueError("activity must be an object")
        _exact_keys(
            data,
            {
                "id",
                "kind",
                "point",
                "dependencies",
                "inputs",
                "expected_artifacts",
                "resources",
                "timeout_seconds",
                "payload",
                "identity",
            },
            "activity",
        )
        raw_point = data.get("point")
        point = None
        if raw_point is not None:
            if not isinstance(raw_point, dict):
                raise ValueError("activity point must be an object or null")
            _exact_keys(raw_point, {"index", "values"}, "activity point")
            raw_index = raw_point["index"]
            if isinstance(raw_index, bool) or not isinstance(raw_index, int) or raw_index < 0:
                raise ValueError("activity point index must be a non-negative integer")
            raw_values = raw_point["values"]
            if not isinstance(raw_values, list):
                raise ValueError("activity point values must be an array")
            values: list[tuple[str, str]] = []
            names: set[str] = set()
            for item in raw_values:
                if (
                    not isinstance(item, list | tuple)
                    or len(item) != 2
                    or not all(isinstance(value, str) for value in item)
                ):
                    raise ValueError("activity point values must contain string pairs")
                name, value = item
                if not name or name.casefold() in names:
                    raise ValueError("activity point parameter names must be non-empty and unique")
                names.add(name.casefold())
                values.append((name, value))
            point = SweepPoint(
                raw_index,
                tuple(values),
            )
        dependencies = data["dependencies"]
        inputs = data["inputs"]
        artifacts = data["expected_artifacts"]
        resources = data["resources"]
        if not isinstance(dependencies, list) or not all(
            isinstance(item, str) for item in dependencies
        ):
            raise ValueError("activity dependencies must be an array of strings")
        if len(dependencies) != len(set(dependencies)):
            raise ValueError("activity dependencies must be unique")
        if not isinstance(inputs, list):
            raise ValueError("activity inputs must be an array")
        parsed_inputs = tuple(InputDigest.from_dict(item) for item in inputs)
        logical_names = [item.logical_name.casefold() for item in parsed_inputs]
        if len(logical_names) != len(set(logical_names)):
            raise ValueError("activity input logical names must be unique")
        if not isinstance(artifacts, list) or not all(
            isinstance(item, str) and item for item in artifacts
        ):
            raise ValueError("activity expected_artifacts must be non-empty strings")
        if len({item.casefold() for item in artifacts}) != len(artifacts):
            raise ValueError("activity expected_artifacts must be unique")
        for artifact in artifacts:
            path = Path(artifact)
            if path.anchor or ".." in path.parts:
                raise ValueError("activity expected artifact path is unsafe")
        if not isinstance(resources, dict):
            raise ValueError("activity resources must be an object")
        resource_items: list[tuple[str, int]] = []
        for name, value in resources.items():
            resource_items.append(
                (_text(name, "activity resource name"), _positive_integer(value, "resource value"))
            )
        timeout = data["timeout_seconds"]
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, int | float)
            or not math.isfinite(timeout)
            or not 0 < timeout <= 31_536_000
        ):
            raise ValueError("activity timeout_seconds must be finite and in (0, 31536000]")
        payload = data["payload"]
        if not isinstance(payload, dict):
            raise ValueError("activity payload must be an object")
        _json_value(payload, "activity payload")
        identity = data["identity"]
        if not isinstance(identity, dict):
            raise ValueError("activity identity must be an object")
        _json_value(identity, "activity identity")
        kind = _text(data["kind"], "activity kind")
        _validate_activity_contract(kind, point, parsed_inputs, payload, identity)
        activity_id = _digest(data["id"], "activity id")
        expected_id = hashlib.sha256(
            canonical_json(
                {
                    "activity_schema": 1,
                    "kind": kind,
                    "point": None if point is None else list(point.values),
                    "dependencies": dependencies,
                    "inputs": [
                        {
                            "logical_name": item.logical_name,
                            "sha256": item.sha256,
                        }
                        for item in parsed_inputs
                    ],
                    "expected_artifacts": artifacts,
                    "identity": identity,
                }
            ).encode("utf-8")
        ).hexdigest()
        if activity_id != expected_id:
            raise ValueError("activity id does not match its identity")
        return cls(
            activity_id,
            kind,
            point,
            tuple(dependencies),
            parsed_inputs,
            tuple(artifacts),
            tuple(sorted(resource_items)),
            float(timeout),
            canonical_json(payload),
            canonical_json(identity),
        )


@dataclass(frozen=True, slots=True)
class Plan:
    id: str
    manifest_path: str
    activities: tuple[Activity, ...]
    jobs: int
    resource_limits: tuple[tuple[str, int], ...]
    fail_fast: bool

    def activity_map(self) -> dict[str, Activity]:
        return {activity.id: activity for activity in self.activities}

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "id": self.id,
            "manifest_path": self.manifest_path,
            "jobs": self.jobs,
            "resource_limits": dict(self.resource_limits),
            "fail_fast": self.fail_fast,
            "activities": [activity.as_dict() for activity in self.activities],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Plan:
        if not isinstance(data, dict):
            raise ValueError("saved plan must be an object")
        _exact_keys(
            data,
            {
                "schema_version",
                "id",
                "manifest_path",
                "jobs",
                "resource_limits",
                "fail_fast",
                "activities",
            },
            "saved plan",
        )
        schema_version = data.get("schema_version")
        if (
            isinstance(schema_version, bool)
            or not isinstance(schema_version, int)
            or schema_version != 1
        ):
            raise ValueError("unsupported saved-plan schema version")
        raw_activities = data["activities"]
        if not isinstance(raw_activities, list) or not raw_activities:
            raise ValueError("saved plan activities must be a non-empty array")
        activities = tuple(Activity.from_dict(item) for item in raw_activities)
        identifiers = [activity.id for activity in activities]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("saved plan activity ids must be unique")
        seen: set[str] = set()
        point_values: dict[int, tuple[tuple[str, str], ...]] = {}
        for activity in activities:
            if any(dependency not in seen for dependency in activity.dependencies):
                raise ValueError("saved plan dependencies must refer to earlier activities")
            seen.add(activity.id)
            if activity.point is not None:
                previous = point_values.setdefault(activity.point.index, activity.point.values)
                if previous != activity.point.values:
                    raise ValueError("saved plan point identity is inconsistent")
        raw_limits = data["resource_limits"]
        if not isinstance(raw_limits, dict):
            raise ValueError("saved plan resource_limits must be an object")
        limits = tuple(
            sorted(
                (
                    _text(name, "resource limit name"),
                    _positive_integer(value, "resource limit"),
                )
                for name, value in raw_limits.items()
            )
        )
        fail_fast = data["fail_fast"]
        if not isinstance(fail_fast, bool):
            raise ValueError("saved plan fail_fast must be boolean")
        jobs = _positive_integer(data["jobs"], "saved plan jobs")
        plan_id = _digest(data["id"], "saved plan id")
        expected_id = hashlib.sha256(
            canonical_json(
                {
                    "plan_schema": 1,
                    "activities": identifiers,
                    "jobs": jobs,
                    "resources": dict(limits),
                    "fail_fast": fail_fast,
                }
            ).encode("utf-8")
        ).hexdigest()
        if plan_id != expected_id:
            raise ValueError("saved plan id does not match its contents")
        return cls(
            plan_id,
            _text(data["manifest_path"], "saved plan manifest_path"),
            activities,
            jobs,
            limits,
            fail_fast,
        )


@dataclass(frozen=True, slots=True)
class ActivityOutcome:
    activity_id: str
    status: str
    duration_seconds: float
    message: str = ""


@dataclass(frozen=True, slots=True)
class RunReport:
    run_id: str
    plan_id: str
    status: str
    outcomes: tuple[ActivityOutcome, ...]
    run_directory: Path

    @property
    def counts(self) -> dict[str, int]:
        result: dict[str, int] = {}
        for outcome in self.outcomes:
            result[outcome.status] = result.get(outcome.status, 0) + 1
        return dict(sorted(result.items()))

    def as_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "plan_id": self.plan_id,
            "status": self.status,
            "counts": self.counts,
            "run_directory": str(self.run_directory),
            "outcomes": [
                {
                    "activity_id": item.activity_id,
                    "status": item.status,
                    "duration_seconds": item.duration_seconds,
                    "message": item.message,
                }
                for item in self.outcomes
            ],
        }


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
