"""Sandboxed built-in activities and simulator subprocess execution."""

from __future__ import annotations

import asyncio
import csv
import json
import math
import os
import shutil
import tempfile
import time
from pathlib import Path

from simcairn.adapters import AdapterError, create_adapter
from simcairn.fingerprints import sha256_file, stable_json
from simcairn.manifest import SimulatorConfig
from simcairn.model import Activity, ActivityOutcome
from simcairn.store import ArtifactStore, StoreError
from simcairn.templates import render_template


class ExecutionError(RuntimeError):
    pass


class ActivityExecutor:
    def __init__(self, store: ArtifactStore) -> None:
        self.store = store

    def _materialize_dependencies(self, activity: Activity, sandbox: Path) -> None:
        if activity.kind == "aggregate":
            for dependency in activity.dependencies:
                self.store.materialize(dependency, sandbox / "deps" / dependency)
        else:
            for dependency in activity.dependencies:
                self.store.materialize(dependency, sandbox)

    def _render(self, activity: Activity, sandbox: Path) -> None:
        payload = activity.payload
        for source in activity.inputs:
            if sha256_file(source.path) != source.sha256:
                raise ExecutionError(f"input changed after planning: {source.logical_name}")
        template_path = Path(payload["template_path"])
        template_text = template_path.read_text(encoding="utf-8")
        rendered = render_template(template_text, payload["point"])
        (sandbox / "deck.sp").write_text(rendered, encoding="utf-8", newline="\n")
        (sandbox / "point.json").write_text(stable_json(payload["point"]), encoding="utf-8")
        for item in payload["copies"]:
            relative = Path(item["logical_name"])
            destination = sandbox / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item["path"], destination)

    @staticmethod
    def _environment(extra: dict[str, str]) -> dict[str, str]:
        inherited = {}
        for name in ("PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "HOME"):
            if name in os.environ:
                inherited[name] = os.environ[name]
        inherited.update({str(name): str(value) for name, value in extra.items()})
        inherited["PYTHONIOENCODING"] = "utf-8"
        return inherited

    async def _simulate(self, activity: Activity, sandbox: Path) -> None:
        payload = activity.payload
        config = SimulatorConfig(
            str(payload["adapter"]),
            None if payload.get("executable") is None else str(payload["executable"]),
            tuple(
                sorted((str(name), str(value)) for name, value in payload["environment"].items())
            ),
        )
        adapter = create_adapter(config)
        command = adapter.command(sandbox, payload)
        process = await asyncio.create_subprocess_exec(
            *command,
            cwd=sandbox,
            env=self._environment(dict(config.environment)),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=activity.timeout_seconds
            )
        except asyncio.CancelledError:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=2)
            except TimeoutError:
                process.kill()
                await process.wait()
            raise
        except TimeoutError as error:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=2)
            except TimeoutError:
                process.kill()
                await process.wait()
            raise ExecutionError(
                f"simulator timed out after {activity.timeout_seconds:g} seconds"
            ) from error
        (sandbox / "stdout.log").write_bytes(stdout)
        (sandbox / "stderr.log").write_bytes(stderr)
        if process.returncode != 0:
            summary = stderr.decode("utf-8", errors="replace").strip()
            raise ExecutionError(
                f"simulator exited with status {process.returncode}: {summary[-500:]}"
            )
        try:
            adapter.collect(sandbox, payload)
        except AdapterError as error:
            raise ExecutionError(str(error)) from error

    @staticmethod
    def _extract(activity: Activity, sandbox: Path) -> None:
        payload = activity.payload
        metrics_by_source: dict[str, dict[str, object]] = {}
        extracted: dict[str, float] = {}
        for measure in payload["measures"]:
            source = str(measure["source"])
            if source not in metrics_by_source:
                try:
                    value = json.loads((sandbox / source).read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as error:
                    raise ExecutionError(
                        f"cannot read measurement source {source}: {error}"
                    ) from error
                if not isinstance(value, dict):
                    raise ExecutionError(f"measurement source {source} is not a JSON object")
                metrics_by_source[source] = value
            raw = metrics_by_source[source].get(str(measure["field"]))
            if not isinstance(raw, (int, float)) or isinstance(raw, bool) or not math.isfinite(raw):
                raise ExecutionError(
                    f"measurement {measure['name']!r} is missing or non-finite in {source}"
                )
            extracted[str(measure["name"])] = float(raw)
        result = {
            "point_index": int(payload["point_index"]),
            "point": payload["point"],
            "metrics": extracted,
        }
        (sandbox / "extracted.json").write_text(stable_json(result), encoding="utf-8")

    @staticmethod
    def _aggregate(activity: Activity, sandbox: Path) -> None:
        rows: list[tuple[int, dict[str, object], dict[str, object]]] = []
        for dependency in activity.dependencies:
            path = sandbox / "deps" / dependency / "extracted.json"
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as error:
                raise ExecutionError(f"cannot aggregate {dependency[:12]}: {error}") from error
            if not isinstance(value, dict):
                raise ExecutionError(f"cannot aggregate {dependency[:12]}: result is not an object")
            point_index = value.get("point_index")
            point = value.get("point")
            metrics = value.get("metrics")
            if not isinstance(point_index, int) or isinstance(point_index, bool):
                raise ExecutionError(
                    f"cannot aggregate {dependency[:12]}: point_index is not an integer"
                )
            if not isinstance(point, dict) or not all(isinstance(name, str) for name in point):
                raise ExecutionError(f"cannot aggregate {dependency[:12]}: point is not an object")
            if not isinstance(metrics, dict) or not all(isinstance(name, str) for name in metrics):
                raise ExecutionError(
                    f"cannot aggregate {dependency[:12]}: metrics is not an object"
                )
            rows.append((point_index, point, metrics))
        rows.sort(key=lambda item: item[0])
        flattened: list[dict[str, object]] = []
        for _, point, metrics in rows:
            flattened.append({**point, **metrics})
        (sandbox / "results.json").write_text(stable_json(flattened), encoding="utf-8")
        fieldnames: list[str] = []
        for row in flattened:
            for name in row:
                if name not in fieldnames:
                    fieldnames.append(name)
        with (sandbox / "results.csv").open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=fieldnames, lineterminator="\n")
            writer.writeheader()
            writer.writerows(flattened)

    async def execute(self, activity: Activity) -> ActivityOutcome:
        started = time.monotonic()
        sandbox = Path(tempfile.mkdtemp(prefix=f"{activity.id[:12]}-", dir=self.store.work_root))
        try:
            self._materialize_dependencies(activity, sandbox)
            if activity.kind == "render":
                self._render(activity, sandbox)
            elif activity.kind == "simulate":
                await self._simulate(activity, sandbox)
            elif activity.kind == "extract":
                self._extract(activity, sandbox)
            elif activity.kind == "aggregate":
                self._aggregate(activity, sandbox)
            else:
                raise ExecutionError(f"unknown activity kind {activity.kind!r}")
            self.store.publish(activity, sandbox)
            return ActivityOutcome(activity.id, "succeeded", time.monotonic() - started)
        except (OSError, ValueError, StoreError, ExecutionError) as error:
            return ActivityOutcome(activity.id, "failed", time.monotonic() - started, str(error))
        finally:
            shutil.rmtree(sandbox, ignore_errors=True)
