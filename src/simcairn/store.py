"""Content-addressed artifacts and per-run metadata."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from simcairn.fingerprints import sha256_file, stable_json
from simcairn.model import Activity, Plan, strict_json_loads


class StoreError(RuntimeError):
    pass


def _safe_artifact(name: str) -> Path:
    path = Path(name)
    if path.anchor or not path.parts or ".." in path.parts:
        raise StoreError(f"unsafe artifact name {name!r}")
    return path


class ArtifactStore:
    def __init__(self, root: str | Path = ".simcairn") -> None:
        self.root = Path(root).resolve()
        self.cache_root = self.root / "cache"
        self.run_root = self.root / "runs"
        self.work_root = self.root / "work"
        for directory in (self.cache_root, self.run_root, self.work_root):
            directory.mkdir(parents=True, exist_ok=True)

    def cache_path(self, activity_id: str) -> Path:
        if len(activity_id) != 64 or any(
            character not in "0123456789abcdef" for character in activity_id
        ):
            raise StoreError(f"invalid activity id {activity_id!r}")
        return self.cache_root / activity_id

    def verify(self, activity_id: str) -> tuple[bool, str]:
        target = self.cache_path(activity_id)
        manifest_path = target / "manifest.json"
        try:
            data = strict_json_loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, ValueError) as error:
            return False, f"cache manifest unavailable: {error}"
        if not isinstance(data, dict) or set(data) != {"schema_version", "activity", "artifacts"}:
            return False, "cache manifest fields are invalid"
        version = data.get("schema_version")
        if isinstance(version, bool) or not isinstance(version, int) or version != 1:
            return False, "cache manifest schema version is invalid"
        try:
            activity = Activity.from_dict(data["activity"])
        except (KeyError, TypeError, ValueError) as error:
            return False, f"cache manifest activity is invalid: {error}"
        if activity.id != activity_id:
            return False, "cache manifest activity id does not match"
        artifacts = data.get("artifacts")
        if not isinstance(artifacts, list):
            return False, "cache artifact list is invalid"
        names: set[str] = set()
        for item in artifacts:
            if not isinstance(item, dict) or set(item) != {"name", "sha256", "size"}:
                return False, "cache artifact entry is invalid"
            name = item.get("name")
            digest = item.get("sha256")
            size = item.get("size")
            if (
                not isinstance(name, str)
                or not isinstance(digest, str)
                or len(digest) != 64
                or any(character not in "0123456789abcdef" for character in digest)
                or isinstance(size, bool)
                or not isinstance(size, int)
                or size < 0
                or name.casefold() in names
            ):
                return False, "cache artifact entry is invalid"
            names.add(name.casefold())
            try:
                relative = _safe_artifact(name)
            except StoreError as error:
                return False, str(error)
            path = target / "files" / relative
            if not path.is_file():
                return False, f"artifact is missing: {item['name']}"
            if path.stat().st_size != item.get("size"):
                return False, f"artifact size changed: {item['name']}"
            if sha256_file(path) != item.get("sha256"):
                return False, f"artifact hash changed: {item['name']}"
        expected_names = {name.casefold() for name in activity.expected_artifacts}
        if names != expected_names:
            return False, "cache artifacts do not match the activity declaration"
        return True, "verified"

    def publish(self, activity: Activity, sandbox: Path) -> Path:
        records: list[dict[str, Any]] = []
        for name in activity.expected_artifacts:
            relative = _safe_artifact(name)
            source = (sandbox / relative).resolve()
            if source != sandbox.resolve() and not source.is_relative_to(sandbox.resolve()):
                raise StoreError(f"artifact escapes sandbox: {name}")
            if not source.is_file():
                raise StoreError(f"activity {activity.id[:12]} did not create artifact {name}")
            records.append(
                {"name": name, "sha256": sha256_file(source), "size": source.stat().st_size}
            )

        temporary = Path(tempfile.mkdtemp(prefix=".publish-", dir=self.cache_root))
        try:
            files_root = temporary / "files"
            for record in records:
                relative = _safe_artifact(record["name"])
                destination = files_root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(sandbox / relative, destination)
            (temporary / "manifest.json").write_text(
                stable_json(
                    {
                        "schema_version": 1,
                        "activity": activity.as_dict(),
                        "artifacts": records,
                    }
                ),
                encoding="utf-8",
            )
            target = self.cache_path(activity.id)
            if target.exists():
                valid, _ = self.verify(activity.id)
                if valid:
                    return target
                shutil.rmtree(target)
            try:
                os.replace(temporary, target)
            except OSError:
                valid, reason = self.verify(activity.id)
                if not valid:
                    raise StoreError(f"cannot publish cache entry: {reason}") from None
            return target
        finally:
            if temporary.exists():
                shutil.rmtree(temporary, ignore_errors=True)

    def materialize(self, activity_id: str, destination: Path) -> tuple[Path, ...]:
        valid, reason = self.verify(activity_id)
        if not valid:
            raise StoreError(f"cannot materialize {activity_id[:12]}: {reason}")
        manifest = self.explain(activity_id)
        result: list[Path] = []
        for item in manifest["artifacts"]:
            relative = _safe_artifact(item["name"])
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(self.cache_path(activity_id) / "files" / relative, target)
            result.append(target)
        return tuple(result)

    def explain(self, activity_id: str) -> dict[str, Any]:
        valid, reason = self.verify(activity_id)
        if not valid:
            raise StoreError(f"cannot read cache entry {activity_id}: {reason}")
        path = self.cache_path(activity_id) / "manifest.json"
        try:
            data = strict_json_loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, ValueError) as error:
            raise StoreError(f"cannot read cache entry {activity_id}: {error}") from error
        if not isinstance(data, dict):
            raise StoreError("cache manifest root is not an object")
        return data

    def new_run_id(self, plan_id: str) -> str:
        prefix = plan_id[:12]
        used: set[int] = set()
        for path in self.run_root.glob(f"{prefix}-*"):
            try:
                used.add(int(path.name.rsplit("-", 1)[1]))
            except ValueError:
                continue
        sequence = 1
        while sequence in used:
            sequence += 1
        return f"{prefix}-{sequence:04d}"

    def create_run(self, plan: Plan) -> tuple[str, Path]:
        run_id = self.new_run_id(plan.id)
        directory = self.run_root / run_id
        directory.mkdir(parents=False, exist_ok=False)
        (directory / "plan.json").write_text(stable_json(plan.as_dict()), encoding="utf-8")
        return run_id, directory

    def load_plan(self, run_id: str) -> Plan:
        if Path(run_id).name != run_id:
            raise StoreError(f"invalid run id {run_id!r}")
        path = self.run_root / run_id / "plan.json"
        try:
            data = strict_json_loads(path.read_text(encoding="utf-8"))
            return Plan.from_dict(data)
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
            raise StoreError(f"cannot load run {run_id}: {error}") from error

    def run_directory(self, run_id: str) -> Path:
        if Path(run_id).name != run_id:
            raise StoreError(f"invalid run id {run_id!r}")
        directory = self.run_root / run_id
        if not directory.is_dir():
            raise StoreError(f"unknown run id {run_id!r}")
        return directory
