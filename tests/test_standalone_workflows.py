from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize(
    "workflow,script,arguments,expected",
    [("dco.yml", "dco.py", [], 2), ("release.yml", "release_artifacts.py", ["--help"], 0)],
)
def test_actual_standalone_workflow_command_is_import_isolated(
    workflow: str, script: str, arguments: list[str], expected: int, tmp_path: Path
) -> None:
    root = Path(__file__).resolve().parents[1]
    body = (root / ".github/workflows" / workflow).read_text(encoding="utf-8")
    relative = f"src/simcairn/{script}"
    # Exercise the actual launcher mode, not an in-process import of the helper.
    isolated = f"python -I -S {relative}" in body
    command = [
        sys.executable,
        *(["-I", "-S"] if isolated else []),
        str(root / relative),
        *arguments,
    ]
    result = subprocess.run(command, cwd=tmp_path, capture_output=True, text=True, timeout=20)
    assert result.returncode == expected, result.stderr
    assert "usage:" in result.stdout + result.stderr
    assert isolated, "standalone trusted helpers must not import sibling or user-site modules"
