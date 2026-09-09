from __future__ import annotations

import re
import tomllib
from pathlib import Path


def test_transitional_pr_checkout_dco_is_retired() -> None:
    ci = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "\n  dco:" not in ci
    assert "git rev-list" not in ci


def test_actions_are_pinned_to_full_commits() -> None:
    workflows = tuple(Path(".github/workflows").glob("*.yml"))
    assert workflows
    for workflow in workflows:
        for line in workflow.read_text(encoding="utf-8").splitlines():
            if line.strip().startswith("uses:"):
                reference = line.partition("uses:")[2].strip()
                assert re.fullmatch(r"[^\s@]+@[0-9a-f]{40}(?:\s+#.*)?", reference), reference


def test_release_requires_main_push_ci_for_the_exact_signed_commit() -> None:
    release = Path(".github/workflows/release.yml").read_text(encoding="utf-8")
    assert "git verify-tag" in release
    assert 'git merge-base --is-ancestor "$GITHUB_SHA" origin/main' in release
    assert '.event == "push"' in release or '.event == \\"push\\"' in release
    assert '.head_branch == "main"' in release or '.head_branch == \\"main\\"' in release
    assert '.head_sha == \\"$GITHUB_SHA\\"' in release
    assert release.index("git verify-tag") < release.index("Run release quality gate")
    assert release.index("git show origin/main:.github/allowed_signers") < release.index(
        "git verify-tag"
    )
    assert "path: .release-smoke" in release
    assert "bind-installed-wheel" in release
    assert release.count("verify-release") == 3


def test_source_archive_includes_the_files_needed_by_its_tests() -> None:
    config = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    profile = config["tool"]["hatch"]["build"]["targets"]["sdist"]
    assert {"/.github/workflows", "/.github/allowed_signers", "/uv.lock"} <= set(profile["include"])
    assert not {"/.github", "/.github/workflows", "/uv.lock"} & set(profile.get("exclude", []))
    release = Path(".github/workflows/release.yml").read_text(encoding="utf-8")
    for name in (
        ".github/workflows/ci.yml",
        ".github/workflows/dco.yml",
        ".github/workflows/release.yml",
        ".github/allowed_signers",
        "src/simcairn/adapters.py",
        "src/simcairn/characterization.py",
        "src/simcairn/xyce.py",
        "tests/fixtures/fake_xyce.py",
        "tests/test_characterization.py",
        "tests/test_xyce.py",
        "tests/test_xyce_windows_launch.py",
        "uv.lock",
    ):
        assert f'"{name}",' in release
    assert "Re-test the audited source distribution with frozen dependencies" in release
    assert 'mktemp -d "$RUNNER_TEMP/sdist-test.XXXXXX"' in release
    assert "uv run --frozen python - <<'PY'" not in release
    assert release.count("uv run --frozen python -I - <<'PY'") == 2
    assert 'XyceAdapter("not-invoked", "tran").collect' in release
    assert "accepted a numeric default without success evidence" in release
