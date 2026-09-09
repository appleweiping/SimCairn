"""Trusted-base, author-matching Developer Certificate of Origin checks."""

from __future__ import annotations

import json
import math
import re
import sys
import unicodedata
from pathlib import Path
from typing import Any

_SHA = re.compile(r"^[0-9a-f]{40}$")
_TRAILER = re.compile(r"^(?P<key>[A-Za-z0-9][A-Za-z0-9-]*):[ \t]+(?P<value>\S.*)$")
_SIGNOFF_VALUE = re.compile(r"^(?P<name>[^<>\r\n]+?)[ \t]*<(?P<email>[^<>\s]+)>$")
_MAX_PAYLOAD_BYTES = 8 * 1024 * 1024
_MAX_COMMITS = 250
_MAX_TEXT_CHARACTERS = 262_144


class DCOError(ValueError):
    """Pull-request metadata or a commit sign-off violates the DCO contract."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise DCOError(f"duplicate JSON member {name!r}")
        result[name] = value
    return result


def _constant(token: str) -> Any:
    raise DCOError(f"non-finite JSON number {token!r} is forbidden")


def _integer(token: str) -> int:
    if len(token) > 128:
        raise DCOError("oversized JSON number is forbidden")
    return int(token)


def _float(token: str) -> float:
    if len(token) > 128:
        raise DCOError("oversized JSON number is forbidden")
    value = float(token)
    if not math.isfinite(value):
        raise DCOError("non-finite JSON number is forbidden")
    return value


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > _MAX_TEXT_CHARACTERS:
        raise DCOError(f"GitHub returned an invalid {label}")
    normalized = unicodedata.normalize("NFC", value.strip())
    if any(
        unicodedata.category(character) in {"Cc", "Cf", "Cs", "Zl", "Zp"}
        for character in normalized
    ):
        raise DCOError(f"GitHub returned an unsafe {label}")
    return normalized


def _message(value: Any) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > _MAX_TEXT_CHARACTERS:
        raise DCOError("GitHub returned an invalid commit message")
    normalized = unicodedata.normalize("NFC", value)
    if any(
        (
            unicodedata.category(character) in {"Cf", "Cs", "Zl", "Zp"}
            or (unicodedata.category(character) == "Cc" and character not in {"\n", "\r", "\t"})
        )
        for character in normalized
    ):
        raise DCOError("GitHub returned an unsafe commit message")
    return normalized


def _trailer_signoffs(message: str) -> tuple[tuple[str, str], ...]:
    normalized = message.replace("\r\n", "\n").replace("\r", "\n").rstrip()
    if not normalized:
        raise DCOError("GitHub returned an invalid commit message")
    paragraph = normalized.rsplit("\n\n", maxsplit=1)[-1]
    lines = paragraph.splitlines()
    trailers = [_TRAILER.fullmatch(line) for line in lines]
    if not lines or any(match is None for match in trailers):
        return ()
    signoffs: list[tuple[str, str]] = []
    for match in trailers:
        if match is None:  # defensive after the all-lines trailer check
            continue
        if match["key"].casefold() != "signed-off-by":
            continue
        value = _SIGNOFF_VALUE.fullmatch(match["value"])
        if value is not None:
            signoffs.append(
                (
                    _text(value["name"], "sign-off name"),
                    _text(value["email"], "sign-off email").casefold(),
                )
            )
    return tuple(signoffs)


def verify_commit_pages(pages: Any, *, expected_count: int, expected_head: str) -> int:
    """Validate paginated REST commits, their final head, and every sign-off."""

    if not isinstance(expected_head, str) or _SHA.fullmatch(expected_head) is None:
        raise DCOError("expected pull-request head SHA is invalid")
    if type(expected_count) is not int or not 1 <= expected_count <= _MAX_COMMITS:
        raise DCOError("expected pull-request commit count is invalid")
    if (
        not isinstance(pages, list)
        or not pages
        or any(not isinstance(page, list) for page in pages)
    ):
        raise DCOError("GitHub returned invalid pull-request commit pages")
    if any(len(page) > 100 for page in pages):
        raise DCOError("GitHub returned an oversized commit page")
    commits = [commit for page in pages for commit in page]
    if len(commits) != expected_count:
        raise DCOError(
            f"GitHub returned {len(commits)} commits but the pull request declares {expected_count}"
        )
    if len(commits) > _MAX_COMMITS:
        raise DCOError(f"pull request exceeds the {_MAX_COMMITS}-commit verification limit")

    shas: list[str] = []
    failures: list[str] = []
    for commit in commits:
        if not isinstance(commit, dict):
            raise DCOError("GitHub returned a malformed commit record")
        try:
            details = commit["commit"]
            author = details["author"]
        except (KeyError, TypeError) as error:
            raise DCOError("GitHub returned a malformed commit record") from error
        if not isinstance(details, dict) or not isinstance(author, dict):
            raise DCOError("GitHub returned a malformed commit record")
        sha = _text(commit.get("sha"), "commit SHA")
        if _SHA.fullmatch(sha) is None:
            raise DCOError("GitHub returned an invalid commit SHA")
        shas.append(sha)
        name = _text(author.get("name"), "author name")
        email = _text(author.get("email"), "author email").casefold()
        message = _message(details.get("message"))
        if (name, email) not in _trailer_signoffs(message):
            failures.append(f"{sha[:12]} expected Signed-off-by: {name} <{email}>")
    if len(set(shas)) != len(shas):
        raise DCOError("GitHub returned duplicate commit SHAs")
    if shas[-1] != expected_head:
        raise DCOError("paginated commit list is not bound to the final pull-request head")
    if failures:
        raise DCOError("DCO sign-off check failed:\n" + "\n".join(failures))
    return len(commits)


def verify_commit_file(path: str | Path, *, expected_count: int, expected_head: str) -> int:
    """Strictly load a bounded, non-symlink API response and verify it."""

    source = Path(path)
    try:
        if source.is_symlink() or not source.is_file():
            raise DCOError("pull-request commit metadata is not a regular file")
        with source.open("rb") as stream:
            payload = stream.read(_MAX_PAYLOAD_BYTES + 1)
        if not 0 < len(payload) <= _MAX_PAYLOAD_BYTES:
            raise DCOError("pull-request commit metadata size is invalid")
        pages = json.loads(
            payload,
            object_pairs_hook=_pairs,
            parse_constant=_constant,
            parse_int=_integer,
            parse_float=_float,
        )
        pending: list[tuple[Any, int]] = [(pages, 0)]
        visited = 0
        while pending:
            item, depth = pending.pop()
            visited += 1
            if depth > 64 or visited > 250_000:
                raise DCOError("pull-request metadata exceeds JSON complexity limits")
            if isinstance(item, dict):
                pending.extend((child, depth + 1) for child in item.values())
            elif isinstance(item, list):
                pending.extend((child, depth + 1) for child in item)
    except DCOError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise DCOError(f"cannot read pull-request commit metadata: {error}") from error
    return verify_commit_pages(
        pages,
        expected_count=expected_count,
        expected_head=expected_head,
    )


def main(argv: list[str] | None = None) -> int:
    """Entry point for the trusted ``pull_request_target`` workflow."""

    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 3:
        print(
            "usage: python dco.py PULL_COMMITS.json EXPECTED_COUNT EXPECTED_HEAD",
            file=sys.stderr,
        )
        return 2
    try:
        if re.fullmatch(r"[1-9][0-9]{0,2}", arguments[1]) is None:
            raise DCOError("expected pull-request commit count is invalid")
        count = verify_commit_file(
            arguments[0],
            expected_count=int(arguments[1]),
            expected_head=arguments[2],
        )
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 1
    print(f"verified author-matching DCO sign-offs on {count} commit(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
