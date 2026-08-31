"""Strict, non-executable deck parameter substitution."""

from __future__ import annotations

import re
from collections.abc import Mapping


class TemplateError(ValueError):
    pass


_PLACEHOLDER = re.compile(r"@\{([A-Za-z_][A-Za-z0-9_]*)\}")
_SAFE_VALUE = re.compile(r"[A-Za-z0-9_.+\-]+\Z")


def render_template(text: str, values: Mapping[str, str]) -> str:
    """Replace declared placeholders without expressions or recursive expansion."""

    normalized = {name.casefold(): value for name, value in values.items()}
    used: set[str] = set()

    def replace(match: re.Match[str]) -> str:
        source_name = match.group(1)
        key = source_name.casefold()
        if key not in normalized:
            raise TemplateError(f"template references unknown parameter {source_name!r}")
        value = normalized[key]
        if not _SAFE_VALUE.fullmatch(value):
            raise TemplateError(f"template value for {source_name!r} is unsafe")
        used.add(key)
        return value

    rendered = _PLACEHOLDER.sub(replace, text)
    stray = re.search(r"@\{", rendered)
    if stray:
        raise TemplateError(f"malformed placeholder at character {stray.start()}")
    unused = sorted(set(normalized) - used)
    if unused:
        raise TemplateError(
            "sweep parameters are unused by the deck template: " + ", ".join(unused)
        )
    return rendered
