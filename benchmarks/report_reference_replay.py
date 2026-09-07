"""CLI shim for the installed real-reference evidence reporter."""

from __future__ import annotations

from simcairn.reference_replay import main

if __name__ == "__main__":
    raise SystemExit(main())
