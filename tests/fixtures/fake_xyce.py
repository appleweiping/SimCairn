"""Strict controlled Xyce test double; never used as physical evidence."""

from __future__ import annotations

import csv
import math
import os
import re
import subprocess
import sys
import time
from pathlib import Path


def _probes(line: str) -> list[str]:
    return re.findall(
        r"(?:V|I|VR|VI|VM|VDB|VP|IR|II|IM|IDB|IP)\([^\s]+?\)|INOISE|ONOISE",
        line,
        re.IGNORECASE,
    )


def main() -> int:
    if sys.argv[1:] == ["-v"]:
        print("This is version Xyce Release 7.10.0-opensource")
        print("SIMCAIRN CONTROLLED TEST DOUBLE - NO PHYSICAL SIMULATION")
        return 0
    if sys.argv[1:] != ["-randseed", "1", "-l", "xyce.log", "deck.cir"]:
        print(f"unexpected argv: {sys.argv[1:]!r}", file=sys.stderr)
        return 64
    if "LEAK_SENTINEL" in os.environ:
        print("ambient environment leaked", file=sys.stderr)
        return 65
    mode = os.environ.get("SIMCAIRN_FAKE_MODE", "success")
    if mode == "sleep":
        time.sleep(30)
    if mode == "spawn-child-overflow":
        sentinel = os.environ["SIMCAIRN_CHILD_SENTINEL"]
        subprocess.Popen(  # nosec B603: controlled fixture for process-tree cleanup
            [
                sys.executable,
                "-c",
                "import pathlib,sys,time;time.sleep(.5);"
                "pathlib.Path(sys.argv[1]).write_text('orphan')",
                sentinel,
            ],
            stdin=subprocess.DEVNULL,
        )
        sys.stdout.write("x" * 4096)
        return 0
    if mode == "exit":
        Path("xyce.log").write_text(
            "controlled diagnostic from Xyce log\n", encoding="utf-8", newline="\n"
        )
        return 7
    deck = Path("deck.cir").read_text(encoding="utf-8")
    if mode == "mutate-deck":
        Path("deck.cir").write_text("changed by controlled fixture\n", encoding="utf-8")
    print_line = next(line for line in deck.splitlines() if line.upper().startswith(".PRINT "))
    kind = print_line.split()[1].upper()
    probes = _probes(print_line)
    if mode == "missing":
        probes = ["V(not_requested)"]
    if kind == "TRAN":
        tran = next(line for line in deck.splitlines() if line.upper().startswith(".TRAN "))
        _card, step, stop, start = tran.split()
        step_value, stop_value, start_value = float(step), float(stop), float(start)
        count = math.ceil((stop_value - start_value) / step_value - 1e-12) + 1
        axis = "TIME"
        values = [start_value + index * step_value for index in range(count - 1)]
        values.append(stop_value)
    elif kind in {"AC", "NOISE"}:
        prefix = f".{kind} "
        sweep_line = next(line for line in deck.splitlines() if line.upper().startswith(prefix))
        parts = sweep_line.split()
        sweep, points, start, stop = parts[-4:]
        points_value, start_value, stop_value = int(points), float(start), float(stop)
        if sweep.upper() == "LIN":
            count = points_value
            values = [
                start_value + index * (stop_value - start_value) / (count - 1)
                for index in range(count)
            ]
        else:
            logarithm = math.log10 if sweep.upper() == "DEC" else math.log2
            base = 10.0 if sweep.upper() == "DEC" else 2.0
            count = math.floor(points_value * logarithm(stop_value / start_value) + 1e-12) + 1
            values = [start_value * base ** (index / points_value) for index in range(count)]
        axis = "FREQ"
    elif ".OP" in deck.upper():
        axis, values = None, [0.0]
    else:
        dc_line = next(line for line in deck.splitlines() if line.upper().startswith(".DC "))
        _card, _source, start, stop, step = dc_line.split()
        start_value, stop_value, step_value = float(start), float(stop), float(step)
        count = int((stop_value - start_value) / step_value + 1e-12) + 1
        axis = probes.pop(0)
        values = [start_value + index * step_value for index in range(count)]
    with Path("results.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow([*(() if axis is None else (axis,)), *probes])
        for index, value in enumerate(values):
            coordinates = [] if axis is None else [value]
            writer.writerow(
                [*coordinates, *(index + offset / 10 for offset, _ in enumerate(probes, 1))]
            )
    if mode == "oversize":
        with Path("results.csv").open("ab") as stream:
            stream.write(b"0" * (17 * 1024 * 1024))
    Path("xyce.log").write_text(
        "CONTROLLED TEST DOUBLE: no circuit equations were solved\n",
        encoding="utf-8",
        newline="\n",
    )
    if mode == "precreate":
        Path("stdout.log").write_text("must not be overwritten\n", encoding="utf-8", newline="\n")
    print("controlled Xyce fixture completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
