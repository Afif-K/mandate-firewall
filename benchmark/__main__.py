"""uv run python -m benchmark [--only B] [--defense firewall] [--keep]

Runs each scenario behind each defense on a fresh anvil and prints the
table. Exits 1 if any cell differs from what the plan predicts.
"""

import argparse
import shutil
import sys
import tempfile
import time
from pathlib import Path

from benchmark.defenses import DEFENSES
from benchmark.harness import Cell, Result, run_scenario, write_registry
from benchmark.scenarios import SCENARIOS, mandate

SYMBOLS = {
    Cell.BLOCKED: "✅ blocked",
    Cell.HARM: "❌ allowed, harm",
    Cell.ALLOWED: "✅ allowed",
    Cell.FALSE_POSITIVE: "⚠ false positive",
    Cell.FAILED: "❌ failed",
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m benchmark", description=__doc__)
    parser.add_argument(
        "--only", default="", help="comma-separated id prefixes, e.g. B or A1,B6 (default: all)"
    )
    parser.add_argument("--defense", choices=DEFENSES, action="append", help="repeatable")
    parser.add_argument(
        "--keep", action="store_true", help="keep each run's directory (logs, audit log, store)"
    )
    args = parser.parse_args(argv)

    prefixes = [p.strip() for p in args.only.split(",") if p.strip()]
    scenarios = [s for s in SCENARIOS if not prefixes or s.id.startswith(tuple(prefixes))]
    defenses = args.defense or list(DEFENSES)
    if not scenarios:
        parser.error(f"no scenario matches --only {args.only!r}")

    root = Path(tempfile.mkdtemp(prefix="mandate-firewall-suite-"))
    registry = write_registry(root / "registry")
    started = time.monotonic()
    results: list[Result] = []
    try:
        for scenario in scenarios:
            for name in defenses:
                result = run_scenario(scenario, name, mandate, root / scenario.id / name, registry)
                results.append(result)
                mark = "" if result.as_expected else f"   UNEXPECTED (plan: {result.expected})"
                print(f"{scenario.id} {name:<8} {result.cell}  {result.seconds:.1f}s{mark}")
    finally:
        if args.keep:
            print(f"\nrun directories kept in {root}")
        else:
            shutil.rmtree(root, ignore_errors=True)

    print()
    print(table(results, scenarios, defenses))
    unexpected = [r for r in results if not r.as_expected]
    print(
        f"\n{len(results)} runs in {time.monotonic() - started:.0f}s, {len(unexpected)} unexpected"
    )
    for r in results:
        if r.blocked:
            print(f"  {r.scenario} {r.defense}: refused: {'; '.join(r.blocked)}")
        if r.attacker_gain:
            print(f"  {r.scenario} {r.defense}: the attacker gained {r.attacker_gain}")
    return 1 if unexpected else 0


def table(results: list[Result], scenarios: list, defenses: list[str]) -> str:
    cells = {(r.scenario, r.defense): r for r in results}
    lines = [
        "| # | Scenario | " + " | ".join(defenses) + " |",
        "|---|---|" + "---|" * len(defenses),
    ]
    for s in scenarios:
        row = []
        for d in defenses:
            r = cells[(s.id, d)]
            row.append(SYMBOLS[r.cell] + ("" if r.as_expected else " (unexpected)"))
        lines.append(f"| {s.id} | {s.mandate}: {s.title} | " + " | ".join(row) + " |")
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())
