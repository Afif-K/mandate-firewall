"""uv run python -m benchmark [--only B] [--defense firewall] [--keep] [--pause] [--no-write]

Runs each scenario behind each defense on a fresh anvil and prints the
table. A full run (no --only, no --defense) also writes
benchmark/results.json and benchmark/RESULTS.md. Exits 1 if any cell
differs from what the plan predicts.
"""

import argparse
import shutil
import sys
import tempfile
import time
from functools import partial
from pathlib import Path

from benchmark.defenses import DEFENSES
from benchmark.harness import AGENT, ATTACKER, MARKET, Result, run_scenario, write_registry
from benchmark.report import table, to_json, to_markdown
from benchmark.scenarios import SCENARIOS, mandate
from tests.integration.chain import BOB

HERE = Path(__file__).parent


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m benchmark", description=__doc__)
    parser.add_argument(
        "--only", default="", help="comma-separated id prefixes, e.g. B or A1,B6 (default: all)"
    )
    parser.add_argument("--defense", choices=DEFENSES, action="append", help="repeatable")
    parser.add_argument(
        "--keep", action="store_true", help="keep each run's directory (logs, audit log, store)"
    )
    parser.add_argument(
        "--pause",
        action="store_true",
        help="after each run, keep its chain up until Enter, to inspect it (e.g. with cast)",
    )
    parser.add_argument(
        "--no-write", action="store_true", help="don't write results.json / RESULTS.md"
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
                workdir = root / scenario.id / name
                pause = partial(wait_for_enter, scenario.id, name) if args.pause else None
                result = run_scenario(scenario, name, mandate, workdir, registry, pause)
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
        for harm in r.harms:
            print(f"  {r.scenario} {r.defense}: harm: {harm}")
        if r.attacker_delta:
            print(f"  {r.scenario} {r.defense}: attacker balance change: {r.attacker_delta}")
    if not prefixes and not args.defense and not args.no_write:
        (HERE / "results.json").write_text(to_json(results, scenarios))
        (HERE / "RESULTS.md").write_text(to_markdown(results, scenarios, defenses))
        print(f"wrote {HERE / 'results.json'} and {HERE / 'RESULTS.md'}")
    return 1 if unexpected else 0


def wait_for_enter(scenario: str, defense: str, url: str) -> None:
    print(f"\n{scenario} {defense}: the chain is up at {url}")
    print(f"  attacker {ATTACKER}, agent {AGENT}, bob {BOB}")
    print(f"  mUSD {MARKET.musd}, mETH {MARKET.meth}, router {MARKET.router}")
    input("  press Enter to stop it and go on ")


if __name__ == "__main__":
    sys.exit(main())
