"""The scenario suite, cell by cell: each (scenario x defense) run on a
fresh anvil must give the cell benchmark/scenarios.py expects
(docs/v0.1-plan.md §1). A regression in the firewall, a defense or the
harness shows up as one failing cell. The committed results.json must
agree with the same expectations.

Each cell also checks its run, step by step, against the committed
traces.json (the data the project website replays): a hand edit to that
file, or a change in what a run does, fails the cell
(docs/website-plan.md, pushback 1)."""

import json
from functools import cache
from pathlib import Path
from typing import Any

import pytest

from benchmark.defenses import DEFENSES
from benchmark.harness import run_scenario, write_registry
from benchmark.report import trace_entry
from benchmark.scenarios import SCENARIOS, mandate

RESULTS_JSON = Path(__file__).parents[2] / "benchmark" / "results.json"
TRACES_JSON = Path(__file__).parents[2] / "benchmark" / "traces.json"


@cache
def committed_traces() -> dict[tuple[str, str], dict[str, Any]]:
    runs = json.loads(TRACES_JSON.read_text())["runs"]
    return {(r["scenario"], r["defense"]): r for r in runs}


@pytest.fixture(scope="module")
def registry(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return write_registry(tmp_path_factory.mktemp("suite-registry"))


@pytest.mark.anvil
@pytest.mark.benchmark
@pytest.mark.parametrize("defense", DEFENSES)
@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.id)
def test_cell(scenario, defense: str, registry: Path, tmp_path: Path) -> None:  # noqa: ANN001
    result = run_scenario(scenario, defense, mandate, tmp_path, registry)
    assert result.cell is result.expected, (
        f"{scenario.id} {defense}: got {result.cell}, expected {result.expected}; "
        f"refused {result.blocked}, harms {result.harms}"
    )
    # Round-tripped through JSON, as the file was written.
    live = json.loads(json.dumps(trace_entry(result, scenario)))
    assert live == committed_traces()[(scenario.id, defense)], (
        f"{scenario.id} {defense}: the run differs from benchmark/traces.json; "
        "if the change is intended, rerun `uv run python -m benchmark`"
    )


def test_committed_results_match_the_expectations() -> None:
    """results.json covers every cell, each as expected: rerun the suite
    after changing a scenario or an expectation."""
    rows = json.loads(RESULTS_JSON.read_text())["results"]
    got = {(r["scenario"], r["defense"]): r["cell"] for r in rows}
    want = {(s.id, d): str(s.expected[d]) for s in SCENARIOS for d in DEFENSES}
    assert got == want


def test_committed_traces_match_the_results() -> None:
    """traces.json has exactly one run per cell of results.json, with the
    same cell and harms."""
    rows = json.loads(RESULTS_JSON.read_text())["results"]
    runs = json.loads(TRACES_JSON.read_text())["runs"]
    results = {(r["scenario"], r["defense"]): (r["cell"], r["harms"]) for r in rows}
    traces = {(r["scenario"], r["defense"]): (r["cell"], r["harms"]) for r in runs}
    assert len(runs) == len(traces)  # no run twice
    assert traces == results
