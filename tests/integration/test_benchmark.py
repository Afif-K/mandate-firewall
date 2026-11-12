"""The scenario suite, cell by cell: each (scenario x defense) run on a
fresh anvil must give the cell benchmark/scenarios.py expects
(docs/v0.1-plan.md §1). A regression in the firewall, a defense or the
harness shows up as one failing cell. The committed results.json must
agree with the same expectations."""

import json
from pathlib import Path

import pytest

from benchmark.defenses import DEFENSES
from benchmark.harness import run_scenario, write_registry
from benchmark.scenarios import SCENARIOS, mandate

RESULTS_JSON = Path(__file__).parents[2] / "benchmark" / "results.json"


@pytest.fixture(scope="module")
def registry(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return write_registry(tmp_path_factory.mktemp("suite-registry"))


@pytest.mark.anvil
@pytest.mark.parametrize("defense", DEFENSES)
@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.id)
def test_cell(scenario, defense: str, registry: Path, tmp_path: Path) -> None:  # noqa: ANN001
    result = run_scenario(scenario, defense, mandate, tmp_path, registry)
    assert result.cell is result.expected, (
        f"{scenario.id} {defense}: got {result.cell}, expected {result.expected}; "
        f"refused {result.blocked}, harms {result.harms}"
    )


def test_committed_results_match_the_expectations() -> None:
    """results.json covers every cell, each as expected: rerun the suite
    after changing a scenario or an expectation."""
    rows = json.loads(RESULTS_JSON.read_text())["results"]
    got = {(r["scenario"], r["defense"]): r["cell"] for r in rows}
    want = {(s.id, d): str(s.expected[d]) for s in SCENARIOS for d in DEFENSES}
    assert got == want
