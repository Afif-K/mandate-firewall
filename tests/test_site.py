"""The project website (scripts/build_site.py, website/): built from the
scenario suite's files, and nothing on it disagrees with them.

- Every element the builder fills from a suite file names its source
  (data-src, a JSON pointer). Each one is resolved against the full
  results.json or traces.json and its text compared, with this test's own
  formatting rules, not the builder's.
- The recorded runs embedded in the page are a strict subset of
  traces.json: values may be left out, never changed (docs/website-plan.md).
- No request leaves the page's own origin, links go only to GitHub, the
  build is deterministic and fits the 150 KB budget.
"""

import importlib.util
import json
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
RESULTS = json.loads((ROOT / "benchmark" / "results.json").read_text())
TRACES = json.loads((ROOT / "benchmark" / "traces.json").read_text())
SOURCES = {"results": RESULTS, "traces": TRACES}
BUDGET_BYTES = 150_000

# How a results.json cell reads on the page: written out here, separately
# from the builder's own table.
CELL_SHOWN = {
    "blocked": "✓ Blocked",
    "harm": "✗ Allowed, harm",
    "allowed": "✓ Allowed",
    "false positive": "! False positive",
}
VOID = {"meta", "link", "br", "img", "input", "hr", "source", "wbr", "area", "col", "base"}


def load_builder() -> Any:
    spec = importlib.util.spec_from_file_location("build_site", ROOT / "scripts" / "build_site.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Page(HTMLParser):
    """Collects the tagged values, links, sources and the embedded data."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[str] = []
        self.open: list[tuple[int, dict[str, str], list[str]]] = []  # (depth, attrs, text)
        self.values: list[tuple[dict[str, str], str]] = []
        self.attrs: list[tuple[str, dict[str, str]]] = []
        self.data_block: list[str] | None = None
        self.trace_data = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        found = {k: v or "" for k, v in attrs}
        self.attrs.append((tag, found))
        if tag in VOID:
            return
        self.stack.append(tag)
        if "data-src" in found or "data-summary" in found:
            self.open.append((len(self.stack), found, []))
        if tag == "script" and found.get("id") == "trace-data":
            self.data_block = []

    def handle_endtag(self, tag: str) -> None:
        if tag in VOID:
            return
        assert self.stack and self.stack[-1] == tag, f"unbalanced </{tag}> after {self.stack[-3:]}"
        if self.open and self.open[-1][0] == len(self.stack):
            _, found, text = self.open.pop()
            self.values.append((found, "".join(text)))
        if tag == "script" and self.data_block is not None:
            self.trace_data = "".join(self.data_block)
            self.data_block = None
        self.stack.pop()

    def handle_data(self, data: str) -> None:
        for _, _, text in self.open:
            text.append(data)
        if self.data_block is not None:
            self.data_block.append(data)


@pytest.fixture(scope="module")
def site(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("site") / "_site"
    load_builder().build(out)
    return out


@pytest.fixture(scope="module")
def page(site: Path) -> Page:
    parser = Page()
    parser.feed((site / "index.html").read_text())
    parser.close()
    assert not parser.stack, f"unclosed elements: {parser.stack}"
    return parser


def resolve(document: Any, pointer: str) -> Any:
    item = document
    for raw in pointer.split("/")[1:]:
        key = raw.replace("~1", "/").replace("~0", "~")
        item = item[int(key)] if isinstance(item, list) else item[key]
    return item


def shown(attrs: dict[str, str]) -> str:
    """What the element must say, from the full file."""
    file, _, pointer = attrs["data-src"].partition("#")
    item = resolve(SOURCES[file], pointer)
    if "data-line" in attrs:
        item = item.split("\n")[int(attrs["data-line"])]
    if attrs.get("data-fmt") == "cell":
        return CELL_SHOWN[item]
    assert "data-fmt" not in attrs, f"no rule for data-fmt={attrs['data-fmt']!r}"
    assert isinstance(item, str | int), f"{attrs['data-src']} is not a single value"
    return str(item)


def test_every_shown_value_matches_the_full_files(page: Page) -> None:
    tagged = [(a, text) for a, text in page.values if "data-src" in a]
    assert len(tagged) > 100
    for attrs, text in tagged:
        assert text == shown(attrs), attrs["data-src"]


def test_every_cell_is_shown_once(page: Page) -> None:
    cells = [a["data-src"] for a, _ in page.values if a.get("data-fmt") == "cell"]
    expected = [f"results#/results/{i}/cell" for i in range(len(RESULTS["results"]))]
    assert sorted(cells) == sorted(expected)


def test_summary_counts(page: Page) -> None:
    counts = {a["data-summary"]: text for a, text in page.values if "data-summary" in a}
    for defense in ("none", "rules", "firewall"):
        mine = [r for r in RESULTS["results"] if r["defense"] == defense]
        attacks = [r for r in mine if r["kind"] in ("attack", "miss")]
        benign = [r for r in mine if r["kind"] == "benign"]
        blocked = sum(r["cell"] == "blocked" for r in attacks)
        allowed = sum(r["cell"] == "allowed" for r in benign)
        assert counts[f"{defense} attacks"] == f"{blocked}/{len(attacks)}"
        assert counts[f"{defense} benign"] == f"{allowed}/{len(benign)}"
    # The README's table, as a fixed point: a change here is a change to the pitch.
    assert counts["firewall attacks"] == "7/10" and counts["rules attacks"] == "4/10"


def test_the_hero_shows_a_real_refusal(page: Page) -> None:
    lines = [t for a, t in page.values if "data-line" in a]
    assert lines[0].startswith("BLOCKED  tx 0x")
    assert "Why:" in lines and "Nothing was charged." in lines
    run = resolve(TRACES, page.values[0][0]["data-src"].partition("#")[2].split("/steps")[0])
    assert (run["scenario"], run["defense"], run["cell"]) == ("A5", "firewall", "blocked")
    rules = next(r for r in TRACES["runs"] if (r["scenario"], r["defense"]) == ("A5", "rules"))
    assert rules["cell"] == "harm"  # the caption says the rules allowed it


def is_subset(part: Any, whole: Any, where: str = "") -> None:
    """`part` only leaves values out of `whole`: object keys may be missing,
    lists keep their length and order, every value present is equal."""
    if isinstance(part, dict):
        assert isinstance(whole, dict), where
        for key, item in part.items():
            assert key in whole, f"{where}/{key} is not in traces.json"
            is_subset(item, whole[key], f"{where}/{key}")
    elif isinstance(part, list):
        assert isinstance(whole, list) and len(part) == len(whole), where
        for i, (a, b) in enumerate(zip(part, whole, strict=True)):
            is_subset(a, b, f"{where}/{i}")
    else:
        assert part == whole and type(part) is type(whole), where


def test_embedded_runs_are_a_subset_of_traces_json(page: Page) -> None:
    embedded = json.loads(page.trace_data)
    is_subset(embedded, TRACES)
    assert len(embedded["runs"]) == len(TRACES["runs"])
    assert "<" not in page.trace_data  # nothing can close the data block early


def test_no_request_leaves_the_origin(page: Page) -> None:
    csp = [
        a["content"]
        for tag, a in page.attrs
        if tag == "meta" and a.get("http-equiv") == "Content-Security-Policy"
    ]
    assert csp and "default-src 'none'" in csp[0]
    assert "script-src 'self'" in csp[0] and "style-src 'self'" in csp[0]
    for tag, attrs in page.attrs:
        assert "style" not in attrs, f"inline style on <{tag}> (the CSP refuses it)"
        assert not any(k.startswith("on") for k in attrs), f"inline handler on <{tag}>"
        for key in ("src", "srcset", "poster", "data"):
            if key in attrs:
                assert "//" not in attrs[key], f"<{tag} {key}={attrs[key]!r}>"
        if tag == "link":
            assert attrs["href"].startswith("data:") or "//" not in attrs["href"], attrs


def test_links_go_only_to_github(page: Page) -> None:
    for tag, attrs in page.attrs:
        if tag != "a":
            continue
        href = attrs["href"]
        assert href.startswith("#") or href.startswith("https://github.com/"), href


def test_build_is_deterministic_and_within_budget(site: Path, tmp_path: Path) -> None:
    again = tmp_path / "again"
    load_builder().build(again)
    files = sorted(p.relative_to(site) for p in site.rglob("*") if p.is_file())
    assert files == sorted(p.relative_to(again) for p in again.rglob("*") if p.is_file())
    for name in files:
        assert (site / name).read_bytes() == (again / name).read_bytes(), name
    size = sum((site / name).stat().st_size for name in files)
    assert size < BUDGET_BYTES, f"{size} bytes"
