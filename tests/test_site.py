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
import re
from decimal import Decimal
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
    "harm": "✗ Harm",
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


def token_amount(base_units: str, symbol: str) -> str:
    """Base units in whole tokens, exactly: Decimal, not the builder's divmod."""
    decimals = TRACES["assets"][symbol]["decimals"]
    text = format(Decimal(base_units).scaleb(-decimals).normalize(), "f")
    return f"{text} {symbol}"


def party_name(address: str) -> str:
    matches = [name for name, a in TRACES["parties"].items() if a == address]
    assert len(matches) <= 1, address
    return matches[0] if matches else address


# data-fmt -> how a raw value from the file reads on the page.
FORMATS = {
    "cell": lambda item, arg: CELL_SHOWN[item],
    "amount": token_amount,
    "party": lambda item, arg: party_name(item),
    "answer": lambda item, arg: {"forwarded": "Forwarded", "refused": "Refused"}[item],
}


def signed_change(after: str, attrs: dict[str, str], symbol: str) -> str:
    """data-fmt="change:SYM": data-src minus data-base, signed, exact."""
    file, _, pointer = attrs["data-base"].partition("#")
    diff = int(after) - int(resolve(SOURCES[file], pointer))
    assert diff != 0, "the table shows only balances that changed"
    return ("+" if diff > 0 else "\u2212") + token_amount(str(abs(diff)), symbol)


def shown(attrs: dict[str, str]) -> str:
    """What the element must say, from the full file."""
    file, _, pointer = attrs["data-src"].partition("#")
    item = resolve(SOURCES[file], pointer)
    if attrs.get("data-fmt", "").startswith("change:"):
        return signed_change(item, attrs, attrs["data-fmt"].partition(":")[2])
    if "data-line" in attrs:
        item = item.split("\n")[int(attrs["data-line"])]
    if "data-fmt" in attrs:
        name, _, arg = attrs["data-fmt"].partition(":")
        assert name in FORMATS, f"no rule for data-fmt={attrs['data-fmt']!r}"
        return FORMATS[name](item, arg)
    assert isinstance(item, str | int), f"{attrs['data-src']} is not a single value"
    return str(item)


def test_every_shown_value_matches_the_full_files(page: Page) -> None:
    tagged = [(a, text) for a, text in page.values if "data-src" in a]
    assert len(tagged) > 100
    for attrs, text in tagged:
        assert text == shown(attrs), attrs["data-src"]


def test_every_cell_is_shown_once(page: Page) -> None:
    cells = [
        a["data-src"]
        for a, _ in page.values
        if a.get("data-fmt") == "cell" and a["data-src"].startswith("results#")
    ]
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
    assert csp, "no CSP meta"
    directives = dict(d.strip().partition(" ")[::2] for d in csp[0].split(";") if d.strip())
    assert directives == {
        "default-src": "'none'",
        "script-src": "'self'",
        "style-src": "'self'",
        "img-src": "data:",  # the inline favicon, nothing else
        "base-uri": "'none'",
        "form-action": "'none'",
        # Scripts can't write HTML (innerHTML and the like): text only.
        "require-trusted-types-for": "'script'",
        "trusted-types": "'none'",
    }
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


def test_the_attack_section_shows_a5_as_recorded(page: Page) -> None:
    """The rules forwarded the swap and the attacker gained; the firewall
    refused the same signed bytes and nothing moved."""
    values = {a["data-src"]: text for a, text in page.values if "data-src" in a}
    runs = {(r["scenario"], r["defense"]): i for i, r in enumerate(TRACES["runs"])}
    rules, firewall = runs[("A5", "rules")], runs[("A5", "firewall")]
    swap = next(
        i
        for i, step in enumerate(TRACES["runs"][firewall]["steps"])
        if step.get("call", {}).get("function") == "exactInputSingle"
    )
    assert values[f"traces#/runs/{firewall}/steps/{swap}/call/args/recipient"] == "attacker"
    assert values[f"traces#/runs/{rules}/holdings_after/attacker/mETH"] == "0.03 mETH"
    assert values[f"traces#/runs/{firewall}/holdings_after/attacker/mETH"] == "0 mETH"
    assert values[f"traces#/runs/{firewall}/cell"] == "✓ Blocked"
    assert values[f"traces#/runs/{rules}/cell"] == "✗ Harm"
    a = TRACES["runs"][rules]["steps"][swap]["tx_hash"]
    assert a == TRACES["runs"][firewall]["steps"][swap]["tx_hash"]


# --- accessibility ----------------------------------------------------------------

STYLE = (ROOT / "website" / "style.css").read_text()
# Text colour on background, as the stylesheet pairs them (WCAG AA: 4.5:1).
TEXT_PAIRS = [
    ("ink", "paper"),
    ("ink-2", "paper"),
    ("ink-3", "paper"),
    ("ink", "paper-2"),
    ("ink-2", "paper-2"),
    ("ink-3", "paper-2"),
    ("accent", "paper"),
    ("accent", "paper-2"),
    ("accent", "accent-soft"),
    ("accent-ink", "accent"),
    ("ink-2", "accent-soft"),
    ("good", "good-soft"),
    ("bad", "bad-soft"),
    ("warn", "warn-soft"),
    ("ink", "warn-soft"),
    ("good", "paper"),
    ("bad", "paper"),
    ("warn", "paper"),
    ("term-ink", "term-bg"),
    ("term-dim", "term-bg"),
    ("term-bad", "term-bg"),
    ("term-head", "term-bg"),
]


def colour_tokens() -> dict[str, dict[str, str]]:
    light_block = STYLE[STYLE.index(":root {") : STYLE.index("}", STYLE.index(":root {"))]
    start = STYLE.index("@media (prefers-color-scheme: dark)")
    dark_block = STYLE[start : STYLE.index("}\n}", start)]

    def found(block: str) -> dict[str, str]:
        return dict(re.findall(r"--([\w-]+):\s*(#[0-9a-fA-F]{6})\b", block))

    light = found(light_block)
    return {"light": light, "dark": light | found(dark_block)}


def luminance(colour: str) -> float:
    channels = [int(colour[i : i + 2], 16) / 255 for i in (1, 3, 5)]
    r, g, b = (c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a: str, b: str) -> float:
    high, low = sorted((luminance(a), luminance(b)), reverse=True)
    return (high + 0.05) / (low + 0.05)


@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_text_contrast_meets_wcag_aa(scheme: str) -> None:
    tokens = colour_tokens()[scheme]
    low = {
        f"{fg} on {bg}": round(contrast(tokens[fg], tokens[bg]), 2)
        for fg, bg in TEXT_PAIRS
        if contrast(tokens[fg], tokens[bg]) < 4.5
    }
    assert not low, f"{scheme}: below 4.5:1: {low}"


class Outline(HTMLParser):
    """Headings, landmarks, and the accessible text of links and buttons."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.headings: list[int] = []
        self.tags: list[tuple[str, dict[str, str]]] = []
        self.named: list[tuple[str, dict[str, str], list[str]]] = []  # a, button, label
        self.label_depth = 0
        self.controls_in_labels: list[str] = []
        self.label_for: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        found = {k: v or "" for k, v in attrs}
        self.tags.append((tag, found))
        if re.fullmatch(r"h[1-6]", tag):
            self.headings.append(int(tag[1]))
        if tag in ("a", "button"):
            self.named.append((tag, found, []))
        if tag == "label":
            self.label_depth += 1
            if "for" in found:
                self.label_for.add(found["for"])
        if tag in ("input", "select", "textarea") and self.label_depth:
            self.controls_in_labels.append(found.get("id") or found.get("name", tag))

    def handle_endtag(self, tag: str) -> None:
        if tag == "label":
            self.label_depth -= 1

    def handle_data(self, data: str) -> None:
        for _, _, text in self.named:
            text.append(data)


@pytest.fixture(scope="module")
def outline(site: Path) -> Outline:
    parser = Outline()
    parser.feed((site / "index.html").read_text())
    return parser


def test_one_h1_and_no_skipped_heading_levels(outline: Outline) -> None:
    assert outline.headings.count(1) == 1 and outline.headings[0] == 1
    for before, after in zip(outline.headings, outline.headings[1:], strict=False):
        assert after <= before + 1, f"h{before} followed by h{after}"


def test_landmarks_language_and_skip_link(outline: Outline) -> None:
    tags = [t for t, _ in outline.tags]
    html_attrs = dict(outline.tags)["html"]
    assert html_attrs.get("lang") == "en"
    for landmark in ("header", "nav", "main", "footer"):
        assert tags.count(landmark) == 1, landmark
    first_link = next(a for t, a in outline.tags if t == "a")
    assert first_link.get("href") == "#main" and ("main", {"id": "main"}) in outline.tags


def test_every_link_button_and_control_has_a_name(outline: Outline) -> None:
    for tag, attrs, text in outline.named:
        name = "".join(text).strip() or attrs.get("aria-label", "")
        assert name, f"<{tag} {attrs}> has no accessible name"
    controls = [
        a.get("id") or a.get("name", t) for t, a in outline.tags if t in ("input", "select")
    ]
    for control in controls:
        assert control in outline.controls_in_labels or control in outline.label_for, control
    for tag, attrs in outline.tags:
        if tag == "svg":
            assert attrs.get("aria-hidden") == "true", "decorative SVGs are hidden"
        if tag == "img":
            assert "alt" in attrs
