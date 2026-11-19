#!/usr/bin/env python3
"""Build the project website from the scenario suite's own output.

Run from the repo root:

    uv run python scripts/build_site.py _site

Reads website/ (the hand-written page and styles) and the files a full
`uv run python -m benchmark` writes (benchmark/results.json and
benchmark/traces.json), and writes a static site to the given directory.
Standard library only; no network, no timestamps, so the same inputs give
the same bytes (docs/website-plan.md §2).

Every value the page shows that comes from the suite is in an element that
names its source: `data-src="traces#/runs/14/steps/1/firewall/explanation"`
(a JSON pointer into the file), with `data-line` when the element shows one
line of a multi-line string and `data-fmt` when the value is formatted
(see FORMATS in tests/test_site.py: a cell name, a token amount, a party's
name, a defense's answer). tests/test_site.py resolves
every one against the full files and checks the text. The recorded runs
are embedded as a trimmed copy of traces.json; the same test checks that
the copy is a strict subset of the full file (values removed, none changed).
"""

import html
import json
import shutil
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
REPO_URL = "https://github.com/Afif-K/mandate-firewall"
BLOB = f"{REPO_URL}/blob/main"

# The cell names results.json uses, as the page shows them: a symbol and a
# word, never colour alone.
CELL_TEXT = {
    "blocked": ("✓", "Blocked"),
    "harm": ("✗", "Harm"),
    "allowed, no harm": ("?", "Allowed, no harm"),
    "allowed": ("✓", "Allowed"),
    "false positive": ("!", "False positive"),
    "failed": ("✗", "Failed"),
}
CELL_CLASS = {
    "blocked": "good",
    "harm": "bad",
    "allowed, no harm": "warn",
    "allowed": "good",
    "false positive": "warn",
    "failed": "bad",
}
KIND_HEADING = {
    "attack": "Attacks",
    "miss": "Attacks the firewall misses (documented gaps)",
    "benign": "Benign tasks",
}
DEFENSE_NAME = {"none": "No defense", "rules": "Rule-based guard", "firewall": "Mandate firewall"}
FEATURED = ("A5", "firewall")  # the attack rules miss, in the hero

FAVICON = (
    "data:image/svg+xml,"
    "%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E"
    "%3Cpath d='M16 2 4 7v8c0 7.5 5.1 13.4 12 15 6.9-1.6 12-7.5 12-15V7z' fill='%232457d6'/%3E"
    "%3Cpath d='M10 16.5l4 4 8-9' fill='none' stroke='white' stroke-width='3' "
    "stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E"
)


def esc(text: object) -> str:
    return html.escape(str(text), quote=True)


def pointer(*parts: object) -> str:
    """A JSON pointer (RFC 6901) to parts."""
    return "".join("/" + str(p).replace("~", "~0").replace("/", "~1") for p in parts)


def src(file: str, *parts: object) -> str:
    return f'data-src="{esc(file)}#{esc(pointer(*parts))}"'


def value(text: str, file: str, *parts: object, tag: str = "span", fmt: str | None = None,
          line: int | None = None, cls: str | None = None) -> str:  # fmt: skip
    """An element showing one value from a suite file, tagged with its source."""
    attrs = [src(file, *parts)]
    if fmt is not None:
        attrs.append(f'data-fmt="{esc(fmt)}"')
    if line is not None:
        attrs.append(f'data-line="{line}"')
    if cls is not None:
        attrs.append(f'class="{esc(cls)}"')
    return f"<{tag} {' '.join(attrs)}>{esc(text)}</{tag}>"


# --- the embedded recorded runs ------------------------------------------------------


def drop_nulls(item: Any) -> Any:
    """Remove null-valued keys from objects, recursively. Lists keep their
    length and order, so every pointer into the copy points at the same
    value in the full file."""
    if isinstance(item, dict):
        return {k: drop_nulls(v) for k, v in item.items() if v is not None}
    if isinstance(item, list):
        return [drop_nulls(v) for v in item]
    return item


def changed(before: dict[str, dict[str, str]], after: dict[str, dict[str, str]], which: str) -> (
    dict[str, dict[str, str]]
):  # fmt: skip
    """`which` (before or after) holdings, only where the balance changed."""
    pick = before if which == "before" else after
    out: dict[str, dict[str, str]] = {}
    for party, assets in pick.items():
        moved = {a: n for a, n in assets.items() if before[party][a] != after[party][a]}
        if moved:
            out[party] = moved
    return out


def trimmed(traces: dict[str, Any]) -> dict[str, Any]:
    """What the page embeds: a subset of traces.json, nothing rewritten."""
    top = ("suite", "package_version", "anvil", "chain_id", "note", "parties", "assets", "mandates")
    runs = []
    for run in traces["runs"]:
        keep = {k: run[k] for k in ("scenario", "kind", "mandate", "title", "defense", "cell")}
        keep["harms"] = run["harms"]
        before, after = run["holdings_before"], run["holdings_after"]
        keep["holdings_before"] = changed(before, after, "before")
        keep["holdings_after"] = changed(before, after, "after")
        keep["steps"] = drop_nulls(run["steps"])
        runs.append(keep)
    return {**{k: traces[k] for k in top}, "runs": runs}


def embed_json(document: Any) -> str:
    """JSON safe inside <script type="application/json">: no `<` at all, so
    no `</script>` or `<!--` can end the block early. JSON readers turn
    \\u003c back into `<`."""
    text = json.dumps(document, ensure_ascii=False, separators=(",", ":"))
    return text.replace("<", "\\u003c")


# --- the hero card: an excerpt of the featured run's real explanation ---------------


def run_index(traces: dict[str, Any], scenario: str, defense: str) -> int:
    for i, run in enumerate(traces["runs"]):
        if (run["scenario"], run["defense"]) == (scenario, defense):
            return i
    raise SystemExit(f"build_site: traces.json has no run {scenario} {defense}")


def featured_step(traces: dict[str, Any]) -> tuple[int, int, dict[str, Any]]:
    """The featured run's refused step with a firewall explanation."""
    r = run_index(traces, *FEATURED)
    for s, step in enumerate(traces["runs"][r]["steps"]):
        if step.get("answer") == "refused" and step.get("firewall", {}).get("explanation"):
            return r, s, step
    raise SystemExit(f"build_site: {FEATURED} has no refused step with an explanation")


def excerpt(lines: list[str]) -> Iterator[int | None]:
    """Indexes of the explanation lines the hero shows; None marks a cut.
    Shows the verdict line, what the user said, and everything from "This
    transaction:" on. Leaves out the intent's detail lines."""
    yield 0
    said = next(i for i, ln in enumerate(lines) if ln.lstrip().startswith("you said:"))
    yield from (2, said)
    doing = lines.index("This transaction:")
    if doing > said + 1:
        yield None
    yield from range(doing, len(lines))


def hero_card(traces: dict[str, Any]) -> str:
    r, s, step = featured_step(traces)
    lines = step["firewall"]["explanation"].split("\n")
    rows = []
    for i in excerpt(lines):
        if i is None:
            rows.append('<span class="ln cut" aria-hidden="true">  …</span>')
            continue
        text = lines[i]
        cls = "ln"
        if i == 0:
            cls += " verdict"
        elif not text.startswith(" "):
            cls += " head"
        parts = ("runs", r, "steps", s, "firewall", "explanation")
        rows.append(value(text, "traces", *parts, line=i, cls=cls))
    run = traces["runs"][r]
    scenario = value(run["scenario"], "traces", "runs", r, "scenario")
    return (
        '<figure class="terminal" aria-labelledby="hero-cap">'
        '<div class="terminal-bar" aria-hidden="true"><i></i><i></i><i></i>'
        "<span>mandate-firewall alerts</span></div>"
        f'<pre class="terminal-body">{"".join(rows)}</pre>'
        f'<figcaption id="hero-cap">Recorded output, scenario {scenario}: a swap through the '
        "right router, of the right token, within budget, whose output goes to the attacker. "
        "The rule-based guard allowed it. Lines about the mandate's details are cut "
        "(…).</figcaption></figure>"
    )


# --- the attack rules miss: A5, side by side ------------------------------------


def amount(base_units: str, symbol: str, traces: dict[str, Any]) -> str:
    """Base units as a decimal amount, exactly: "30000" mETH -> "0.03 mETH"."""
    decimals = traces["assets"][symbol]["decimals"]
    whole, fraction = divmod(int(base_units), 10**decimals)
    text = str(whole)
    if fraction:
        text += "." + str(fraction).rjust(decimals, "0").rstrip("0")
    return f"{text} {symbol}"


def party(address: str, traces: dict[str, Any]) -> str:
    names = {a: name for name, a in traces["parties"].items()}
    return names.get(address, address)


def swap_step(traces: dict[str, Any], r: int) -> tuple[int, dict[str, Any]]:
    for s, step in enumerate(traces["runs"][r]["steps"]):
        if step.get("call", {}).get("function") == "exactInputSingle":
            return s, step
    raise SystemExit(f"build_site: run {r} has no swap step")


def balance_change(traces: dict[str, Any], r: int, who: str, symbol: str) -> str:
    """`who`'s balance of `symbol`, before and after the run."""
    run = traces["runs"][r]
    shown = []
    for when in ("holdings_before", "holdings_after"):
        base = run[when][who][symbol]
        fmt = f"amount:{symbol}"
        shown.append(
            value(amount(base, symbol, traces), "traces", "runs", r, when, who, symbol, fmt=fmt)
        )
    return (
        f'<span class="who">{esc(who)}</span> {shown[0]} <span aria-label="to">→</span> {shown[1]}'
    )


def answer(traces: dict[str, Any], r: int, s: int) -> str:
    """A step's answer, capitalised: Forwarded or Refused."""
    text = traces["runs"][r]["steps"][s]["answer"]
    return value(text.capitalize(), "traces", "runs", r, "steps", s, "answer", fmt="answer")


def run_cell(traces: dict[str, Any], r: int) -> str:
    shown = " ".join(CELL_TEXT[traces["runs"][r]["cell"]])
    return value(shown, "traces", "runs", r, "cell", fmt="cell", cls="badge-cell")


def call_args(traces: dict[str, Any], r: int, s: int) -> str:
    """The swap's arguments as named values; the recipient is flagged."""
    args = traces["runs"][r]["steps"][s]["call"]["args"]
    rows = []
    for name, shown, fmt in (
        ("tokenIn", party(args["tokenIn"], traces), "party"),
        ("tokenOut", party(args["tokenOut"], traces), "party"),
        ("amountIn", amount(args["amountIn"], "mUSD", traces), "amount:mUSD"),
        ("amountOutMinimum", amount(args["amountOutMinimum"], "mETH", traces), "amount:mETH"),
        ("recipient", party(args["recipient"], traces), "party"),
    ):
        flag = ' class="flag"' if name == "recipient" else ""
        where = ("runs", r, "steps", s, "call", "args", name)
        rows.append(
            f'<tr{flag}><th scope="row"><code>{esc(name)}</code></th>'
            f"<td>{value(shown, 'traces', *where, fmt=fmt)}</td></tr>"
        )
    return f'<table class="args"><tbody>{"".join(rows)}</tbody></table>'


def balances(traces: dict[str, Any], r: int) -> str:
    return (
        f'<p class="balances">{balance_change(traces, r, "attacker", "mETH")}<br>'
        f"{balance_change(traces, r, 'agent', 'mUSD')}</p>"
    )


def attack_section(traces: dict[str, Any]) -> str:
    """The within-policy, off-mandate swap: what the user asked, the
    transaction the agent signed, and what each defense did with it."""
    scenario = FEATURED[0]
    rules, firewall = run_index(traces, scenario, "rules"), run_index(traces, scenario, "firewall")
    s_rules, step_rules = swap_step(traces, rules)
    s, step = swap_step(traces, firewall)
    if step_rules["tx_hash"] != step["tx_hash"]:
        raise SystemExit("build_site: the A5 defenses did not get the same signed transaction")
    which = traces["runs"][firewall]["mandate"]
    mandate = traces["mandates"][which]

    said = value(mandate["instruction"], "traces", "mandates", which, "instruction", tag="q")
    lines = "".join(
        value(line, "traces", "mandates", which, "lines", i, cls="ln")
        for i, line in enumerate(mandate["lines"])
    )
    function = value(step["call"]["function"], "traces", "runs", firewall, "steps", s, "call",
                     "function", tag="code")  # fmt: skip
    target = value(party(step["to"], traces), "traces", "runs", firewall, "steps", s, "to",
                   fmt="party")  # fmt: skip
    explanation = step["firewall"]["explanation"].split("\n")
    why_line = explanation.index("Why:") + 1
    why = value(explanation[why_line], "traces", "runs", firewall, "steps", s, "firewall",
                "explanation", line=why_line)  # fmt: skip
    return f"""
<div class="flow">
  <article class="flow-card">
    <p class="flow-step"><span>1</span> You asked</p>
    <p class="said">{said}</p>
    <pre class="mono-block">{lines}</pre>
    <p class="flow-note">Locked as mandate {esc(which)} before the agent read anything.</p>
  </article>
  <article class="flow-card">
    <p class="flow-step"><span>2</span> The injected agent signed</p>
    <p class="call">{function} to the {target}</p>
    {call_args(traces, firewall, s)}
    <p class="flow-note">Right router, right token, within budget. Only the recipient is wrong,
      inside calldata an allowlist never reads. Both defenses got the same signed bytes.</p>
  </article>
  <article class="flow-card outcomes">
    <p class="flow-step"><span>3</span> What happened</p>
    <div class="outcome bad">
      <h3>Rule-based guard {run_cell(traces, rules)}</h3>
      <p>{answer(traces, rules, s_rules)}: the target is on the allowlist, and a router call
        isn't an ERC-20 transfer, so the rules have no recipient to check.</p>
      {balances(traces, rules)}
    </div>
    <div class="outcome good">
      <h3>Mandate firewall {run_cell(traces, firewall)}</h3>
      <p>{answer(traces, firewall, s)} after simulating it:</p>
      <p class="why">{why}</p>
      {balances(traces, firewall)}
    </div>
  </article>
</div>"""


# --- the results tables ----------------------------------------------------------


def summary_rows(results: dict[str, Any]) -> str:
    rows = []
    for defense in ("none", "rules", "firewall"):
        cells = []
        for group in ("attacks", "benign"):
            tag = f'data-summary="{defense} {group}"'
            cells.append(f"<td {tag}>{esc(summary_count(results, defense, group))}</td>")
        rows.append(
            f'<tr class="def-{defense}"><th scope="row">{esc(DEFENSE_NAME[defense])}</th>'
            + "".join(cells)
            + "</tr>"
        )
    return "".join(rows)


def summary_count(results: dict[str, Any], defense: str, group: str) -> str:
    mine = [r for r in results["results"] if r["defense"] == defense]
    if group == "attacks":
        pool = [r for r in mine if r["kind"] != "benign"]
        return f"{sum(r['cell'] == 'blocked' for r in pool)}/{len(pool)}"
    pool = [r for r in mine if r["kind"] == "benign"]
    return f"{sum(r['cell'] == 'allowed' for r in pool)}/{len(pool)}"


COLUMN = {"none": "No defense", "rules": "Rules", "firewall": "Firewall"}


def cell_html(results: dict[str, Any], index: int) -> str:
    """One defense's cell. `data-label` names the column on phones, where
    the row is stacked and the header row is out of view."""
    row = results["results"][index]
    cell = row["cell"]
    symbol, word = CELL_TEXT[cell]
    shown = value(f"{symbol} {word}", "results", "results", index, "cell", fmt="cell")
    label = esc(COLUMN[row["defense"]])
    return f'<td role="cell" class="cell {CELL_CLASS[cell]}" data-label="{label}">{shown}</td>'


def result_rows(results: dict[str, Any]) -> str:
    rows: list[str] = []
    order: list[str] = []
    by_cell: dict[tuple[str, str], int] = {}
    for i, r in enumerate(results["results"]):
        by_cell[(r["scenario"], r["defense"])] = i
        if r["scenario"] not in order:
            order.append(r["scenario"])
    kind = None
    for scenario in order:
        first = by_cell[(scenario, "none")]
        row = results["results"][first]
        if row["kind"] != kind:
            kind = row["kind"]
            rows.append(
                '<tr role="row" class="group"><th role="rowheader" colspan="5" scope="colgroup">'
                f"{esc(KIND_HEADING[kind])}</th></tr>"
            )
        cells = "".join(
            cell_html(results, by_cell[(scenario, d)]) for d in ("none", "rules", "firewall")
        )
        rows.append(
            f'<tr role="row" class="kind-{esc(kind)}">'
            '<th role="rowheader" scope="row">'
            f"{value(scenario, 'results', 'results', first, 'scenario')}</th>"
            '<td role="cell" class="what">'
            f"{value(row['mandate'], 'results', 'results', first, 'mandate', cls='mandate-tag')} "
            f"{value(row['title'], 'results', 'results', first, 'title')}</td>"
            f"{cells}</tr>"
        )
    return "".join(rows)


def mandate_legend(traces: dict[str, Any]) -> str:
    items = []
    for which, m in traces["mandates"].items():
        said = value(m["instruction"], "traces", "mandates", which, "instruction", tag="q")
        items.append(f'<li><span class="mandate-tag">{esc(which)}</span> {said}</li>')
    return "".join(items)


def versions(traces: dict[str, Any]) -> str:
    return (
        f"mandate-firewall {value(traces['package_version'], 'traces', 'package_version')}, "
        f"{value(traces['anvil'], 'traces', 'anvil')}"
    )


# --- the page ----------------------------------------------------------------------


def minify_css(text: str) -> str:
    """Comments out, whitespace collapsed, no spaces around `{ } ; ,` or
    after `:`. Quoted strings are copied as they are. The source in
    website/ stays readable; this only keeps the page within budget."""
    out: list[str] = []
    i = 0
    while i < len(text):
        c = text[i]
        if c in "\"'":
            end = text.index(c, i + 1) + 1
            out.append(text[i:end])
            i = end
        elif text.startswith("/*", i):
            i = text.index("*/", i) + 2
        elif c.isspace():
            while i < len(text) and text[i].isspace():
                i += 1
            if out and out[-1][-1:] not in "{};,:" and i < len(text) and text[i] not in "{};,":
                out.append(" ")
        else:
            if c in "{};," and out and out[-1] == " ":
                out.pop()
            out.append(c)
            i += 1
    return "".join(out).strip() + "\n"


def render(template: str, slots: dict[str, str]) -> str:
    page = template
    for name, text in slots.items():
        page = page.replace("{{" + name + "}}", text)
    if "{{" in page:
        missing = page[page.index("{{") : page.index("{{") + 40]
        raise SystemExit(f"build_site: unfilled slot in the template: {missing!r}")
    return page


def build(out: Path, root: Path = ROOT) -> None:
    results = json.loads((root / "benchmark" / "results.json").read_text())
    traces = json.loads((root / "benchmark" / "traces.json").read_text())
    template = (root / "website" / "index.html.in").read_text()
    page = render(
        template,
        {
            "favicon": FAVICON,
            "repo": REPO_URL,
            "blob": BLOB,
            "hero_card": hero_card(traces),
            "attack_section": attack_section(traces),
            "summary_rows": summary_rows(results),
            "result_rows": result_rows(results),
            "mandate_legend": mandate_legend(traces),
            "versions": versions(traces),
            "trace_data": embed_json(trimmed(traces)),
        },
    )
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    (out / "index.html").write_text(page)
    (out / "style.css").write_text(minify_css((root / "website" / "style.css").read_text()))
    shutil.copyfile(root / "website" / "replay.js", out / "replay.js")
    # GitHub Pages: serve files as they are, no Jekyll processing.
    (out / ".nojekyll").write_text("")


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: build_site.py OUT_DIR", file=sys.stderr)
        return 2
    out = Path(argv[0])
    build(out)
    size = sum(f.stat().st_size for f in out.rglob("*") if f.is_file())
    print(f"wrote {out} ({size:,} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
