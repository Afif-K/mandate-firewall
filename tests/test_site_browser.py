"""The website in a real browser (headless Chrome).

- It never scrolls sideways: at each width, the built page's scrollWidth
  fits its viewport, and every table fits its box. Only code blocks may
  scroll, inside their own box, never the page.
- The recorded-runs player, driven through every step of every run: the
  "Recorded run, not live" banner is visible at each step, and every value
  the player shows matches the full traces.json (the same check
  tests/test_site.py runs on the builder's values).

Runs the real page in headless Chrome. A harness page (no CSP of its own)
loads the site in same-origin iframes of each width, measures each one,
and writes the result into the DOM, which `--dump-dom` prints. Standard
library only. Skipped if no Chrome is found, unless REQUIRE_BROWSER=1:
then a missing browser fails the run, as REQUIRE_FOUNDRY does for anvil.
"""

import functools
import html
import http.server
import json
import os
import re
import shutil
import subprocess
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tests.test_site import TRACES, load_builder, shown

WIDTHS = (360, 375, 768, 1280)
MAC_CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

HARNESS = """<!doctype html><meta charset="utf-8">
<style>iframe { border: 0; height: 900px; display: block; }</style>
<body><script>
const widths = WIDTHS_JSON, out = {};
let pending = widths.length;
for (const w of widths) {
  const frame = document.createElement("iframe");
  frame.style.width = w + "px";
  frame.src = "site/index.html";
  frame.onload = () => {
    const doc = frame.contentDocument, root = doc.documentElement;
    const viewport = root.clientWidth;
    // For the failure message: elements that reach past the viewport and
    // aren't inside a box that scrolls or clips them.
    const clipped = (e) => {
      for (let p = e.parentElement; p && p !== doc.body; p = p.parentElement) {
        if (getComputedStyle(p).overflowX !== "visible") return true;
      }
      return false;
    };
    const wide = [...doc.body.querySelectorAll("*")]
      .filter((e) => e.getBoundingClientRect().right > viewport + 0.5 && !clipped(e))
      .slice(0, 5)
      .map((e) => e.tagName.toLowerCase() + (e.className ? "." + e.className : ""));
    // Tables must fit too: only code blocks may scroll inside their box.
    const tables = [...doc.querySelectorAll(".table-scroll, .table-frame")]
      .filter((box) => box.scrollWidth > box.clientWidth)
      .map((box) => box.querySelector("table").className);
    out[w] = { scroll: root.scrollWidth, viewport, wide, tables };
    if (--pending === 0) {
      const pre = document.createElement("pre");
      pre.id = "result";
      pre.textContent = JSON.stringify(out);
      document.body.append(pre);
    }
  };
  document.body.append(frame);
}
</script></body>
"""


PLAYER_HARNESS = """<!doctype html><meta charset="utf-8">
<style>iframe { border: 0; width: 1000px; height: 900px; }</style>
<body><iframe src="site/index.html"></iframe><script>
const frame = document.querySelector("iframe");
frame.onload = () => {
  const doc = frame.contentDocument, win = frame.contentWindow;
  const select = doc.getElementById("run-scenario"), next = doc.getElementById("run-next");
  const banner = doc.getElementById("run-banner"), states = [];
  const fire = (el) => el.dispatchEvent(new win.Event("change", { bubbles: true }));
  const grab = (scenario, defense) => {
    const box = banner.getBoundingClientRect();
    states.push({
      scenario, defense, pos: doc.getElementById("run-pos").textContent,
      banner: banner.textContent, bannerShown: !banner.closest("[hidden]") && box.height > 0,
      values: [...doc.querySelectorAll("#player [data-src]")]
        .filter((e) => !e.closest("select"))
        .map((e) => [e.dataset.src, e.dataset.fmt || "", e.textContent]),
    });
  };
  for (const option of select.options) {
    select.value = option.value;
    fire(select);
    for (const radio of doc.querySelectorAll("input[name=run-defense]")) {
      radio.checked = true;
      fire(radio);
      for (let guard = 0; guard < 50; guard++) {
        grab(option.value, radio.value);
        if (next.disabled) break;
        next.click();
      }
    }
  }
  const options = [...select.options].map((o) => [...o.querySelectorAll("[data-src]")]
    .map((e) => [e.dataset.src, "", e.textContent]));
  const pre = document.createElement("pre");
  pre.id = "result";
  pre.textContent = JSON.stringify({ states, options });
  document.body.append(pre);
};
</script></body>
"""


def find_chrome() -> str | None:
    configured = os.environ.get("CHROME_PATH")
    if configured:
        return configured
    for name in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser"):
        found = shutil.which(name)
        if found:
            return found
    return MAC_CHROME if Path(MAC_CHROME).exists() else None


@pytest.fixture(scope="module")
def chrome() -> str:
    found = find_chrome()
    if found is None:
        if os.environ.get("REQUIRE_BROWSER") == "1":
            raise pytest.UsageError("REQUIRE_BROWSER=1 but no Chrome was found (set CHROME_PATH)")
        pytest.skip("no Chrome found (set CHROME_PATH)")
    return found


@pytest.fixture(scope="module")
def served(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    """The built site and the harness, on a loopback port."""
    root = tmp_path_factory.mktemp("layout")
    load_builder().build(root / "site")
    (root / "harness.html").write_text(HARNESS.replace("WIDTHS_JSON", json.dumps(WIDTHS)))
    (root / "player.html").write_text(PLAYER_HARNESS)
    handler = functools.partial(QuietHandler, directory=str(root))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/harness.html"
    finally:
        server.shutdown()
        server.server_close()


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib's name
        pass


def measure(chrome: str, url: str, profile: Path) -> Any:
    argv = [
        chrome,
        "--headless=new",
        "--disable-gpu",
        "--hide-scrollbars",
        "--no-first-run",
        f"--user-data-dir={profile}",
        "--window-size=1400,1000",
        "--virtual-time-budget=5000",
        "--dump-dom",
        url,
    ]
    done = subprocess.run(argv, capture_output=True, text=True, timeout=60, check=True)  # noqa: S603
    found = re.search(r'<pre id="result">(.*?)</pre>', done.stdout, re.DOTALL)
    assert found, "the harness wrote no result (did the page load?)"
    return json.loads(html.unescape(found.group(1)))


def test_the_page_never_scrolls_sideways(chrome: str, served: str, tmp_path: Path) -> None:
    results = measure(chrome, served, tmp_path / "profile")
    assert sorted(int(w) for w in results) == sorted(WIDTHS)
    too_wide = {
        w: r
        for w, r in results.items()
        if int(r["scroll"]) > int(r["viewport"])  # type: ignore[call-overload]
    }
    assert not too_wide, f"the page scrolls sideways: {too_wide}"


def test_every_table_fits_without_scrolling(chrome: str, served: str, tmp_path: Path) -> None:
    results = measure(chrome, served, tmp_path / "profile")
    scrolling = {w: r["tables"] for w, r in results.items() if r["tables"]}
    assert not scrolling, f"tables that scroll sideways, by width: {scrolling}"


def test_the_player_shows_every_step_of_every_run_as_recorded(
    chrome: str, served: str, tmp_path: Path
) -> None:
    result = measure(chrome, served.replace("harness.html", "player.html"), tmp_path / "profile")
    states = result["states"]
    # Every run, every step, plus its outcome.
    assert len(states) == sum(len(run["steps"]) + 1 for run in TRACES["runs"])
    visited = {(s["scenario"], s["defense"]) for s in states}
    assert visited == {(run["scenario"], run["defense"]) for run in TRACES["runs"]}
    checked = 0
    for state in states:
        where = f"{state['scenario']} {state['defense']} {state['pos']}"
        assert state["bannerShown"], f"{where}: the recorded-run banner is not visible"
        assert state["banner"].startswith("Recorded run, not live."), where
        assert state["values"], f"{where}: no values shown"
        for src, fmt, text in state["values"]:
            attrs = {"data-src": src} | ({"data-fmt": fmt} if fmt else {})
            assert text == shown(attrs), f"{where}: {src}"
            checked += 1
    for values in result["options"]:  # the scenario picker
        for src, _, text in values:
            assert text == shown({"data-src": src}), src
    assert checked > 1000
