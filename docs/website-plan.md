# Project website plan (side task before the router calldata check)

Status: approved 2026-11-19, with the visual-design addition in §2. Commits follow §4, with an
OK between each.

## Context

v0.1 is public, but developers building AI agents find projects through a page they can read
in a minute, not an 18 KB README. The site's job: pitch in one line, show the attack that rules
miss, show the honest results (misses and false positives included), let people step through
**real recorded runs**, state the gaps, and send them to the quickstart.

Decision (2026-11-19): website first, as a side task. CLAUDE.md keeps "router calldata check"
as the current milestone and gets a one-line note about this side task. When the router check
lands and the suite is rerun, the site updates from the new data with no hand edits.

### Facts found while planning
- `benchmark/results.json` holds only cells, refusal reasons, harm sentences and the
  attacker's balance change. **It has no transactions, no explanations and no balances**, so
  requirement 3 can't be met from today's data. The suite must record more (commit 1).
- The firewall's full "You asked / This transaction" explanation, decoded call, effects and
  verdict already exist: in each run's audit log (`AuditRecord`, `src/mandate_firewall/audit.py`),
  which `benchmark/defenses.py:Firewall.submit` already reads, then the temp dir is deleted.
- Holdings for agent, Bob and attacker are already measured before and after every run
  (`benchmark/harness.py:holdings`), then thrown away except the attacker's delta.
- Not reproducible across runs: the mandate id (it hashes `created_at`, which is wall-clock
  time, `tests/mandates.py:mandate_with`), its expiry, and audit timestamps. Signed
  transactions should be reproducible (fixed nonce, fees and gas in `tests/integration/chain.py:sign`);
  commit 1 checks this rather than assuming it.
- `report.py` already follows the rule "files hold only what reruns reproduce"; the trace file
  follows it too.
- CI (`.github/workflows/ci.yml`) pins actions by SHA, `contents: read`, no credentials kept,
  and already runs the 51 suite cells on every push.

## Decisions after approval

- **2026-11-19, commit 3 (trimmed data, every shown value checked):** `traces.json` is
  155 KB (101 KB compact), so the page embeds a trimmed copy: null fields dropped, and
  only the balances that changed. It is a strict subset: lists keep their length and
  order, nothing is rewritten. `tests/test_site.py` checks that, and checks every value
  the page shows: each element the builder fills from a suite file carries `data-src` (a
  JSON pointer into the full `results.json` or `traces.json`), and the test resolves it
  and compares the text using its own formatting rules. The 150 KB budget is measured
  on raw bytes, not gzipped (the built site is 121 KB before the player).

## Pushback (built into the plan)

1. **"Real recorded runs" needs new suite output, and a test that keeps it honest.** Commit 1
   makes `python -m benchmark` write `benchmark/traces.json`; commit 2 makes each suite cell in
   CI compare its live trace with the committed one. A hand edit to `traces.json` then fails
   CI, which is a stronger guarantee than a "don't edit" comment.
2. **Volatile fields are replaced, and the site says so.** Mandate ids and timestamps change on
   every run, so the trace stores the mandate as `mandate E/T/S` and drops timestamps. The
   replay labels this: "The mandate id is shown as a label: the real one includes the time it
   was created." Everything else is byte-for-byte what the run produced.
3. **Call it "Recorded runs", not "interactive demo".** "Demo" suggests a live simulation. The
   section title, a banner on every step, and the footer say: recorded by the v0.1 scenario
   suite on a local anvil, firewall 0.1.0b1, anvil 1.8.3; how to regenerate it.
4. **No npm, no framework, no build toolchain.** Plain HTML, CSS and one small JS file; a
   stdlib-only Python script turns the suite's JSON into the page. No new dependencies, no
   supply chain beyond what the repo already has.
5. **No third-party requests at all**: no Google Fonts (system font stack), no CDN, no
   analytics. A `Content-Security-Policy` meta tag (`default-src 'self'`; Pages can't set
   headers) enforces it, and a test checks the built page has no external `src`. Honest
   footnote: GitHub, as the host, keeps its own server logs; we add nothing.
6. **The recorded data is rendered as text, never as HTML.** It is our own suite output, but
   the explanations quote addresses and reasons; `textContent` only, so a future scenario with
   odd strings can't inject markup.
7. **Don't name the directory `site/`**: a top-level `site` package would shadow Python's
   stdlib `site` module for scripts run from the repo root. Use `website/`.
8. **Hand-written prose can drift; generated numbers can't.** The pitch and the gaps are
   hand-written (short, linking to THREAT_MODEL.md and the README). Every number and table
   comes from `results.json`. A test checks the page's summary counts against it. CONTRIBUTING
   gets one line: changing THREAT_MODEL.md's top gaps means updating `website/`.
9. **Deploy only from `main`, only from CI.** The deploy job alone gets `pages: write` and
   `id-token: write`; the build job is read-only. The `github-pages` environment is limited to
   `main`. You enable Pages (Settings → Pages → Source: GitHub Actions) by hand; publishing is
   outward-facing, so the first deploy waits for your OK.

## 1. What the suite records (commits 1–2)

`benchmark/traces.json`, written by a full `uv run python -m benchmark` next to `results.json`,
one entry per (scenario × defense):

- `scenario`, `defense`, `mandate` (E/T/S), the mandate shown as `mandate.render` prints it
  (the same text `mandate new` shows), with the id replaced by its label.
- `steps`: every action in order, as the harness saw it:
  - agent submissions: tx hash, to, value, decoded call (function and arguments, from the
    existing decoder), and the defense's answer (forwarded / refused + reason). For the
    firewall: decision, reason, violation codes, the effects summary, and the explanation
    text from its audit record.
  - market and attacker actions (price moves, the attacker's `transferFrom`, the permit
    submission in M2), recorded by the `Run` methods that already perform them, so the replay
    can show "the firewall never saw this" honestly.
- `holdings_before` / `holdings_after` for agent, Bob and attacker in every asset (base units
  plus decimals, so the page formats them).
- `cell`, `harms`: copied from the same `Result`.

Changes: `Submission` gains the firewall's audit record (already read in `Firewall.submit`);
`Run` appends a step for each action; `Result` gains `trace`; `report.py` gains `to_traces()`
with the normalisation; `__main__.py` writes the file. The rule guard's and no-defense's
answers need nothing new.

## 2. The site (commits 3–6)

```
website/
  index.html.in   page skeleton with placeholders; hand-written pitch, gaps, get started
  style.css       mobile-first, light/dark via prefers-color-scheme, reduced motion
  replay.js       the recorded-runs player (~200 lines, no dependencies)
scripts/build_site.py   stdlib only: reads benchmark/results.json + traces.json, writes _site/
tests/test_site.py      builds into tmp_path and checks it
```

`_site/` is gitignored. The trace data is embedded in the page as
`<script type="application/json">`, so there's no fetch and the page works from `file://`.
Sections, in order:

1. **Pitch**: "Stops AI agents from sending onchain transactions you didn't authorize,
   including the ones that pass every spend limit and allowlist." Badge: v0.1 beta, testnets
   and local forks only. Buttons: Get started, GitHub.
2. **The attack rules miss** (A5): three columns built from A5's traces. You asked (mandate
   S) → the agent's transaction (right router, right token, 100 mUSD, recipient = attacker)
   → rules: allowed, attacker +0.03 mETH / firewall: blocked, with its real explanation.
   HTML and CSS, no image, so it reads on a screen reader and on a phone.
3. **Results**: the summary table and the 17-row table generated from `results.json`, with
   the same symbols plus text (never colour alone), misses M1–M3 and false positives B6–B7
   included, and the selection-bias sentence from RESULTS.md above the table.
4. **Recorded runs**: pick a scenario and a defense; step through with Next/Previous (buttons,
   arrow keys); each step shows the transaction, the defense's answer and the explanation;
   the last step shows balances before → after and the cell. Banner on every view: "Recorded
   run, not live". A live region announces each step. Without JS, the section shows the
   A5 firewall run as static text and a link to RESULTS.md.
5. **Known gaps**: the README's five, one sentence each, linking to THREAT_MODEL.md.
6. **Get started**: the four quickstart commands (clone, `uv sync`, `anvil`, `mandate new`)
   and a link to the README's quickstart. Footer: Apache-2.0, SECURITY.md, how the data was
   made, how this was built.

Performance budget: one HTML page, one CSS, one JS, no images, under 150 KB total.

### Visual design (added at approval, 2026-11-19)

The page is a first impression for developers and recruiters: polished and distinctive, not a
default template, within every constraint above (no framework, no external requests, 150 KB).

- **Typography**: the system font stack for text (`system-ui, -apple-system, "Segoe UI",
  Roboto, sans-serif`) and the system monospace stack (`ui-monospace, SFMono-Regular, Menlo,
  Consolas, monospace`) for addresses, hashes and explanations. A fluid type scale with
  `clamp()`: a large, tight-tracked hero headline, clear h2/h3 steps, body around 17–18 px,
  line length capped near 70 characters.
- **Colour**: one restrained identity, defined as CSS custom properties on `:root` and
  redefined under `prefers-color-scheme: dark`: a near-neutral ink/paper base, one accent for
  the brand and links, and two semantic colours kept apart from the accent: *blocked/safe*
  and *harm*, each always paired with a symbol and a word, never colour alone. All text
  pairs checked for WCAG AA contrast in both modes.
- **Hierarchy**: a hero that lands the pitch in seconds: the one-line headline, a short
  sub-line ("passes the spend limit, passes the allowlist, still not what you asked"), the
  beta/testnet badge, two buttons, and beside it (stacked on phones) a compact terminal-style
  card showing the real A5 firewall verdict from the trace: "You asked … / This transaction
  … / BLOCKED". Then generous section spacing, a consistent card style for the A5 comparison
  and the player, and tables styled for scanning (sticky first column on narrow screens,
  horizontal scroll inside the table only, never the page).
- **Detail**: subtle borders and shadows rather than heavy fills; a small inline SVG mark
  (a shield/gate glyph) and inline SVG favicon, both in the page, no image files; motion only
  for the player's step transitions, disabled under `prefers-reduced-motion`.
- Verified in commit 6 alongside Lighthouse: a look at 360 px, 768 px and 1280 px in both
  colour schemes, and screenshots for you to judge.

`tests/test_site.py` (runs in normal `pytest`, no anvil needed):
- the summary numbers on the page equal those computed from `results.json`;
- every (scenario × defense) in `results.json` has a trace, with the same cell;
- no `http(s)://` in any `src=` attribute; the CSP meta is present; links only to github.com;
- the build is deterministic (two builds, identical bytes).

## 3. Deployment (commit 7)

`.github/workflows/pages.yml`:
- triggers: push to `main` touching `website/**`, `benchmark/*.json`, `scripts/build_site.py`
  or the workflow; and `workflow_dispatch`.
- `permissions: {}` at the top; job `build` gets `contents: read`: checkout
  (`persist-credentials: false`), setup-uv, `uv sync --locked`, `uv run pytest tests/test_site.py`,
  `uv run python scripts/build_site.py _site`, `actions/upload-pages-artifact`.
- job `deploy` (needs build) gets `pages: write` + `id-token: write`, environment
  `github-pages`: `actions/deploy-pages`.
- every action pinned to a full commit SHA with the release in a comment, as in ci.yml. The
  SHAs are looked up with `gh api repos/<owner>/<action>/git/ref/tags/<tag>` when writing the
  commit, not guessed; checkout and setup-uv reuse ci.yml's pins.
- concurrency group `pages`, `cancel-in-progress: false` (a half-finished deploy isn't
  cancelled).
- ci.yml: add `website` to the wheel's stray-path check.

## 4. Commit sequence and how you verify each

| # | Commit | How you verify it |
|---|---|---|
| 0 | Add the website plan (`docs/website-plan.md`); CLAUDE.md: side-task note | Read it. |
| 1 | Record per-run traces in the scenario suite; write `benchmark/traces.json` | `uv run python -m benchmark` twice; after the second, `git diff --exit-code benchmark/` is clean (proves reruns reproduce). Read A5's firewall trace: its explanation should match what `--keep` + `mandate-firewall alerts` shows for that run. `results.json` and `RESULTS.md` unchanged. |
| 2 | Each suite cell checks its trace against the committed `traces.json` | `uv run pytest -m benchmark` passes. Change one digit in `traces.json`; the matching cell fails; `git checkout` it. |
| 3 | Site skeleton and builder: pitch, results tables, known gaps, get started | `uv run pytest tests/test_site.py`; `uv run python scripts/build_site.py _site && python -m http.server -d _site`; open it, compare the tables with RESULTS.md. |
| 4 | The A5 "rules miss, firewall catches" section from its traces | Reload; numbers and explanation match RESULTS.md's A5 lines; read it at 360 px width (DevTools device mode). |
| 5 | Recorded-runs player | Step through A5, M1, M2, B7 under each defense with the keyboard only; turn JS off and see the static fallback; check the "recorded" banner on every step. |
| 6 | Accessibility, mobile and performance pass; CSP | Chrome DevTools Lighthouse (built in, nothing to install): Accessibility and Best Practices 100, Performance ≥ 95 on mobile; VoiceOver reads the A5 section and a replay step; DevTools Network shows only same-origin requests, Console shows no CSP errors. |
| 7 | Pages workflow (hardened) and ci.yml wheel-check update | Read the workflow (permissions per job, SHAs); push; CI and the `build` job pass. Enable Pages → Source: GitHub Actions; then, with your OK, run the deploy and open `https://afif-k.github.io/mandate-firewall/`. Check the `github-pages` environment allows only `main`. |
| 8 | README and pyproject: link the site; CONTRIBUTING: the drift note | Links work on GitHub's rendered README. |

## Out of scope
A custom domain, a blog, a docs site (the README is the docs), a live in-browser simulation,
any form or email capture, analytics of any kind.
