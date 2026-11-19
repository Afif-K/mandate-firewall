// Recorded runs: replays benchmark/traces.json (embedded, trimmed) step by step.
// Every value shown is copied from that data and tagged with its source
// (data-src, a JSON pointer into the full traces.json), which tests/test_site_browser.py
// checks. Text is set with textContent only, never parsed as HTML.
"use strict";
(() => {
  const data = JSON.parse(document.getElementById("trace-data").textContent);
  const $ = (id) => document.getElementById(id);
  const player = $("player"), select = $("run-scenario"), card = $("run-step");
  const prev = $("run-prev"), next = $("run-next");
  const CELL = { blocked: "✓ Blocked", harm: "✗ Harm", "allowed, no harm": "? Allowed, no harm",
    allowed: "✓ Allowed", "false positive": "! False positive", failed: "✗ Failed" };
  const TONE = { blocked: "good", allowed: "good", harm: "bad", failed: "bad" };
  const names = Object.fromEntries(Object.entries(data.parties).map(([n, a]) => [a, n]));
  let run = 0, step = 0;

  // --- formatting (the test has its own copy of each rule) --------------------------
  const amount = (base, sym) => {
    const d = BigInt(data.assets[sym].decimals), v = BigInt(base), unit = 10n ** d;
    const frac = (v % unit).toString().padStart(Number(d), "0").replace(/0+$/, "");
    return `${v / unit}${frac ? "." + frac : ""} ${sym}`;
  };
  // after - before, signed: "−0.000267 ETH" (U+2212 minus), exact.
  const change = (after, before, sym) => {
    const d = BigInt(after) - BigInt(before);
    return (d < 0n ? "−" : "+") + amount((d < 0n ? -d : d).toString(), sym);
  };
  const FORMAT = {
    amount: (x, sym) => amount(x, sym),
    party: (x) => names[x] || x,
    answer: (x) => x[0].toUpperCase() + x.slice(1),
    cell: (x) => CELL[x],
  };

  // --- building nodes -----------------------------------------------------------------
  const el = (tag, cls, ...kids) => {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    for (const k of kids) e.append(k);
    return e;
  };
  // A value from the data, at JSON pointer `ptr`, optionally formatted.
  const val = (ptr, fmt, tag = "span", cls) => {
    let x = ptr.slice(1).split("/").reduce((o, k) => o[k], data);
    const e = el(tag, cls);
    e.dataset.src = "traces#" + ptr;
    if (fmt) {
      const [name, arg] = fmt.split(":");
      e.dataset.fmt = fmt;
      x = FORMAT[name](x, arg);
    }
    e.textContent = x;
    return e;
  };
  const p = (...kids) => el("p", null, ...kids);
  const isAddress = (x) => typeof x === "string" && /^0x[0-9a-fA-F]{40}$/.test(x);

  function callBlock(call, ptr) {
    const rows = el("dl", "args");
    for (const [name, x] of Object.entries(call.args)) {
      const at = `${ptr}/args/${name}`;
      let shown;
      if (Array.isArray(x)) {
        shown = el("div", "inner", ...x.map((c, i) => callBlock(c, `${at}/${i}`)));
      } else {
        shown = val(at, isAddress(x) ? "party" : null);
      }
      rows.append(el("dt", null, name), el("dd", null, shown));
    }
    return el("div", "call", el("code", null, val(`${ptr}/function`)), rows,
      ptr.endsWith("/call") ? el("p", "units", "Numbers as signed: in base units.") : "");
  }

  function located(s, ptr) {
    if (!s.mined) return [];
    return [p("Mined in block ", val(`${ptr}/mined/block`), ", position ",
      val(`${ptr}/mined/index`), ": ", val(`${ptr}/mined/status`), ".")];
  }

  // --- one step ---------------------------------------------------------------------
  const ACTOR = { agent: "Agent", market: "Market", attacker: "Attacker", chain: "Chain" };
  const DEFENSE = { none: "No defense", rules: "Rule-based guard", firewall: "Mandate firewall" };

  function stepView(r, i) {
    const s = data.runs[r].steps[i], ptr = `/runs/${r}/steps/${i}`;
    const body = [];
    let head;
    if (s.actor === "agent" && s.action === "sign_permit") {
      head = "The agent signs a permit off-chain";
      body.push(p("No transaction, so no defense in front of the agent sees it. Spender: ",
        val(`${ptr}/spender`, "party"), ", amount ", val(`${ptr}/value`), " base units of ",
        val(`${ptr}/token`, "party"), "."));
    } else if (s.actor === "agent") {
      head = s.action === "resend" ? "The agent re-sends the same signed bytes"
        : "The agent sends a transaction";
      body.push(p("To ", val(`${ptr}/to`, "party"), s.value !== "0" ? " with " : "",
        s.value !== "0" ? val(`${ptr}/value`, "amount:ETH") : ""));
      if (s.call) body.push(callBlock(s.call, `${ptr}/call`));
      body.push(el("p", "hash", "tx ", val(`${ptr}/tx_hash`)));
      const answer = el("div", `answer ${s.answer}`,
        el("h4", null, DEFENSE[data.runs[r].defense], ": ", val(`${ptr}/answer`, "answer")));
      if (s.reason) answer.append(p("Reason: ", val(`${ptr}/reason`)));
      if (s.upstream_error) answer.append(p("The node replied: ", val(`${ptr}/upstream_error`)));
      if (s.firewall && s.firewall.explanation) {
        answer.append(val(`${ptr}/firewall/explanation`, null, "pre", "explain"));
      } else if (s.firewall && s.firewall.reason) {
        answer.append(p("Firewall: ", val(`${ptr}/firewall/reason`)));
      }
      body.push(answer, ...located(s, ptr));
    } else if (s.actor === "market") {
      head = "The market moves the price";
      body.push(p("mUSD → mETH rate set to ", val(`${ptr}/rate/0`), "/", val(`${ptr}/rate/1`),
        s.outbid ? ", with higher fees than the agent's, so it is mined first." : "."),
        ...located(s, ptr));
    } else if (s.actor === "attacker") {
      head = "The attacker sends its own transaction";
      body.push(p("Straight to the chain: no defense stands between an attacker and the chain. To ",
        val(`${ptr}/to`, "party"), "."));
      if (s.call) body.push(callBlock(s.call, `${ptr}/call`));
      body.push(...located(s, ptr));
    } else {
      head = s.action === "mine" ? "A block is mined"
        : s.on ? "Automine back on" : "Automine off: transactions wait in the pool";
    }
    return [head, ACTOR[s.actor], body];
  }

  function outcomeView(r) {
    const run = data.runs[r], ptr = `/runs/${r}`, body = [];
    body.push(el("p", `run-verdict ${TONE[run.cell] || "warn"}`, val(`${ptr}/cell`, "cell")));
    if (run.harms.length) {
      body.push(el("ul", "harms", ...run.harms.map((_, i) => el("li", null, val(`${ptr}/harms/${i}`)))));
    }
    const rows = el("tbody");
    for (const [who, assets] of Object.entries(run.holdings_after)) {
      for (const sym of Object.keys(assets)) {
        const before = `${ptr}/holdings_before/${who}/${sym}`;
        const after = `${ptr}/holdings_after/${who}/${sym}`;
        const diff = el("span");
        diff.dataset.src = "traces#" + after;
        diff.dataset.base = "traces#" + before;
        diff.dataset.fmt = `change:${sym}`;
        diff.textContent = change(run.holdings_after[who][sym], run.holdings_before[who][sym], sym);
        rows.append(el("tr", null, el("th", null, who + " " + sym), el("td", "change", diff),
          el("td", null, val(before, `amount:${sym}`)), el("td", null, val(after, `amount:${sym}`))));
      }
    }
    const head = el("thead", null, el("tr", null, ...["Balance", "Change", "Before", "After"]
      .map((t) => el("th", null, t))));
    const table = el("table", "balances-table", head, rows);
    // Explicit roles: the phone layout restyles the rows (see the results table).
    table.setAttribute("role", "table");
    for (const e of table.querySelectorAll("thead, tbody")) e.setAttribute("role", "rowgroup");
    for (const e of table.querySelectorAll("tr")) e.setAttribute("role", "row");
    for (const e of table.querySelectorAll("thead th")) e.setAttribute("role", "columnheader");
    for (const e of table.querySelectorAll("tbody th")) e.setAttribute("role", "rowheader");
    for (const e of table.querySelectorAll("td")) e.setAttribute("role", "cell");
    body.push(el("div", "balances-scroll", table),
      el("p", "fine", "Balances that changed, exact. ETH changes include the gas each party paid."));
    return ["Outcome, judged from balances on chain", "Result", body];
  }

  // --- the player -------------------------------------------------------------------
  function show() {
    const r = data.runs[run], total = r.steps.length + 1;
    const [head, who, body] = step < r.steps.length ? stepView(run, step) : outcomeView(run);
    $("run-mandate").replaceChildren("Mandate ", r.mandate, ": ",
      val(`/mandates/${r.mandate}/instruction`, null, "q"));
    $("run-pos").textContent = `Step ${step + 1} of ${total}`;
    card.replaceChildren(el("p", "who", who), el("h3", null, head), ...body);
    prev.disabled = step === 0;
    next.disabled = step === total - 1;
    $("run-live").textContent = `Step ${step + 1} of ${total}: ${head}.`;
  }

  function pick() {
    const defense = document.querySelector("input[name=run-defense]:checked").value;
    run = data.runs.findIndex((r) => r.scenario === select.value && r.defense === defense);
    step = 0;
    show();
  }

  const seen = new Set();
  data.runs.forEach((r, i) => {
    if (seen.has(r.scenario)) return;
    seen.add(r.scenario);
    const o = el("option");
    o.value = r.scenario;
    o.append(val(`/runs/${i}/scenario`), ": ", val(`/runs/${i}/title`));
    select.append(o);
  });
  $("run-meta").replaceChildren("mandate-firewall ", val("/package_version"), ", ", val("/anvil"),
    ", local chain.");
  select.value = "A5";
  select.addEventListener("change", pick);
  for (const radio of document.querySelectorAll("input[name=run-defense]")) {
    radio.addEventListener("change", pick);
  }
  prev.addEventListener("click", () => { if (step > 0) { step--; show(); } });
  next.addEventListener("click", () => {
    if (step < data.runs[run].steps.length) { step++; show(); }
  });
  // Arrow keys step only while the step area itself has focus (click it or Tab to
  // it); everywhere else, including the buttons, they keep their usual meaning.
  card.addEventListener("keydown", (e) => {
    if (e.target !== card || e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
    if (e.key === "ArrowRight") next.click();
    else if (e.key === "ArrowLeft") prev.click();
    else return;
    e.preventDefault();
  });
  player.hidden = false;
  pick();
})();
