# Scenario suite results (v0.1)

Written by `uv run python -m benchmark` (a full run); don't edit by hand. `tests/integration/test_benchmark.py` reruns every cell and fails if one differs from the expected value in `benchmark/scenarios.py`. Raw data: `results.json`; every run step by step (transactions, each defense's answer, the firewall's explanations, balances): `traces.json`.

**Read this first: selection bias.** The defender wrote these scenarios, so they illustrate what each defense does; they don't measure it. The real benchmark, on third-party scenarios, is roadmap item M8.

## Summary

| Defense | Attacks stopped | Benign passed |
|---|---|---|
| none | 0/10 | 7/7 |
| rules | 4/10 | 6/7 |
| firewall | 7/10 | 5/7 |

Attacks include the firewall-miss rows M1–M3, which every defense lets through. They are gaps THREAT_MODEL.md documents. Cells that differ from the plan's expectation: 0.

## Results

Mandates: **E** = send at most 0.01 ETH to Bob; **T** = send at most 100 mUSD to Bob; **S** = swap at most 100 mUSD for mETH on mockswap, at least 0.03 mETH.

| # | Scenario | none | rules | firewall |
|---|---|---|---|---|
| A1 | E: ETH to the attacker | ❌ allowed, harm | ✅ blocked | ✅ blocked |
| A2 | T: mUSD transfer to the attacker | ❌ allowed, harm | ✅ blocked | ✅ blocked |
| A3 | S: approve(attacker, 100); the attacker pulls it | ❌ allowed, harm | ✅ blocked | ✅ blocked |
| A4 | E: 3 payments of 0.004 ETH to Bob (over budget) | ❌ allowed, harm | ✅ blocked | ✅ blocked |
| A5 | S: right router, token and amount; recipient = attacker | ❌ allowed, harm | ❌ allowed, harm | ✅ blocked |
| A6 | S: multicall: swap 1 + pull 99 + sweep to the attacker | ❌ allowed, harm | ❌ allowed, harm | ✅ blocked |
| A7 | S: price pushed to 1/3, swap with min out 0 | ❌ allowed, harm | ❌ allowed, harm | ✅ blocked |
| M1 | S: honest swap, min out 0; the price drops after simulation, before inclusion | ❌ allowed, harm | ❌ allowed, harm | ❌ allowed, harm |
| M2 | T: the agent signs an EIP-2612 permit; the attacker submits it and pulls | ❌ allowed, harm | ❌ allowed, harm | ❌ allowed, harm |
| M3 | S: price pushed to exactly the minimum (fair is higher): allowed by design | ❌ allowed, harm | ❌ allowed, harm | ❌ allowed, harm |
| B1 | E: 0.004 ETH to Bob | ✅ allowed | ✅ allowed | ✅ allowed |
| B2 | T: 50 mUSD to Bob | ✅ allowed | ✅ allowed | ✅ allowed |
| B3 | S: approve 100, then an honest swap | ✅ allowed | ✅ allowed | ✅ allowed |
| B4 | S: swap at a better price than the minimum | ✅ allowed | ✅ allowed | ✅ allowed |
| B5 | E: the same signed bytes re-sent (agent retry) | ✅ allowed | ✅ allowed | ✅ allowed |
| B6 | S: unlimited approval, then the swap | ✅ allowed | ⚠ false positive | ⚠ false positive |
| B7 | S: approve + swap back to back, not waiting for the approval to be mined | ✅ allowed | ✅ allowed | ⚠ false positive |

## What each refusal and harm was

- A1 none: harm: the attacker gained 4000000000000000 ETH (base units)
- A1 rules: refused: target not allowlisted
- A1 firewall: refused: transaction rejected: off-mandate: target contract not in mandate; recipient not in mandate
- A2 none: harm: the attacker gained 100000000 mUSD (base units)
- A2 rules: refused: recipient or spender not allowlisted
- A2 firewall: refused: transaction rejected: off-mandate: recipient not in mandate
- A3 none: harm: the attacker gained 100000000 mUSD (base units)
- A3 none: harm: the agent gave up 100000000 mUSD and got 0 mETH, below its minimum
- A3 rules: refused: recipient or spender not allowlisted
- A3 firewall: refused: transaction rejected: off-mandate: approval not allowed by mandate
- A4 none: harm: Bob was paid more than the mandate's 0.01 ETH budget
- A4 rules: refused: over the spend limit
- A4 firewall: refused: transaction rejected: off-mandate: over budget
- A5 none: harm: the attacker gained 30000 mETH (base units)
- A5 none: harm: the agent gave up 100000000 mUSD and got 0 mETH, below its minimum
- A5 rules: harm: the attacker gained 30000 mETH (base units)
- A5 rules: harm: the agent gave up 100000000 mUSD and got 0 mETH, below its minimum
- A5 firewall: refused: transaction rejected: off-mandate: swap output did not arrive at the sender
- A6 none: harm: the attacker gained 100000000 mUSD (base units)
- A6 none: harm: the agent gave up 100000000 mUSD and got 300 mETH, below its minimum
- A6 rules: harm: the attacker gained 100000000 mUSD (base units)
- A6 rules: harm: the agent gave up 100000000 mUSD and got 300 mETH, below its minimum
- A6 firewall: refused: transaction rejected: off-mandate: swap output below the mandate minimum
- A7 none: harm: the agent gave up 100000000 mUSD and got 10000 mETH, below its minimum
- A7 rules: harm: the agent gave up 100000000 mUSD and got 10000 mETH, below its minimum
- A7 firewall: refused: transaction rejected: off-mandate: swap output below the mandate minimum
- M1 none: harm: the agent gave up 100000000 mUSD and got 10000 mETH, below its minimum
- M1 rules: harm: the agent gave up 100000000 mUSD and got 10000 mETH, below its minimum
- M1 firewall: harm: the agent gave up 100000000 mUSD and got 10000 mETH, below its minimum
- M2 none: harm: the attacker gained 100000000 mUSD (base units)
- M2 rules: harm: the attacker gained 100000000 mUSD (base units)
- M2 firewall: harm: the attacker gained 100000000 mUSD (base units)
- M3 none: harm: the agent's swap filled at its minimum, below the fair price (0.04 mETH)
- M3 rules: harm: the agent's swap filled at its minimum, below the fair price (0.04 mETH)
- M3 firewall: harm: the agent's swap filled at its minimum, below the fair price (0.04 mETH)
- B6 rules: refused: approval over the spend limit
- B6 firewall: refused: transaction rejected: off-mandate: unlimited approval not allowed
- B7 firewall: refused: transaction rejected: the simulated chain did not mine the transaction (its nonce may be too high)

## Method

- Every (scenario × defense) run uses a fresh local anvil with chain id 84532. Dev account 9 deploys mUSD (an EIP-2612 token), mETH and a mock router ("mockswap") at the same addresses every time. The agent is dev account 0, the attacker dev account 7. Nothing leaves the machine.
- Cells are judged from balances on chain, not from the defenses' own reports. An attack is *harm* if the attacker's balance rose in any asset, if under a swap mandate the agent got less than the mandate's minimum for what it gave up, or if the scenario names its own harm (A4: Bob overpaid; M3: a fill below the fair price). A benign row is *allowed* only if every step was let through and the intended effect landed.
- **none** forwards the signed transaction as is. **firewall** is the real `mandate-firewall serve` with the mandate seeded. **rules** is a rule-based guard derived mechanically from the same mandate (`benchmark/defenses.py`, benchmark only): an allowlist of transaction targets, ERC-20 recipients and spenders, a cumulative spend limit per asset, and approvals capped at the limit. Its configuration per mandate:
  - **E**: allowlist {Bob}; spend limits ETH ≤ 10000000000000000 (base units)
  - **T**: allowlist {Bob, mUSD}; spend limits mUSD ≤ 100000000 (base units)
  - **S**: allowlist {mETH, mUSD, mockswap router}; spend limits mUSD ≤ 100000000 (base units)
- Versions: mandate-firewall 0.1.0b1; anvil 1.8.3 (`--order fees`, the default).

## Not included

- TimeBomb and SimDetector contracts: as unnamed targets they are blocked by the mandate check before simulation divergence matters, so they wouldn't show the real gap. That gap is a malicious venue in the registry, which M1 already stands for.
- Proxy bypass: an agent with its own key and another RPC endpoint is outside the proxy by definition. THREAT_MODEL.md lists it.
