# M4 plan: the verifier

Status: **approved 2026-11-07; done 2026-11-10** (commits 0–7, 9, 10; commit 8 deferred, see §9). Corrections made during implementation are marked *Changed in commit N*.

## Decisions (agreed 2026-11-07)

1. **The deterministic matcher decides; the LLM never does** (carried over from M3 Decision 7). The matcher compares a transaction's simulated effects with its mandate and returns allow, block or escalate. See §2.
2. **Escalate means block now and alert loudly. There is no hold queue.** A human never approves or releases a single transaction. They act on the *mandate*: revoke it, or lock a new one. In M4, alerts go to the audit record, the operator log and a `mandate-firewall alerts` command. Push channels (Slack, Telegram, webhook) are M6. See §3.
3. **Budgets are charged when a transaction is forwarded, and pending replay is deferred to M6.** Charging at forward time makes budget accounting independent of whether a transaction is mined, so it needs no pending state. Nonce n+1 sent before n is mined is still blocked, as in M2. See §4.
4. **Explanations in the proxy are deterministic only.** A template renders "You asked: X. This transaction does: Y." from structured violations. An LLM explainer is optional, done last if time allows (commit 8): an on-demand CLI command outside the proxy that never sees hex. See §5.
5. **A swap minimum is required at capture** (commit 9). The compiler asks for one instead of adding a note. Mandates already stored without one keep working under the `bought > 0` rule, and THREAT_MODEL.md documents why that's weak. See §6.
6. **The agent gets violation codes and facts about its own transaction, never mandate values** (no budgets, remaining amounts or swap minimums). The full explanation goes to the audit record and the operator. See §5.

## Context

M1 built the choke point, M2 measures what each transaction does (`Effects`), and M3 locks what the user asked for (`Mandate`) and blocks senders without one. Nothing compares the two yet. `scripts/demo_m3.sh` step 6 shows the gap on purpose: with a mandate for "send 0.01 ETH to Bob", a transfer to `0x…dEaD` is forwarded and charged. M4 closes that gap.

Code M4 builds on:
- `models.py`: `Effects` and its parts (`NativeBalanceChange`, `TokenTransfer`, `TokenApproval`, `OperatorApproval`, `CallFrame`, `RawLog`, `TokenStateCheck`), and `Decision`.
- `mandate/models.py`: `Mandate`, `TransferIntent`, `SwapIntent`, `Ratio`, `Budget`.
- `mandate/store.py`: `record_transaction` (check and charge in `BEGIN IMMEDIATE`), the counters-only authorizer, and `counters` keyed by `(mandate_id, period_start)`.
- `mandate/render.py`: `format_units`, `safe_text`, registry names, full addresses. Reused for explanations.
- `mandate/registry.py`: `symbol_for(address)` and venue lookups.
- `proxy/app.py`, `_send_raw_transaction`: simulate → `record_transaction` → audit → forward. The verifier goes between simulate and charge.

---

## 1. The transaction's effects on the principal

The mandate says what may leave **one account**, the principal (the agent's wallet). So step one turns `Effects` into the principal's own movements of money, called **flows**:

- **ETH.** The principal is an EOA (a plain key-controlled account with no code), so ETH can leave it only through the transaction's own `value` (call frame depth 0) and the gas fee. ETH can arrive through any frame whose target is the principal, for example a router that unwraps WETH and sends ETH back. M2 measures the real balance change, so the arithmetic can be checked exactly:
  `measured_delta == inflows_from_frames − tx_value − gas_cost`.
  If it doesn't hold, something moved ETH that the trace doesn't explain (for example, EIP-7702 delegated code on the account). That's an anomaly (§3).
- **Tokens.** Every `TokenTransfer` with `sender == principal` is an outflow, and every one with `recipient == principal` is an inflow, per token and per counterparty. These are events, which means *claims*, so they're trusted only when the matching `TokenStateCheck` is `consistent`. M2 plans a balance check for every address named in a Transfer, so the principal always has one.
- **Approvals.** Every `TokenApproval` and `OperatorApproval` with `owner == principal`.

Example. "Pay Bob 0.004 ETH" gives `{ETH: out 0.004 to Bob}`. A Uniswap swap of 100 USDC gives `{USDC: out 100 to <pool>, WETH: in 0.031 from <pool>}`.

## 2. Matching flows against intents

The matcher takes `(mandate, spent so far, effects, tx.to, tx calldata empty?)` and returns a `Verdict`: a decision, a list of **violations** (clearly off-mandate), a list of **anomalies** (the firewall can't fully interpret the effects), and the **charges** against each intent's budget. It is pure: no I/O, no clock, no registry. Its only inputs are the mandate (trusted) and effects (hex and addresses only, no free text, per M2).

Rules, applied to every transaction:

1. **Allowed top-level targets.** `tx.to` must be something the mandate names: the asset contract of a token transfer intent, the recipient of an ETH transfer intent, a venue of a swap intent, or the sell token of a swap intent (to approve the venue). Anything else is a violation: "calls a contract your mandate doesn't name". Contract creation (`to = None`) and calls to the principal itself are violations too. *Why, when effects are checked anyway:* many harmful state changes produce no token flow at all, such as setting a governance delegate, transferring ownership of a contract or registering a name. Restricting the *entry point* bounds what a transaction can touch. Contracts deeper in the call tree (Uniswap pools under the router) are allowed: the venue chose them, and the venue is trusted through the registry.
2. **ETH to a recipient carries no calldata.** "Send ETH to X" doesn't mean "call X". If X is a contract, calldata could make it act with `msg.sender = principal`.
3. **Transfers.** For a transfer intent on asset T to recipient R, every outflow of T must go to R. The charge is the **gross** outflow (outflows added up, not net of inflows), and `spent + charge ≤ budget.max`.
   Example: the mandate is 0.01 ETH to Bob, with 0.004 already spent. 0.006 to Bob is allowed and spends the budget exactly. 0.007 is over budget. 0.001 to `0x…dEaD` goes to the wrong recipient.
4. **Swaps.** For a swap intent selling S for B via venues V:
   - An outflow of S counts toward the swap **only if `tx.to ∈ V`**. This corrects a line in the M3 table (docs/m3-plan.md §1): the outflow's *recipient* is not checked against the venues. With SwapRouter02, the principal's USDC goes straight to the **pool** (the router calls `transferFrom(principal → pool)` in the swap callback), not to the router. "The money must go to a venue" would block every real swap. The check is that the principal *called* a venue.
   - S sent to a venue by a direct token `transfer` (with `tx.to` = the token) is a violation. Tokens sitting in the router outside a swap can be swept by anyone.
   - The charge is the **net** outflow of S in this transaction, so router refunds count back.
   - **Ratio minimum**, integers only, checked per transaction: `bought × denominator ≥ sold × numerator`, where `bought` is the principal's **gross** inflow of B. *Changed in commit 3* (the plan said net): if some of B leaves again in the same transaction, that outflow is matched (and charged, or refused) on its own under rule 6, like any other outflow, so netting it here would count it twice. Example: "at least 0.03 WETH for 100 USDC" is `Ratio(3·10^16, 10^8)`. A swap that sells 10^8 base units and receives 2.99·10^16 fails, because 2.99·10^16 × 10^8 < 10^8 × 3·10^16. Receiving exactly 3·10^16 passes: the boundary is inclusive. The check is per transaction, not cumulative, because a cumulative check would let one good fill pay for a bad one.
   - **Something must arrive:** `bought > 0` whenever `sold > 0`, even with no minimum (the implicit "bought asset arrives at the principal" rule from M3). This catches the headline attack, a real Uniswap swap with `recipient = attacker`: the principal sells 100 USDC and gets 0 WETH.
   - If the sell assets of two different swap intents leave in one transaction, that's a violation: it's ambiguous which budget is spent.
5. **Approvals (enablers).** An ERC-20 approval by the principal is allowed only if the token is a swap intent's sell asset, the spender is one of that intent's venues, the amount isn't `2^256−1`, and the amount is at most the intent's **remaining** budget after this transaction's charges. An approval to 0 (a revoke) is always allowed. ERC-721 approvals and `ApprovalForAll(approved=true)` by the principal are always violations.
   An approval doesn't spend budget; the swap that uses it does. Example: with a 100 USDC budget, `approve(router, 100)` is allowed, the swap spends 100, and a second `approve(router, 100)` exceeds the remaining 0.
6. **Nothing else may leave.** An outflow of any asset that no intent covers (another token, an NFT, ETH under a token-only mandate) is a violation. Inflows are always fine.

The decision: any anomaly → **escalate**. Otherwise any violation → **block**. Otherwise **allow**, with the charges.

## 3. Anomalies and escalation

| Situation | Verdict | Why |
|---|---|---|
| `TokenStateCheck.consistent == False` (any token) | escalate | A token's events disagree with its storage, so flows built from events can't be trusted. The known false positives (rebasing and fee-on-transfer tokens) err on the safe side. |
| An unrecognized log that **mentions the principal** (its address as a 32-byte word in the topics or the aligned data) and isn't on the informational list | escalate | It says something about this account that the firewall can't interpret: an ERC-1155 transfer, a Permit2 approval, a `DelegateChanged`, or a WETH `Withdrawal(src=principal)` (an outflow with no Transfer event). |
| An unrecognized log that doesn't mention the principal | allow, kept in the record | Pools and routers emit many such logs. Effects on the principal are covered by flows and state checks. |
| Informational events: the Uniswap V3 pool `Swap` (its `recipient` topic is the principal on every honest swap) and WETH9 `Deposit` | ignore | Without this list, every Uniswap swap would escalate. The list lives in code with sources. It only ever *suppresses* an escalation; it never authorizes an outflow. |
| ETH arithmetic doesn't reconcile (§1), or a frame with `caller == principal` at depth ≥ 1, or a `DELEGATECALL` from the principal | escalate | The "EOA" is running code, for example EIP-7702 delegation set outside the firewall. |
| Contracts created anywhere in the call tree | escalate | No supported intent creates contracts. |
| A top-level target the mandate doesn't name ("unregistered contract") | block | Clearly off-mandate (rule 2.1), nothing ambiguous. |
| The matcher raises (a bug) | block, "verification failed: internal error" | Fail closed, like the simulator. |

**Escalation without a per-transaction human (Decision 2).** Escalate means **blocked now**, plus a louder alert. It never means "held until someone approves". Why:
- A hold queue makes the human a per-transaction approver. That's the confirmation fatigue THREAT_MODEL.md warns about, and it breaks "transaction-time decisions are fully automated" (M3 Decision 8).
- An attacker who can trigger anomalies at will could train the human to click "approve".
- Approving later means forwarding stale signed bytes, whose nonce and fees may no longer fit.

The human acts on the **mandate**, never on the transaction. After an alert they revoke the mandate, or lock a new one (for example, after a missing venue has been added to the registry). That happens at capture, when they're present and reading anyway. The agent gets `-32003` for both block and escalate. The M4 alert channels:
- `decision: "escalate"` in the audit record;
- a WARNING line in the operator log with the deterministic explanation;
- `mandate-firewall alerts`, which lists blocks and escalations from the audit log.

## 4. Budget accounting across transactions

- **Ledger.** A new `spending` table, `(mandate_id, period_start, intent_index, spent)`, next to `counters` with the same period key. M5's per-period budgets then add rows, not columns. `intent_index` is the intent's position in `intents`, which the hash fixes.
- **uint256 in SQLite.** SQLite integers are 64-bit, so `spent` is stored as a **32-byte big-endian BLOB**. SQLite compares BLOBs with `memcmp`, which for fixed-length big-endian bytes is numeric order. So the "only goes up" trigger stays one line (`NEW.spent < OLD.spent → ABORT`), plus `CHECK (length(spent) = 32)`. A decimal string would sort "9" after "10".
- **Charging stays atomic.** `record_transaction(mid, charges)` does everything inside the existing `BEGIN IMMEDIATE`: re-check the status, check `spent + charge ≤ max` for each charge, check the approval constraints ("remaining ≥ approved amount after the charges"), add the charges and increment the transaction counter. The matcher read `spent` before simulation, and a concurrent transaction may have charged since, so the store's re-check is authoritative, exactly like the M3 transaction cap. Two transactions racing for the last 0.006 ETH can't both get it. Over budget → `BudgetExceededError` → block.
- **Exhausted** also when every intent's budget is fully spent, not only at the transaction cap.
- **Partial use** leaves a remaining budget. Example: a 100 USDC swap budget; the first swap sells 40, so 60 remain, and an approval above 60 is blocked.
- **Charged at forward, not at mining (Decision 3).** A forwarded transaction that later fails on chain still spends its budget. That fails closed (the agent can do less), matches how M3 charges slots, and means budgets need no pending state.
- **Re-sends.** Agents retry, and sending the *same signed bytes* again would simulate and charge twice. M4 records the hashes of charged transactions. A re-send of a hash already charged under a still-active mandate is forwarded without a new charge or re-simulation, and audited as `resend`. That's safe because identical bytes can be mined only once, so there is nothing new to check.
- **No pending replay (Decision 3).** Nonce n+1 sent before n is mined still fails simulation and is blocked (M2 behavior). Replaying unmined transactions on the fork would need tracking of dropped and replaced transactions and of stale entries, and budgets no longer depend on it. Most agent toolkits wait for a receipt between approve and swap. M6 revisits this with a real agent.

## 5. Explanations

**The proxy explains deterministically (Decision 4).** Each `Violation` and `Anomaly` is structured: a code plus the asset, amount, counterparty and limit. A template turns it into the "You asked: X. This transaction does: Y." diff. "You asked" reuses `render.py`'s mandate lines, and "does" comes from the flows. Names come from the registry; anything unregistered shows as `UNREGISTERED TOKEN 0x…` with the full address. Amounts are exact, formatted with integers. Example for demo step 6:

```
BLOCKED  tx 0x9c…  under mandate 3f2a…
You asked:        send at most 0.01 ETH to 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 (0.006 left)
This transaction: sends 0.001 ETH to 0x000000000000000000000000000000000000dEaD
Why: that recipient is not in your mandate. Nothing was charged.
```

Why no LLM in the proxy:
1. The template already says everything the matcher knows. An LLM can only rephrase it, or get it wrong, and a wrong "this looks like a legitimate swap" can lead the human to widen the mandate, the one decision they still make.
2. It would put the LLM client and API key into the proxy process, which M3's import-boundary tests forbid (M3 Decision 5).
3. Latency, cost and a new way to fail on the transaction path.

**Optional, done last (commit 8): `mandate-firewall explain <tx-hash>`.** It runs on the capture side, with the capture LLM client and key, and reads the audit record after the decision. Its input is built by a **whitelisting serializer**: the mandate, the structured violations, and flows with registry names, addresses and amounts. It **never** includes calldata, log data or topics, or revert data. An LLM decodes hex, so attacker bytes in a log are attacker text. Unrecognized logs appear only as "N unrecognized events from 0x…". The output is printed below the deterministic diff under the label "LLM summary, may be wrong", and is never written to the audit record or the store. It runs after the decision, in another process, so it can't influence one.

**What the agent is told (Decision 6).** The agent is untrusted. Its error message carries the violation *code* and facts about its own transaction ("recipient not in mandate", "over budget"), **never mandate values** (budgets, remaining amounts, the swap minimum). An attacker who learns the minimum can set the price to exactly that floor.

## 6. Swap minimums (Decision 5)

Rule 2.4 makes a swap **with** a minimum safe against value extraction. A swap **without** one isn't. SwapRouter02 has `multicall`, `pull` and `sweepToken`, so an injected agent can `pull(100 USDC)`, swap 1 wei of it for WETH to the principal, and `sweepToken(rest, attacker)`. The principal "sold 100 USDC and received WETH" through the right venue, and every rule passes.

So commit 9 changes the compiler: a swap without a minimum becomes a question ("at least how much WETH for 100 USDC?"), not a note, and the structured path requires `--min-out` (the existing flag; *changed in commit 9*, the plan said `--min`). Mandates already stored without a minimum keep working under the `bought > 0` rule, and THREAT_MODEL.md documents the gap.

## 7. Demo: step 6 becomes a block (`scripts/demo_m4.sh`)

The same skeleton as `demo_m3.sh`: its own anvil (chain 84532) and firewall on spare ports, a temporary directory, the cleanup trap, the structured path, no API key.

1. Lock "send at most 0.01 ETH to Bob, 4 transactions".
2. Start the firewall.
3. Pay Bob 0.004 → allowed. The audit shows a charge of 0.004, with 0.006 left.
4. **The old step 6:** 0.001 ETH to `0x…dEaD` → **blocked**. The agent gets `-32003 … off-mandate: recipient not in mandate`. The audit record has the "You asked / This transaction" diff and no charge. `cast balance` shows dEaD received nothing.
5. Pay Bob 0.007 → blocked, over budget (only 0.006 left).
6. Pay Bob 0.006 → allowed. The budget is spent, so the mandate is **exhausted** even though it has transactions left.
7. Swaps. The demo deploys two `MockERC20`s and a new `MockRouter` test contract (fixed rate, a `recipient` parameter, and `pull` + `sweep` like SwapRouter02) and points `REGISTRY_PATH` at a generated registry for them. It locks "swap 100 mUSD for mETH via mockswap, at least 0.03 mETH for 100 mUSD", then:
   - (a) `approve(router, 2^256−1)` → blocked, unlimited approval;
   - (b) `approve(router, 100)` → allowed;
   - (c) swap with `recipient = thief` → blocked, nothing arrived. This is **the within-policy, off-mandate attack**: right router, right token, right amount;
   - (d) swap at a bad rate → blocked, below the minimum;
   - (e) the `pull` + `sweep` drain of §6 in one `multicall` → blocked, below the minimum (*added in commit 10*);
   - (f) honest swap → allowed.
8. `mandate-firewall alerts` lists the blocks with their explanations.

## 8. What M4 does NOT solve (goes into THREAT_MODEL.md)

1. **Effects are only as true as the simulation.** State changes before inclusion, time bombs and simulation detection (the M2 limits) pass straight through the verifier.
2. **Stored swap mandates without a minimum** can be drained through router features (`pull`/`sweep`) or sandwiched. Only `bought > 0` holds for them.
3. **A minimum is a floor, not a fair price.** MEV can push a fill down to exactly the minimum.
4. **Residual allowances.** A partly used approval stays in place after the mandate ends. It's bounded by the budget and goes only to a registry venue, but nothing revokes it.
5. **Event-less movements and hidden mentions.** Tokens outside the registry that move balances without events, unrecognized logs that mention the principal in unaligned or packed data, and state changes at allowed targets that emit no events aren't seen.
6. **The registry and its venues are trusted completely.** Router features the mandate doesn't model are covered only by the flow rules.
7. **Budgets are charged at forward.** A transaction that fails on chain still spends its budget (fails closed).
8. **No pending replay.** Approve-then-swap still needs the approve mined first.
9. **Escalation isn't approval.** A blocked transaction can't be released; the human changes the mandate instead. Alerts reach only the audit log, the operator log and `alerts`. No push notifications yet.
10. **The block reason is an oracle.** An injected agent can probe the rules through violation codes (without mandate values). There's no rate limit or circuit breaker.
11. **False positives on unusual tokens** (rebasing, fee-on-transfer, ERC-1155, Permit2): they escalate.
12. **Off-chain signatures** stay invisible until M7.
13. **The `explain` output** (if built) can be wrong. It's labeled, kept out of the decision path, and gets no hex.

## 9. Commit sequence (OK between each)

Each commit: `uv run ruff check .`, `uv run pytest`, and `uv run pytest -m anvil` where integration code changes. No Co-Authored-By trailers.

0. **This plan** (`docs/m4-plan.md`). *Verify:* read-through.
1. **Verdict models and `Decision.ESCALATE`** (`verify/models.py`: `Flow`, `Violation` and `Anomaly` with code enums, `Charge`, `Verdict`). The audit record gains `verdict`. *Verify:* unit tests: frozen, `extra="forbid"`, every string field is hex, an address or an enum (the same "no free text" test as for effects), JSON round trip.
2. **Flows** (`verify/flows.py`, pure): Effects + principal → flows + anomalies (ETH reconciliation, signs of code execution, created contracts, inconsistent checks, unrecognized logs that mention the principal, the informational-event list with sources). *Verify:* table tests on hand-built Effects and the recorded M2 trace fixtures; a mutation pass as in M3.
3. **Matcher** (`verify/matcher.py`, pure): rules 2.1–2.6, budgets from a `spent` input. *Verify:* one test per rule and per attack: wrong recipient, over budget, exact budget, ETH with calldata, unnamed target, creation, swap to the attacker, `pull`+`sweep` without a minimum (passes, documented) and with one (blocked), the ratio boundary (equal passes, one wei below fails), unlimited, non-venue and over-remaining approvals, `ApprovalForAll`, a direct transfer to the router, two sell assets in one transaction, an uncovered token outflow. Mutation pass.
4. **Store v2: the spending ledger** (`spending` with BLOB uint256 and the up-only trigger, a charged-hash table, `record_transaction(mid, charges)`, exhausted when budgets are spent, the authorizer allows the new tables, migration v1→v2 by the CLI only, and the proxy refuses a v1 store with "run `mandate-firewall mandate list` to upgrade"). *Verify:* the forced-interleaving race test extended to budgets; triggers refuse a decrease; migration; counters-only still can't touch `mandates`; memcmp order at the 2^64 and 2^255 boundaries.
5. **Deterministic explanations** (`verify/explain.py`, reusing `render.py`). *Verify:* golden-string tests for each violation and anomaly code; full addresses; exact amounts; `UNREGISTERED` labels; a test that the agent-facing message contains no mandate values.
6. **`MockRouter` test contract** (`tests/fixtures/contracts/src/MockRouter.sol`, artifact via `build.py`). *Verify:* the artifact reproducibility test; an integration test that it swaps, pulls and sweeps.
7. **Proxy wiring**: the registry loads at startup (`REGISTRY_PATH` in `Settings`; refuse to start if it's invalid), verification after simulation and before the charge, escalate handling, re-send handling, the `alerts` CLI. M2 tests that relied on "anything goes" (such as `test_lying_token_is_forwarded_with_the_lie_on_record`) flip to expecting escalate or block, which is the point of M4. Their mandate fixtures are adjusted where they test something else. *Verify:* integration tests: off-mandate ETH blocked, never mined and not charged; exact and over budget; a race for the last budget; MockRouter scenarios a–e; the lying token escalates; a re-send isn't charged twice. Mutation pass on the wiring (verifier skipped, charge before verify, wrong budget column).
8. **(Optional; deferred, not built in M4) `mandate-firewall explain`** (capture side). *Verify:* the whitelisting serializer test (a sentinel in log data and revert data never reaches the prompt); the import-boundary tests still pass; one manual live run.
9. **Compiler: a swap minimum is required** (Decision 5). *Verify:* the compile table updated; the structured path needs `--min-out`; stored mandates without a minimum still load.
10. **Docs and demo**: THREAT_MODEL.md (§8, new protections 23+, M3's "Effects aren't checked" section rewritten), README, CLAUDE.md (M4 done), `scripts/demo_m4.sh`, and `demo_m3.sh` step 6 reworded (on M4 code it blocks). *Verify:* run `demo_m4.sh` end to end in a terminal; the full test suite; ruff.

Commits 8 and 9 may swap order: 9 is required, 8 is optional. *Outcome:* 9 was done after 7, then 10; 8 was skipped and stays optional for later.
