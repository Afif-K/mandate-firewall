# Threat model

Status: **v0.1 beta** (the verifier is Milestone 4's). This document describes
what the code in this repository does today, not what the project plans to do.
It is updated with every milestone. If you find a gap that isn't listed here,
please report it privately (see "Security" in the README), not in a public
issue.

## What the firewall is for

An AI agent with a wallet can be prompt-injected. Text it reads (a web page, a
token name, an email, a tool result) can make it send a transaction the user
never asked for. Spend limits and allowlists don't catch an injected transfer
that is under the limit and goes to an allowed contract. The goal of this
project is to check each transaction against the user's own instruction, the
*mandate*, and block anything that doesn't match.

M1 built the choke point: a JSON-RPC proxy that sees every transaction the
agent sends through it. M2 added simulation: every transaction is run on a
private fork of the chain before it's forwarded, and what it actually did
(its *effects*) is recorded. M3 added mandates: the user locks an instruction
with the capture CLI, and the proxy blocks every transaction from an account
that has no confirmed, unexpired mandate with transactions left.

M4 adds verification. A deterministic matcher compares each transaction's
simulated effects with its mandate: where money goes, how much of each
budget is left, which contracts are called, what comes back from a swap,
and which approvals are given. It allows the transaction, blocks it, or
escalates it (blocks it and raises an alert) when the effects contain
something it can't interpret. No LLM takes part in that decision. This is
what catches the *within-policy, off-mandate* transaction: a swap through
the right router, of the right token, within budget, whose output goes to
an attacker.

Verification is only as good as the effects it is given. Effects come from
a simulation, and a simulation can differ from what happens on chain. See
"Effects are only as true as the simulation" below.

v0.1 adds no new protection. It adds evidence: a scenario suite of 17
scenarios, each run on a fresh local chain against no defense, a rule-based
guard derived from the same mandate, and the firewall, with harm judged from
balances on chain ([benchmark/RESULTS.md](benchmark/RESULTS.md)). The
firewall stops 7 of 10 attacks and passes 5 of 7 benign flows. The three
attacks it misses are gaps this document already lists: a price move between
simulation and inclusion (scenario M1, "Simulation can differ from what happens on
chain"), an off-chain permit (scenario M2, "Off-chain signatures"), and a fill pushed
down to exactly the user's minimum (scenario M3, "A minimum is a floor, not a fair
price"). Its two false positives are an unlimited approval (blocked on purpose,
item 27) and an approve + swap sent without waiting for the approval to be
mined ("Multi-transaction flows"). The defender wrote these scenarios,
so they illustrate the defenses; they don't measure them.

## Actors and trust

| Actor | Trusted? | Notes |
|---|---|---|
| User | Yes | Gives the instruction to the capture CLI directly and confirms the summary. Can still be wrong or tricked: see "Confirmation fatigue" and "Poisoned instructions". |
| Operator / host machine | Yes | Runs the proxy, sets its config, owns the audit log. |
| The firewall's OS user | Yes | Owns the mandate store (`0600` in a `0700` directory). **Whoever can run as this user can create mandates.** See "Same-host compromise". |
| Capture LLM (optional) | **No** | Parses the instruction into a draft. Its output is checked like untrusted input: every value must appear in the user's words, and the user confirms the result. It never sees agent content and never decides on transactions. |
| LLM provider | Partly | Receives the instruction text when the LLM path is used. Not involved in transaction decisions. |
| Token and venue registry | Yes | Shipped per chain, or replaced by the operator (`REGISTRY_PATH`). Maps symbols to addresses. A wrong entry makes a wrong mandate, and since M4 every contract a venue lists is trusted to execute swaps honestly. |
| Verifier (matcher) | Yes | Deterministic code in the proxy. Sees the mandate and the effects (hex, addresses and integers only), never agent text, and has no LLM. |
| Agent | **No** | Assumed to be prompt-injected at any moment. It holds or controls its own signing key. |
| Content the agent reads | **No** | The source of injections. |
| Contracts the transaction touches | **No** | Including token contracts: their events, return values and revert messages are attacker-controlled. |
| Upstream RPC node | Partly | Trusted to relay transactions and report chain state honestly. The simulation fork reads its state from the upstream too. Responses are size- and shape-checked, but their content is believed. |
| Simulation node (our anvil) | Yes, *if* only the firewall can reach it | A child process of the proxy on a random loopback port. See "Same-host access to the simulation node". |
| anvil itself | Yes | We rely on it to execute the EVM like the real chain. See "Simulation can differ from the chain". |
| Other processes and users on the host | No | Can reach loopback ports and may be able to read files. |

## What it protects against

Each item has tests under `tests/`.

### The front door (Milestone 1)

1. **The node signing for the agent.** `eth_sendTransaction`, `eth_sign*`,
   `personal_*` and similar methods make the *node* sign with keys it holds.
   Many dev nodes (including anvil) hold unlocked keys. These methods are
   denied: the proxy forwards only transactions the agent signed itself.
2. **Unreviewed RPC methods.** Methods are default-deny: only an explicit list
   of read-only methods is forwarded. Dev-node cheatcodes (`anvil_*`, `evm_*`,
   `hardhat_*`), `debug_*`, filters, subscriptions, and any method invented
   after this list was written are rejected (`-32601`). This also keeps the
   agent away from the simulation node's own cheatcodes.
3. **Denied methods hidden in batches.** Each request in a JSON-RPC batch is
   classified separately. A denied method between two harmless reads is still
   denied.
4. **Wrong-chain transactions.** The proxy fetches the upstream's chain id at
   startup and refuses to start without it. A transaction signed for another
   chain is blocked (`-32003`).
5. **Cross-chain replay.** Legacy transactions without an EIP-155 chain id are
   valid on every chain. They are blocked unless the operator opts in with
   `ALLOW_LEGACY_UNPROTECTED=true`.
6. **Parser differentials.** The decoder accepts only canonical RLP, low-s
   signatures and the transaction types it fully understands (0, 1, 2).
   Anything else, including blob (type 3) and EIP-7702 set-code (type 4)
   transactions, is blocked. The bytes forwarded are exactly the bytes decoded,
   never a re-encoding.
7. **Unrecorded transactions.** Every transaction that reaches the node has an
   audit record, written and fsynced *before* forwarding. If the write fails,
   the transaction is blocked. Blocked transactions are recorded too.
8. **Leaking the upstream API key.** Hosted RPC URLs often embed a key. Logs,
   error messages and startup failures show only `scheme://host:port`.
9. **Browser drive-by requests.** The proxy only accepts
   `Content-Type: application/json`, and it doesn't answer CORS preflights.

### Simulation (Milestone 2)

10. **Judging a transaction by what it claims instead of what it does.** The
    exact signed bytes the agent sent are executed on a private anvil fork of
    the upstream at its latest block. Nothing is rebuilt from decoded fields,
    so anvil checks the same signature, nonce, chain id and fees the real node
    will. The audit record gets the measured effects:
    - ETH balance changes of every address in the call tree, with the gas fee
      split out. Fees can't hide a transfer, and ETH moved inside contracts
      (which no event reports) still shows up.
    - Token transfers and approvals, including NFT `ApprovalForAll`.
    - Every call frame (including `DELEGATECALL`), and the contracts created.
    - Every log the firewall can't decode, kept as raw hex, never dropped.
11. **Transactions that can't be simulated cleanly are blocked** (`-32003`).
    That covers: the fork rejects the transaction (bad nonce, too little ETH,
    fee below the base fee); it isn't mined (a nonce gap); it reverts; the
    simulation times out (`SIMULATION_TIMEOUT_SECONDS`); too many callers are
    waiting; it needs more token checks than `MAX_TOKEN_STATE_CHECKS`; the
    simulation node is down and can't be restarted; the receipt, trace or logs
    are malformed; or the firewall's own code fails. There is no setting that
    turns simulation off.
12. **Token events that lie.** A token's `Transfer` event is a claim made by
    the token contract. For every address named in a token's Transfer events
    (sender *and* recipient), the firewall reads `balanceOf` before and after
    and records whether the change matches what the events claim. It does the
    same for ERC-20 allowances. A token that debits you correctly but credits
    someone other than the named recipient shows up as `consistent: false`.
    Since M4, an inconsistent check escalates the transaction (item 28).
13. **Attacker-chosen text in effects.** Effects contain no token names,
    symbols or revert messages. anvil decodes revert reasons into text, and
    those are dropped. Revert data is kept as hex. Every string field in the
    effects schema is a validated hex value or address, and a test fails if
    one isn't. So text from a contract can't reach M4's verifier through
    effects.
14. **Leaking the upstream URL through the simulator.** anvil is started
    without the URL on its command line (`ps` shows it to every local user)
    and gets it over RPC instead. It runs with `--quiet`, because otherwise
    it logs every request, URL included. Its error messages, which can quote
    the URL, are never passed on unless they're plain short text. It gets no
    environment variables except a private `HOME`.
15. **A simulation that leaks into the next one.** Each simulation runs on a
    verified fork: right chain id, the upstream's block hash at the fork
    point, an empty transaction pool. Afterwards the pool is dropped and the
    fork reverted. Any failure marks the fork dirty, and the next simulation
    starts from a fresh reset. anvil's on-disk fork cache, normally shared
    with every Foundry tool on the machine, lives in a private `0700`
    directory that's deleted on exit, so a stale or tampered cache file can't
    feed a simulation.

### Mandates (Milestone 3)

16. **Transactions without a confirmed mandate.** Each transaction is
    matched to a mandate by `(chain, sender)`. The sender is recovered from
    the signature, so the agent can't claim another account, and nothing it
    sends can choose which mandate applies (an account has at most one
    active mandate). No mandate, or one that is expired, revoked or
    exhausted: blocked (`-32003`) before simulation, and the audit record
    names the mandate it found. There is no setting that turns the gate off.
17. **More transactions than the user allowed.** Each mandate has a
    transaction cap (`max_transactions`, default 3). After simulation the
    proxy charges the transaction to the mandate, re-checking its status in
    the same SQLite transaction (`BEGIN IMMEDIATE`). So two transactions
    racing for the last slot can't both get it, and a mandate revoked,
    expired or used up *during* simulation blocks. Blocked transactions
    aren't charged. Every allowed transaction's audit record carries
    `mandate_id` and its number under that mandate (`mandate_transaction`).
18. **The agent writing its own mandate.** The user gives the instruction to
    the firewall's capture CLI, not to the agent, so an agent that has read
    poisoned content can't rewrite it. The agent's RPC has no mandate
    methods under any name (default-deny, and a test checks that no
    `mandate*`/`firewall*` name is ever allowlisted). The store is
    reachable only by the firewall's OS user, and the agent must run as
    another user or in another container. Confirmation requires a terminal
    on both stdin and stdout, and the exact answer `yes`.
19. **The proxy writing mandates.** The proxy opens the store
    *counters-only*. Its `add` and `revoke` refuse, and an SQLite authorizer
    on its connection denies every statement except reads and writes to the
    counters (and the "exhausted" event). Inserting a mandate, `UPDATE`,
    `DELETE`, `DROP TRIGGER`, `PRAGMA` and `ATTACH` are all refused, so a
    bug in the proxy can't create or widen a mandate. The proxy refuses to
    start if the store is missing or isn't an initialized store, and it never
    creates or writes to such a file.
20. **Edited mandate content.** A mandate's id is the sha256 of its
    canonical JSON, stored with it. Every read re-checks the bytes against
    the id and against the lookup columns (chain, principal, creation and
    expiry times), so a mandate can't be pointed at another account or have
    its expiry extended undetected. Content rows are append-only (SQLite
    triggers). A row that fails its checks blocks the sender's transactions
    with "mandate store integrity failure" (details only in the operator's
    log), and at startup it stops the proxy.
21. **The capture LLM inventing or swapping values.** The LLM produces a
    draft, and a deterministic compiler turns it into a mandate or a
    question. Every amount, address, symbol and venue name must appear as a
    whole word in the user's own instruction. Addresses must carry their
    exact EIP-55 checksum. Symbols and venues resolve only through the
    registry. Missing or ambiguous values become questions, never guesses.
    Recurring wording ("every week", "DCA") is refused, because only
    one-shot mandates exist. The confirmation summary shows full addresses
    (a shortened address is what address-poisoning attacks rely on) and
    registry names. Attacker-controlled strings are sanitized before
    printing.
22. **Leaking the LLM API key.** Only the capture CLI reads `LLM_API_KEY`,
    from the environment or `.env`, never from a flag. The proxy process
    never holds it, and tests check that building the proxy loads none of the
    capture code. The key goes into one HTTP header. Errors carry only an
    error type, never the API's message or the key.

### Verification (Milestone 4)

The proxy now runs: decode, mandate lookup, simulate, **verify**, charge,
audit, forward. The rules are in `src/mandate_firewall/verify/matcher.py`
and docs/m4-plan.md §2–§4.

23. **Money going somewhere the mandate doesn't name.** The effects are
    turned into the principal's own *flows*: every ETH and token movement
    into or out of the agent's account, with its counterparty. Each outflow
    must be covered by an intent: a transfer of asset A to recipient R
    matches only the transfer intent for exactly (A, R). An outflow of any
    asset no intent covers (another token, an NFT, ETH under a token-only
    mandate) is blocked. Inflows are always fine. This closes M3's main
    gap: "pay Bob" no longer lets the agent pay the attacker.
24. **Calling contracts the mandate doesn't name.** The transaction's
    top-level target must be named by the mandate: the token of a token
    transfer, the recipient of an ETH transfer, a swap's venue, or a swap's
    sell token (to approve the venue). Creating a contract and calling the
    agent's own account are blocked. ETH sent to a recipient must carry no
    calldata: "send ETH to X" isn't "call X". This bounds harmful changes
    that move no tokens at all, such as setting a governance delegate or
    transferring a contract's ownership.
25. **Spending more than the budget, over several transactions.** Each
    intent has a budget, and a ledger records how much of it forwarded
    transactions have spent. A transfer is charged its gross outflow, a swap
    its net sell outflow. The store re-checks and charges inside one SQLite
    transaction (`BEGIN IMMEDIATE`), so two transactions racing for the last
    of a budget can't both get it. Amounts are uint256, stored as 32-byte
    big-endian BLOBs (SQLite integers are 64-bit), and a trigger refuses any
    decrease. A mandate whose budgets are all spent is exhausted, even with
    transactions left. Blocked transactions are never charged.
26. **The within-policy, off-mandate swap.** A swap's sell outflow counts
    only when the transaction called one of the swap's venues. Then
    something of the bought asset must arrive at the agent's account, and
    with a minimum, `bought × denominator ≥ sold × numerator`, checked per
    transaction with integers only. That blocks a real swap through the
    right router with `recipient = attacker` (nothing arrived), a swap at a
    manipulated price (below the minimum), and the `pull` + `sweepToken`
    drain (the little that arrived is far below the minimum for all that
    left). Sending the sell token to the router by direct `transfer` is
    blocked (anyone can sweep it), and so is a transaction that spends two
    swap intents' sell assets at once (whose budget would it be?).
    `scripts/demo_m4.sh` step 7 shows each case live.
27. **Approvals that outlive or exceed the mandate.** An ERC-20 approval by
    the agent is allowed only for a swap's sell token, to one of that swap's
    venues, not unlimited (`2^256−1`), and at most what is left of the swap's
    budget after this transaction's own charges. Revoking (approving 0) is
    always allowed. NFT approvals and `ApprovalForAll(true)` are always
    blocked.
28. **Effects the firewall can't interpret.** These *escalate*: the
    transaction is blocked with a louder alert. Cases: a token whose events
    disagree with its storage; an undecoded event that mentions the agent's
    address (an ERC-1155 transfer, a Permit2 approval, a WETH `Withdrawal`);
    ETH arithmetic that doesn't reconcile with the measured balance; the
    agent's account calling something below the top frame (an EIP-7702
    delegation, for instance); and any contract created anywhere in the
    call tree. A short list of known harmless events (the Uniswap V3 pool's
    `Swap`, WETH's `Deposit`) is ignored. That list can only suppress an
    escalation; it never authorizes an outflow.
29. **A bug in the verifier allowing a transaction.** The matcher is pure
    (no I/O, no clock, no LLM). If it or the explainer raises, the
    transaction is blocked as "verification failed: internal error". There
    is no setting that turns verification off.
30. **Teaching the agent the mandate.** The agent gets `-32003` with fixed
    phrases and violation codes in `error.data` (`wrong_recipient`,
    `over_budget`, `below_minimum`…), and never mandate values: no budgets,
    remaining amounts or swap minimums. An injected agent that learned the
    minimum could set the price to exactly that floor.
31. **Explanations that can be wrong or injected.** The operator's "You
    asked / This transaction" diff is rendered by templates from the
    structured verdict. It uses registry names, full addresses and exact
    integer amounts, and labels unregistered tokens as `UNREGISTERED TOKEN
    0x…`. No LLM writes it, and no attacker-chosen text (token names, revert
    strings) reaches it. It goes to the audit record, the operator log and
    `mandate-firewall alerts`.
32. **Swap mandates with no price floor.** Since M4, capture requires a
    minimum for every swap. The compiler asks for one ("at least how much
    WETH must come back for 100 USDC?"), and `--swap` without `--min-out`
    is refused. (Mandates stored earlier without one: see below.)
33. **Re-sends charged twice.** Agents retry. Sending the same signed bytes
    again would be simulated and charged again, so the hashes of charged
    transactions are recorded. A re-send under an active or exhausted
    mandate is forwarded without a new charge and audited as `resend`.
    Identical bytes can be mined only once, so there is nothing new to
    check. Under a revoked or expired mandate a re-send is blocked.
34. **Starting without a registry.** Verification and explanations resolve
    names through the registry, so the proxy refuses to start if the
    registry for the upstream's chain is missing or invalid.

## What it does NOT protect against

### Effects are only as true as the simulation (now the main gap)
M4 compares a transaction's *simulated* effects with the mandate. Everything
under "Simulation can differ from what happens on chain" below passes
straight through the verifier: state that changes between simulation and
inclusion, contracts that behave differently at the real block's timestamp,
and contracts that detect the simulation. A contract that pays Bob in
simulation and the attacker on chain gets an "allow". Swap minimums bound
the price-based variants of this, and nothing bounds the rest yet.

(Through M3, effects weren't compared with the mandate at all. An injected
transfer to an attacker from an account with an active mandate was
forwarded. `scripts/demo_m3.sh` step 6 showed that gap; on M4 code it shows
the block.)

### Stored swap mandates without a minimum
Capture requires a minimum since M4, but mandates locked earlier without one
stay valid: a mandate's id is the hash of its content, so it can't be
amended. For them only `bought > 0` holds. An injected agent can use router
features the mandate doesn't model (SwapRouter02's `multicall` with `pull`
and `sweepToken`) to swap 1 unit to the agent and sweep the rest to itself,
and every rule passes. `mandate show` prints `minimum: NONE ⚠` for them.
Revoke them and lock a new one with a minimum.

### A minimum is a floor, not a fair price
The verifier checks that a swap returns at least the minimum the user typed.
An MEV bot or a manipulated pool can still push the fill down to exactly
that floor. The minimum is only as good as the number the user chose. And
today it holds only for the simulated fill, not the real one: see "State
changes between simulation and inclusion" below.

### Residual allowances
A partly used approval stays in place after the mandate ends: approve 100
USDC, swap 40, and the router can still pull 60. It's bounded by the budget
and goes only to a registry venue, but nothing revokes it.

### Event-less movements and hidden mentions
Token flows come from `Transfer` events checked against `balanceOf`. Not
seen: a token outside the registry that moves balances without emitting
events; an undecoded event that mentions the agent only in packed or
unaligned data (escalation looks for its address as a 32-byte word); and
state changes at an allowed target that emit no events and move no value.
Rule 24 (allowed targets) bounds where such a change can happen.

### Escalation isn't approval
An escalated transaction is blocked, exactly like a blocked one, and can't
be released later. A person acts on the mandate instead: revoke it, or lock
a new one (for example after adding a missing venue to the registry). That
avoids a per-transaction approval queue an attacker could train someone to
click through, and forwarding stale signed bytes later. Alerts reach only
the audit log, a WARNING in the operator log and `mandate-firewall alerts`.
There are no push notifications yet (Slack, Telegram and webhooks are M6),
so an escalation nobody reads is just a block.

### The block reason is an oracle
The agent learns *why* it was blocked (violation codes, never mandate
values). An injected agent can probe the rules by sending variations and
reading the codes. There's no rate limit or circuit breaker that stops an
agent after repeated blocks.

### Confirmation fatigue and misreads
The user confirms a summary, and people confirm without reading,
especially when asked often. A mistyped amount or a look-alike address in
the instruction is grounded (it does appear in the user's words), so the
compiler accepts it, and the summary shows it faithfully. Full addresses,
registry names and a required swap minimum help. They don't make a person
read. Grounding has one more limit: it proves a value appears
in the instruction, not that it's attached to the right thing. In "send 5
USDC to 0xB0b…, not 500", an extracted 500 is grounded. Again only the
confirmation catches it. Standing mandates (M5) are meant to make
confirmations rarer, and so more likely to be read.

### Poisoned instructions
A mandate captures the user's intent; it doesn't judge it. If the user
pastes an address copied from a scam page, or a "recipient" an attacker
supplied by email, the mandate faithfully authorizes paying the scammer, and
M4 faithfully enforces it. The trusted/untrusted split protects the
instruction from the agent. It can't protect the user from what they read
before writing it.

### Authorized but badly executed
An injected agent can still do what the mandate allows, badly: swap at the
minimum instead of the market price, pay in several pieces, or use up the
transaction cap and budget on transactions that fail on chain. Budgets and
swap minimums bound how badly; they don't make the agent do well.

### Same-host compromise
OS file permissions are the only authentication for mandates in M3. There
is no signing.
- **Anyone who can run as the firewall's OS user can create mandates**,
  directly with the CLI or by writing the store. The agent must run as a
  different user or in a different container (this was already needed
  against bypassing the proxy and tampering with the simulation node).
- **The store isn't tamper-evident against that user.** Content can't be
  changed undetected, because of the hash. But whoever can write the file
  can drop the triggers and delete a "revoked" event, an "exhausted" event or
  a counter row, which revives a mandate or resets its count. Nothing
  detects that.
- The store's protections apply only to connections that don't opt out. The
  counters-only authorizer guards the *proxy's* connection, not the file:
  any other program opening the file directly has full access.
- The capture CLI's terminal check stops a scripted `yes` from a pipe. It
  isn't a boundary: a process running as the firewall user can open a
  pseudo-terminal, or write the store directly.

User-wallet EIP-712 signing of mandates (M9) is the fix that adds real
protection: the firewall would accept only mandates signed by a configured
owner key that isn't on this host.

### The authorizer is value-blind
SQLite's authorizer sees which table a statement writes to, not the values.
The proxy must insert "exhausted" events, so its connection is allowed to
insert into `events`, and the authorizer can't tell that from inserting a
"revoked" event. Only the proxy's Python code refuses revoking. That gap can
only ever make the agent do less. In the other direction, the authorizer
can't stop the proxy from *raising* a counter or a `spending` amount, which
also only blocks more. Triggers refuse lowering either one.

### Charged slots and budgets that weren't used
Budgets and transaction slots are charged when a transaction is forwarded,
not when it's mined. A forwarded transaction that later fails on chain, or
that the node rejects ("nonce too low"), still spends its budget and its
slot. The charge also comes before the audit record is written, so if the
write fails, the transaction is blocked but its charge stays (the reverse
order could record "allow" for a transaction that couldn't be charged). All
of these fail closed: the agent can do less, not more.

### Only one-shot mandates
Mandates last at most 24 hours and can't renew. Recurring instructions are
refused. An agent that needs standing authority has to wait for M5.
Meanwhile, users who create long, high-cap mandates to avoid repeated
confirmations widen the window above.

### The registry is trusted
Symbols and venue names resolve through a per-chain registry, shipped with
the package or replaced by the operator. Its addresses were checked by hand
against issuer documentation and on chain, but nothing re-verifies them at
run time. A wrong or malicious entry produces a mandate for the wrong
contract, and the user's summary shows the registry's name for it.
Uniswap on Base Sepolia is SwapRouter02 only. UniversalRouter and Permit2
flows aren't supported yet (Permit2 approvals are off-chain or use events
M2 doesn't decode, and an undecoded Permit2 event that names the agent
escalates). Since M4 the registry's venues are trusted completely: every
contract a venue lists may receive the sell token's approval and be called,
and router features the mandate doesn't model (`pull`, `sweepToken`,
`multicall`) are covered only by the flow rules and the swap minimum.

### Wall-clock expiry
Expiry is checked against the proxy's clock when the transaction arrives. A
transaction forwarded a second before expiry may be mined after it. A wrong
system clock makes mandates expire early or late. Nothing checks the clock.

### The instruction goes to the LLM provider
With the LLM path (`mandate new "…"`), the instruction text, including
amounts and addresses, is sent to the configured provider
(api.anthropic.com by default). The CLI says so before sending it. The
structured path (`--send`/`--swap`) uses no LLM. The capture code calls the
API over plain HTTP (`httpx`), not the vendor SDK, because the SDK and its
new HTTP stack had no verifiable build provenance when checked
(docs/m3-plan.md §5). In exchange, we must track API changes ourselves.

### Off-chain signatures
A lot of value moves without the victim sending any transaction: Permit2 and
EIP-2612 permits, Seaport orders, and other EIP-712 typed-data signatures. An
injected agent can sign a Permit2 approval and hand the signature to an
attacker, who spends it from their own account. **The firewall never sees
this.** It inspects only `eth_sendRawTransaction`, and the signing methods
(`eth_signTypedData*`) are denied on the proxy but performed by the agent's
own key. This is the most common drainer pattern today. **A mandate doesn't help,
and neither does M4's verifier:** the signature is never a transaction, so it is
never matched to one. (When the attacker later spends the permit, that's their
transaction, sent from their own account.) A
pre-sign / typed-data inspection milestone (M7: Permit2 and EIP-2612 at
minimum) is on the roadmap. v0.1 ships without it.

### Simulation can differ from what happens on chain
- **State changes between simulation and inclusion.** The transaction is
  simulated on the latest block and included a few blocks later. In between,
  an upgradeable contract can be upgraded, a "honeypot" owner can flip a
  switch, or a bot can move a price. Effects record exactly which block they
  were simulated on (`fork_block_number`, `fork_block_hash`). M4's swap
  minimum is checked against the *simulated* fill only. If the price moves
  after simulation, only the router's own `amountOutMinimum` protects the
  real fill, and that is in calldata the agent chooses and the firewall
  doesn't decode. An injected agent can pass the simulation at a fair price
  with `amountOutMinimum = 0` and leave the real fill unprotected. **On the
  roadmap right after v0.1:** decode known router calldata (SwapRouter02
  `exactInputSingle`, `exactInput`, `multicall`), require the router's
  `amountOutMinimum` to be at least the mandate's minimum for the amount
  sold, and block venue calls that can't be decoded. Later mitigations:
  deadlines, private mempools, and treating upgradeable or `DELEGATECALL`
  targets as a reason to escalate.
- **Block number and timestamp dependence.** A contract can behave honestly
  at the simulated timestamp and steal at the real one (see the `TimeBomb`
  test contract). Simulating twice at shifted times would catch the simple
  cases. That is deferred, and a contract can always pick a threshold
  beyond any shift.
- **Contracts that detect simulation.** A contract can check `block.coinbase`,
  `prevrandao`, the base fee, gas behavior or anvil quirks, behave in
  simulation, and steal on chain. anvil's default coinbase is the zero
  address, which is trivial to detect (see `SimDetector`). Making the fork
  look more real helps a little. This is an arms race that can't be won in
  general.
- **Client differences.** anvil is not the chain's real client. On OP-stack
  chains (Base, OP), anvil runs in optimism mode but doesn't charge the L1
  data fee, so the sender's recorded ETH change is smaller than the real one.
  A bug in anvil's EVM, or a precompile it implements differently, would make
  the simulation wrong.

### Token checks have limits
- A fully malicious token can lie in `balanceOf` and `allowance` as well as
  in its events. The checks catch tokens whose storage is honest. The real
  defense is the registry: mandates name tokens only through it, so an
  outflow of any other token matches no intent and is blocked.
- ERC-20 and ERC-721 are told apart by the shape of the log (the number of
  indexed topics), so a token that indexes its amount looks like an NFT.
- NFT single-token approvals and `ApprovalForAll` are recorded but not
  state-checked.
- A token that spends an allowance in the same transaction without emitting
  a new `Approval` shows as inconsistent (a false alarm, in the safe
  direction).
- ERC-1155 transfers and Permit2's own events aren't decoded yet. They are
  kept as raw unrecognized logs, and escalate when they name the agent.
- **False positives in the safe direction.** Rebasing and fee-on-transfer
  tokens make events and balances disagree, so they escalate. So do
  ERC-1155 and Permit2 flows. Such tokens can't be used under a mandate
  yet.

### Multi-transaction flows
Each transaction is simulated on its own, against the upstream's latest
block. Budgets are charged at forward time, so accounting across a sequence
(approve, then swap) needs no pending state. But simulation doesn't replay
transactions that are forwarded and not yet mined: a transaction with nonce
n+1 sent before nonce n is mined fails in simulation and is **blocked**.
That's fail-closed but inconvenient: "approve then swap" works only if the
agent waits for the approve to be mined, which most agent toolkits do. A
pending-replay mode is deferred to M6, with a real agent.

### Same-host access to the simulation node
The simulation node listens on a random loopback port with no
authentication. A process on the same host that finds the port can:
- call `anvil_setCode`, `anvil_setBalance` and similar methods to make a
  malicious transaction look harmless in simulation. **That's a full bypass.**
- call `anvil_nodeInfo`, which returns the fork's upstream URL in full,
  **including any API key in it**.

The agent is the obvious candidate. Mitigation today: run the agent as a
different user, or in a different container, from the firewall (this is
already needed against bypassing the proxy, below). Planned: run anvil over
IPC on a Unix socket in a `0700` directory, which other users can't reach,
and have the Docker image run anvil only inside the firewall's container.

### Bypassing the proxy
The proxy only sees transactions that are sent through it. An agent bypasses
it completely if it:

- **holds its private key directly** and signs, then broadcasts the signed
  transaction through any other route;
- **has a second RPC URL**: a hard-coded public endpoint, an SDK's default
  provider, a different provider configured in another tool, or any HTTP
  endpoint that broadcasts raw transactions.

A proxy can also only *refuse to forward*. It can't un-sign. A blocked
transaction is still a valid signed transaction in the agent's hands, and it
can be broadcast elsewhere.

Mitigations, today: run the agent where the proxy is its only network route to
any chain (egress firewall, container network policy), and don't give it any
other RPC URL. **The real fix is to check before signing**, so a signature
never exists for a transaction the firewall blocks. That's why wallet pre-sign
hooks (key held by a separate signer that asks the firewall first) are on the
roadmap after the RPC proxy.

### Decoded calldata is a claim
The calldata decoder knows three ERC-20 selectors. A matching selector says
nothing about what the target contract does. Simulated effects are what the
transaction did. The decoded call is kept for logging and explanation only.

### A malicious or compromised upstream node
Read results (balances, `eth_call`, receipts) are passed through as the
upstream reports them, and the simulation fork reads its state from the same
upstream. A lying upstream can mislead the agent *and* the simulation, and it
could drop or delay forwarded transactions. Each fork is checked against the
upstream's chain id and block hash, but that only proves the fork matches the
upstream, not that the upstream is honest. Use an upstream you trust.

### Anyone who can reach the proxy
The proxy has no authentication. It listens on `127.0.0.1` by default, which
still lets every local process and user send it requests. Through it they can
submit their own signed transactions (harmless; they could use any node) and
use your upstream, including its API key quota, for read calls. The CLI warns
if you bind to a non-loopback address. DNS rebinding (a web page that
re-points its own hostname at `127.0.0.1`) isn't defended against, because the
`Host` header isn't checked. The impact is the same as above.

### Audit log limits
- It contains **signed transactions, including blocked ones**. Anyone who can
  read it can broadcast them. It's created with mode `0600`, and the proxy
  warns at startup if an existing file is readable by others. Root/admin can
  still read it.
- It isn't tamper-evident. Anyone who can write the file can edit or delete
  records without detection. (Hash-chaining or signing records is possible
  later work.)
- No rotation, no size cap, and records now include effects, so they're
  larger. An agent that floods transactions grows the file without limit.
  When the disk fills, writes fail and **every transaction is blocked**.
  That's fail-closed, but it's also a denial of service.
- One proxy process per file. Two processes appending to the same file may
  interleave records.
- Since M4, records carry the verdict and the operator's explanation, which
  include **mandate values** (budgets, what is left, swap minimums). The
  agent must not be able to read the audit log or the operator log, or it
  learns exactly what item 30 keeps from it.
- Blocked records name the mandate they were checked against whenever one
  was identified. They don't copy its content: look the id up with
  `mandate-firewall mandate show <id>`. If the store is lost, the ids in the
  log can no longer be resolved.

### Availability
Simulation adds latency (tens of milliseconds against a local node, more
against a hosted RPC, where every cold state read is a round trip) and new
ways to fail. Every one of them blocks. Verification itself is pure code
and fast, but a transaction that escalates on a false positive (item 28) is
blocked just the same. While the simulation node is down and
can't be restarted, **every transaction is blocked**. Transactions are
simulated one at a time. A transaction that touches thousands of addresses
can run into the timeout and be blocked (token checks are capped up front;
ETH balance reads aren't). If the proxy is killed with `SIGKILL`, its anvil
child keeps running until it's killed by hand. Without its mandate store the
proxy doesn't start. While `mandate new` or `revoke` holds the store's write
lock for more than a second, transactions are blocked. Mandate store calls
are synchronous, so they briefly stall the proxy's event loop.

### No rate limiting
A flood of requests, or expensive reads such as wide `eth_getLogs` ranges,
reaches the upstream unthrottled.

### Out of scope
MEV and front-running after a transaction is broadcast, chain reorgs, attacks
on dependencies (the lockfile pins versions; nothing more), and the security
of the host machine.

## Batch semantics, stated plainly
Requests in a batch are independent, as JSON-RPC 2.0 specifies. A batch with a
valid signed transaction and a denied method **forwards the transaction** and
rejects the method. Transactions in a batch are handled in order, each
simulated on its own (see "Multi-transaction flows"). The firewall makes
decisions per transaction, not per batch.
