# Threat model

Status: **beta, Milestone 2.** This document describes what the code in this
repository does today, not what the project plans to do. It is updated with
every milestone. If you find a gap that isn't listed here, please open an issue.

## What the firewall is for

An AI agent with a wallet can be prompt-injected. Text it reads (a web page, a
token name, an email, a tool result) can make it send a transaction the user
never asked for. Spend limits and allowlists don't catch an injected transfer
that is under the limit and goes to an allowed contract. The goal of this
project is to check each transaction against the user's own instruction, the
*mandate*, and block anything that doesn't match.

**Milestone 2 does not check mandates yet.** M1 built the choke point: a
JSON-RPC proxy that sees every transaction the agent sends through it. M2 adds
simulation. Every transaction is run on a private fork of the chain before
it's forwarded, and what it actually did (its *effects*) is recorded. M2
blocks a transaction only if it can't be simulated cleanly or if it reverts.
Comparing effects with a mandate is M3 (capture) and M4 (verification).

## Actors and trust

| Actor | Trusted? | Notes |
|---|---|---|
| User | Yes | Gives the instruction. Will confirm mandates (M3). |
| Operator / host machine | Yes | Runs the proxy, sets its config, owns the audit log. |
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
    (M2 records this. Blocking on it is M4's job.)
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

## What it does NOT protect against

### Off-mandate transactions (still the main gap)
An injected "send all USDC to the attacker" transaction that is well-formed,
for the right chain, and simulates successfully is **forwarded**. M2 records
exactly what it does, but nothing compares that with what the user asked for.
Mandate capture (M3) and verification (M4) close this gap. Until then, the
firewall is a strict, simulating, auditing proxy, not a firewall against
injected intent.

### Off-chain signatures
A lot of value moves without the victim sending any transaction: Permit2 and
EIP-2612 permits, Seaport orders, and other EIP-712 typed-data signatures. An
injected agent can sign a Permit2 approval and hand the signature to an
attacker, who spends it from their own account. **The firewall never sees
this.** It inspects only `eth_sendRawTransaction`, and the signing methods
(`eth_signTypedData*`) are denied on the proxy but performed by the agent's
own key. This is the most common drainer pattern today. A pre-sign /
typed-data inspection milestone (Permit2 and EIP-2612 at minimum) is on the
roadmap before v0.1.

### Simulation can differ from what happens on chain
- **State changes between simulation and inclusion.** The transaction is
  simulated on the latest block and included a few blocks later. In between,
  an upgradeable contract can be upgraded, a "honeypot" owner can flip a
  switch, or a bot can move a price. Effects record exactly which block they
  were simulated on (`fork_block_number`, `fork_block_hash`). Later
  mitigations: mandate bounds such as minimum output and deadlines (M4),
  private mempools, and treating upgradeable or `DELEGATECALL` targets as a
  reason to escalate.
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
  in its events. The checks catch tokens whose storage is honest. M4's
  registry of known token addresses is the real defense.
- ERC-20 and ERC-721 are told apart by the shape of the log (the number of
  indexed topics), so a token that indexes its amount looks like an NFT.
- NFT single-token approvals and `ApprovalForAll` are recorded but not
  state-checked.
- A token that spends an allowance in the same transaction without emitting
  a new `Approval` shows as inconsistent (a false alarm, in the safe
  direction).
- ERC-1155 transfers and Permit2's own events aren't decoded yet. They are
  kept as raw unrecognized logs.

### Multi-transaction flows
Each transaction is simulated on its own, against the upstream's latest
block. A transaction with nonce n+1 sent before nonce n is mined fails in
simulation and is **blocked**. That's fail-closed but inconvenient: "approve
then swap" works only if the agent waits for the approve to be mined. Whether
a quick follow-up passes depends on timing. Simulating "approve" alone also
says little about intent without the swap that follows. M3/M4 should treat a
sequence as one mandate and track approved-but-unmined transactions.

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

### Availability
Simulation adds latency (tens of milliseconds against a local node, more
against a hosted RPC, where every cold state read is a round trip) and new
ways to fail. Every one of them blocks. While the simulation node is down and
can't be restarted, **every transaction is blocked**. Transactions are
simulated one at a time. A transaction that touches thousands of addresses
can run into the timeout and be blocked (token checks are capped up front;
ETH balance reads aren't). If the proxy is killed with `SIGKILL`, its anvil
child keeps running until it's killed by hand.

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
