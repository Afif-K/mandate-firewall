# Threat model

Status: **beta, Milestone 1.** This document describes what the code in this
repository does today, not what the project plans to do. It is updated with
every milestone. If you find a gap that isn't listed here, please open an issue.

## What the firewall is for

An AI agent with a wallet can be prompt-injected. Text it reads (a web page, a
token name, an email, a tool result) can make it send a transaction the user
never asked for. Spend limits and allowlists don't catch an injected transfer
that is under the limit and goes to an allowed contract. The goal of this
project is to check each transaction against the user's own instruction, the
*mandate*, and block anything that doesn't match.

**Milestone 1 does not check mandates yet.** It builds the choke point that
later milestones check at: a JSON-RPC proxy that sees every transaction the
agent sends through it, decodes it, records it, and forwards it.

## Actors and trust

| Actor | Trusted? | Notes |
|---|---|---|
| User | Yes | Gives the instruction. Will confirm mandates (M3). |
| Operator / host machine | Yes | Runs the proxy, sets its config, owns the audit log. |
| Agent | **No** | Assumed to be prompt-injected at any moment. It holds or controls its own signing key. |
| Content the agent reads | **No** | The source of injections. |
| Upstream RPC node | Partly | Trusted to relay transactions and report chain state honestly. Its responses are size- and shape-checked, but their content is believed. |
| Other processes and users on the host | No | Can reach a loopback port and may be able to read files. |

## What Milestone 1 protects against

Each item has tests under `tests/`.

1. **The node signing for the agent.** `eth_sendTransaction`, `eth_sign*`,
   `personal_*` and similar methods make the *node* sign with keys it holds.
   Many dev nodes (including anvil) hold unlocked keys. These methods are
   denied: the proxy forwards only transactions the agent signed itself.
2. **Unreviewed RPC methods.** Methods are default-deny: only an explicit list
   of read-only methods is forwarded, so dev-node cheatcodes (`anvil_*`,
   `evm_*`, `hardhat_*`), filters, subscriptions, and any method invented
   after this list was written are rejected (`-32601`).
3. **Denied methods hidden in batches.** Each request in a JSON-RPC batch is
   classified separately. A denied method between two harmless reads is still
   denied, and the integration tests check that such a batch mines nothing on
   a real anvil node.
4. **Wrong-chain transactions.** The proxy fetches the upstream's chain id at
   startup and refuses to start without it. A transaction signed for another
   chain is blocked (`-32003`).
5. **Cross-chain replay.** Legacy transactions without an EIP-155 chain id are
   valid on every chain. They are blocked unless the operator opts in with
   `ALLOW_LEGACY_UNPROTECTED=true`.
6. **Parser differentials.** If the firewall decoded a transaction differently
   from the node, it could approve one transaction while the chain executes
   another. The decoder accepts only canonical RLP, low-s signatures and the
   transaction types it fully understands (0, 1, 2). Anything else, including
   blob (type 3) and EIP-7702 set-code (type 4) transactions, is blocked. The
   bytes forwarded are exactly the bytes decoded, never a re-encoding.
7. **Unrecorded transactions.** Every transaction that reaches the node has an
   audit record. The record is written and fsynced *before* forwarding, and if
   the write fails the transaction is blocked. Blocked transactions are
   recorded too.
8. **Leaking the upstream API key.** Hosted RPC URLs often embed a key. Logs,
   error messages and startup failures show only `scheme://host:port`.
9. **Browser drive-by requests.** The proxy only accepts
   `Content-Type: application/json`, so a web page can't send it a "simple"
   cross-origin POST, and it doesn't answer CORS preflights.

## What Milestone 1 does NOT protect against

### Off-mandate transactions (the main gap)
M1 forwards every well-formed transaction for the right chain. An injected
"send all USDC to the attacker" transaction is decoded, logged and **forwarded**.
Simulation (M2), mandate capture (M3) and verification (M4) close this gap.
Until then, this project is a logging proxy with a strict front door, not a
firewall against injected intent.

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

### Decoded calldata is a claim, not an effect
The calldata decoder knows three ERC-20 selectors. A matching selector says
nothing about what the target contract does: any contract can implement
`transfer(address,uint256)` to do anything. Unknown selectors are logged as
unknown. Real effects come from simulation (M2).

### A malicious or compromised upstream node
Read results (balances, `eth_call`, receipts) are passed through as the
upstream reports them. A lying upstream can mislead the agent, and it could
drop or delay forwarded transactions. The chain id is checked once at startup,
not on every request. Use an upstream you trust.

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
- No rotation, no size cap. An agent that floods transactions grows it
  without limit. When the disk fills, writes fail and **every transaction is
  blocked**. That's fail-closed, but it's also a denial of service.
- One proxy process per file. Two processes appending to the same file may
  interleave records.

### No rate limiting or resource controls
A flood of requests, or expensive reads such as wide `eth_getLogs` ranges,
reaches the upstream unthrottled.

### Out of scope
MEV and front-running after a transaction is broadcast, chain reorgs, attacks
on dependencies (the lockfile pins versions; nothing more), and the security
of the host machine.

## Batch semantics, stated plainly
Requests in a batch are independent, as JSON-RPC 2.0 specifies. A batch with a
valid signed transaction and a denied method **forwards the transaction** and
rejects the method. The firewall makes decisions per transaction, not per batch.
