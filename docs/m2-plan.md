# M2 plan: simulation that produces structured effects

Status: **approved 2026-10-06**. Commits 0–1 done. Next step: commit 2 (effects models).

## Decisions (agreed 2026-10-06)

1. Simulation uses **approach B**: one long-lived Anvil fork with reset/snapshot/revert, executing the exact raw transaction.
2. M2 = commits **0–8** below. **Deferred** (not in M2): differential timestamp/block simulation and realistic coinbase (old commit 9), ERC-1155 `TransferSingle`/`TransferBatch` decoding, and Permit2 Approval event decoding. Until then they appear as `unrecognized_logs`.
3. **Off-chain signatures** (Permit2, EIP-2612, Seaport/EIP-712) go into THREAT_MODEL.md during M2. The CLAUDE.md roadmap gets a new **pre-sign / typed-data inspection** milestone (covering at least Permit2 and EIP-2612) **before v0.1**. Both happen in commit 8.
4. **Housekeeping commit before M2 commit 1:** remove the `httpx2` dev dependency, and handle the Starlette deprecation warning with a pytest `filterwarnings` entry that matches only that one message. (Rationale corrected 2026-10-07, see Roadmap pushback item 4.)

## Context

M1 gave us a choke point. Every `eth_sendRawTransaction` is decoded strictly, audited before it goes out, and forwarded as the exact same bytes. What M1 can't do is say what a transaction *does*. `DecodedCall` is only a claim, as `models.py:70` already notes. M2 runs each transaction on a private fork and pulls out **effects**: who gained or lost ETH, which tokens moved, which approvals were granted, and which contracts ran. M3 (mandate) and M4 (verifier) will compare those effects against the user's instruction.

M2 makes no allow/block decisions based on intent. It only adds one new reason to block: **the transaction could not be simulated cleanly** (fail closed).

What exists today that M2 reuses:
- `UpstreamClient` (`proxy/upstream.py`) is already a generic, hardened JSON-RPC client: size caps, id checks, and no URL in error text. The simulator talks to Anvil through a second instance of it, so we don't write a new client.
- `Proxy._send_raw_transaction` (`proxy/app.py:216`) is where simulation gets added, between `_check(tx)` and the audit write.
- `AuditRecord` (`audit.py`) gets `effects` and `simulation_error` fields.
- `BigInt` (`models.py:11`) handles all wei and token amounts, including signed deltas.
- `tests/integration/conftest.py` already has `start`/`stop`/`free_port` helpers for Anvil.
- Anvil 1.8.3 is installed locally.

---

## 1. How simulation works

**Forking, step by step.** A blockchain's state is a big map: address → (balance, nonce, code, storage). Anvil started with a fork points at an upstream node and a block number N. It starts with *no* state of its own. The first time a transaction reads, say, USDC's `balances[you]` slot, Anvil fetches that slot from the upstream at block N (`eth_getStorageAt`) and caches it. After that, everything runs locally. So you get a full EVM over real mainnet or testnet state, and you only pay for the slots you actually touch. Writes stay local and never reach the upstream.

Example: the agent signs "transfer 50 USDC to 0xBob". On the fork, Anvil fetches USDC's code and two balance slots, runs the transfer, and mines block N+1 locally. We then read the receipt (status, logs) and the trace (call tree). The real chain never sees any of this.

**Ways to run one transaction:**

| Approach | Speed | Accuracy | Isolation |
|---|---|---|---|
| **A. Fresh Anvil per tx** (`anvil --fork-url … --fork-block-number N`) | Worst. Process start plus a cold cache each time, about 1–3 s | High, runs the real signed tx | Perfect, nothing is shared |
| **B. One long-lived fork + reset/snapshot/revert** | Good. No process start, and the cache stays warm while the head is unchanged | High, runs the real signed tx | Good *if* every sim starts from a verified clean state. Needs a lock, since it's one sim at a time |
| **C. `eth_call` / `debug_traceCall` / `eth_simulateV1`** on the upstream or fork | Best | **Lower.** It simulates a *call object*, not the signed bytes. Signature, nonce, chain id and fee checks are skipped or reconstructed by us. `eth_call` returns no logs at all. `debug_*` is often unavailable or paid on hosted RPCs | Perfect, it's stateless |

**Recommendation: B, executing the exact raw transaction.** The main reason is the principle we set in M1: *what we check must be byte-for-byte what the node receives*. With C we'd rebuild a call from decoded fields, and that rebuild is a second parser that could drift from the real one. With B, Anvil validates the same signature, nonce and chain id the real node will check. A also runs the real bytes, but it's 10–50× slower for no isolation gain we can't get from B with discipline.

**The clean-state protocol for B:**
1. Ask the upstream for its head: block number N and its hash.
2. If the fork isn't pinned at N, or it's marked *dirty*, call `anvil_reset({forking: {jsonRpcUrl, blockNumber: N}})` and then `evm_snapshot` → S.
   Otherwise, call `evm_revert(S)` and then `evm_snapshot` → S, because Anvil uses up a snapshot when you revert to it.
3. `eth_sendRawTransaction(raw)`, then `evm_mine`. Anvil mines block N+1 containing only our tx. (Changed from automine after the spike, see "Spike findings".)
4. Read the receipt, `debug_traceTransaction` (callTracer), and balances before and after.
5. Revert. Any exception at any step marks the fork **dirty**, which forces a full reset before the next sim.

One honest caveat: on Base (2 s blocks) the head almost always moves between agent transactions, so in practice we'll `anvil_reset` most of the time, and the "warm cache" gain is small. That's fine. Correctness (simulating against the latest head) comes before speed. Commit 6 measures latency so we know rather than guess.

### Spike findings (commit 1, anvil 1.8.3, 2026-10-07)

Both things the plan depends on work: `anvil_reset({forking: {jsonRpcUrl, blockNumber}})` switches a plain dev node into fork mode (it takes the upstream's chain id, and the block hash at N matches), and `debug_traceTransaction` with `callTracer` returns CALL, CREATE and nested frames. The spike also turned up these, now handled in `simulate/node.py`:

- **Automine is asynchronous.** `eth_sendRawTransaction` returns the hash before the block exists, so an immediate receipt or trace lookup says "not found". The node runs with `--no-mining`, and the simulator mines with `evm_mine`, which returns only once the block is mined. A tx that lands in the pool as *queued* (future nonce) leaves the mined block empty, so a missing receipt must be an error.
- **Without `--quiet`, anvil logs each request in full,** including the `anvil_reset` that carries the upstream URL. The node runs `--quiet` with all output sent to `/dev/null`.
- **anvil error text quotes the upstream URL** (e.g. "request to http://host:port/ failed"). `SimulatorError` carries only the method and error code.
- **`anvil_nodeInfo` returns `forkUrl` in full.** Anyone who can reach the node's port can read the upstream URL and its API key. This adds to the same-host risk in §3. It goes into THREAT_MODEL.md in commit 8.
- **A failed `anvil_reset` leaves the previous fork in place,** not an empty node. After a failure the fork is dirty until a later reset succeeds.
- **`evm_revert` does not clear the txpool.** A queued tx survives the revert and could be mined in a later simulation. `anvil_reset` does clear it, and so does `anvil_dropAllTransactions`. Every fork is checked for an empty pool. The simulator (commit 6) must drop the pool before reverting.
- **`evm_revert` to a used snapshot returns `false`,** not an error. It must be checked.
- **Dev accounts get 10000 ETH on a fork by default,** which overwrites their real balances. Those addresses are public and used on real chains, so the node runs with `--accounts 0`. That also leaves it with no signing keys.
- **anvil caches forked state in `~/.foundry/cache/rpc/<chain-name>/<block>/`,** keyed only by chain and block number and shared with every Foundry tool. A local fake chain claiming id 84532 wrote into `base-sepolia/`. The node runs with `HOME` set to a private `0700` temp dir (deleted on stop) and no other environment variables. `--no-storage-caching` can't be used without `--fork-url`.
- **`--optimism` is `--network optimism` in 1.8.3,** and it works with `anvil_reset`. *Open question for commit 6/7:* turn it on for OP-stack chain ids (Base 8453 / 84532, OP 10 / 11155420), or make it a setting.
- **Fork state is read by block hash** by default (`--fork-state-by-number` opts out), which pins the state to the block we verified.

## 2. Effects: what to extract and how

Two sources, with different trust levels:
- **Receipt logs (events)** are claims made by the emitting contract. A malicious token can emit a `Transfer` that didn't happen, or skip one that did.
- **State reads and trace** are what the EVM actually did: balances, call frames, created contracts.

What we extract:
- **Native ETH.** ETH only moves through tx value, CALL/CREATE value, SELFDESTRUCT, and fees, and all of these show up as callTracer frames. So: gather every address in the call tree plus sender, `to` and created contracts, then `eth_getBalance` at N vs N+1 and keep the nonzero deltas. Gas is split out using `gasUsed × effectiveGasPrice` from the receipt, so "sender paid 0.0003 ETH in fees" doesn't hide inside "sender lost 1.0003 ETH". The fee recipient (coinbase) is left out of deltas.
- **Token events, decoded strictly** with the same style as `decode/calldata.py`: fixed registry, padding checks, and the topic count must match exactly.
  - `Transfer(address,address,uint256)`: 3 topics → ERC-20 (amount in data), 4 topics → ERC-721 (tokenId indexed). Same topic0, so the topic count is the only thing telling them apart. Anything else is unrecognized.
  - `Approval(address,address,uint256)`: same 3-vs-4 topic split (ERC-20 allowance vs ERC-721 single-token approval).
  - `ApprovalForAll(address,address,bool)`: ERC-721 and ERC-1155 "operator may move *all* my NFTs". This is the classic NFT drainer.
  - Every other log is kept as a `RawLog` in `unrecognized_logs`, never dropped. M4 will treat "unrecognized effects exist" as a reason to escalate.
- **Cross-check the claims.** For each token that emitted a Transfer or Approval involving the sender, we `eth_call` `balanceOf(sender)` and `allowance(sender, spender)` before and after and compare against the logs. Any mismatch → `consistent=False`. This catches lying events from tokens with honest storage. (A fully malicious token can lie in `balanceOf` too. M4's registry of canonical token addresses is the real defense.)
- **Contracts called**, from callTracer: depth, type (CALL / DELEGATECALL / STATICCALL / CREATE / CREATE2 / SELFDESTRUCT), from, to, value, selector, and whether the frame reverted. DELEGATECALL matters because it runs foreign code with the caller's storage and balance.
- **No attacker strings.** No token names, symbols, or revert *messages* go into the model. Revert data is stored as hex bytes. Names and symbols come later from M4's verified registry, keyed by address.

**Proposed model** (`models.py`, all frozen, amounts as `BigInt`):

```python
class SimulationStatus(StrEnum): SUCCESS = "success"; REVERTED = "reverted"
class TokenStandard(StrEnum): ERC20 = "erc20"; ERC721 = "erc721"
class CallType(StrEnum): CALL, DELEGATECALL, STATICCALL, CALLCODE, CREATE, CREATE2, SELFDESTRUCT

class NativeBalanceChange(BaseModel):  address: str; delta: BigInt           # signed wei
class TokenTransfer(BaseModel):        token: str; standard: TokenStandard; sender: str
                                       recipient: str; amount: BigInt | None; token_id: BigInt | None
                                       log_index: int
class TokenApproval(BaseModel):        token: str; standard: TokenStandard; owner: str
                                       spender: str; amount: BigInt | None; token_id: BigInt | None
class OperatorApproval(BaseModel):     token: str; owner: str; operator: str; approved: bool
class CallFrame(BaseModel):            depth: int; call_type: CallType; caller: str; target: str | None
                                       value: BigInt; selector: str | None; reverted: bool
class RawLog(BaseModel):               address: str; topics: tuple[str, ...]; data: str; log_index: int
class TokenStateCheck(BaseModel):      token: str; kind: Literal["balance", "allowance"]
                                       owner: str; spender: str | None
                                       before: BigInt; after: BigInt; consistent: bool

class Effects(BaseModel):
    tx_hash: str; sender: str; chain_id: int
    fork_block_number: int; fork_block_hash: str        # exactly what we simulated against
    status: SimulationStatus; revert_data: str | None    # hex, never decoded to text
    gas_used: BigInt; effective_gas_price: BigInt; gas_cost: BigInt
    native_balance_changes: tuple[NativeBalanceChange, ...]
    token_transfers: tuple[TokenTransfer, ...]
    token_approvals: tuple[TokenApproval, ...]
    operator_approvals: tuple[OperatorApproval, ...]
    calls: tuple[CallFrame, ...]
    contracts_created: tuple[str, ...]
    unrecognized_logs: tuple[RawLog, ...]
    token_state_checks: tuple[TokenStateCheck, ...]
```

Deliberately left out of M2: ERC-1155 `TransferSingle`/`TransferBatch` decoding (they land in `unrecognized_logs`, which fails safe), and Permit2's own Approval event (also unrecognized for now). Both are easy to add once M4 shows they're needed.

## 3. Where the simulation node lives

- **The firewall owns a private Anvil subprocess.** The FastAPI lifespan starts it next to the upstream client and the audit log, and stops it on shutdown. It binds to `127.0.0.1` on a random free port.
- **Two clients, two URLs.** `Proxy._forward` only ever uses the upstream client. A separate `SimulatorClient` (wrapping an `UpstreamClient` instance) is the only thing that knows the Anvil URL. The `anvil_*`/`evm_*`/`debug_*` methods are called from Python code and never go through `classify()`. `methods.py` stays exactly as it is: those methods remain denied to agents. A test checks this.
- **Keep the upstream API key out of `ps`.** Start Anvil *without* `--fork-url`, then pass the URL through `anvil_reset` over RPC. That's the same concern `cli.py` already warns about for our own flags.
- **Startup checks (no unverified startup):** the `anvil` binary exists, the fork's `eth_chainId` equals the upstream's, the fork's block hash at N equals the upstream's, and `debug_traceTransaction` with `callTracer` works (checked by tracing a tx on a throwaway snapshot). If any check fails, the firewall refuses to start.
- **Pushback / residual risk:** Anvil's port is unauthenticated. If the *agent* runs on the same host as the same user, it can find that port and call `anvil_setCode` or `anvil_setBalance` to make its own malicious tx look harmless in simulation. That's a full bypass. Mitigations, in order: (1) document that the agent must run in a separate container or user (we already require this for the bypass-the-proxy issue); (2) later, switch Anvil to `--ipc` on a Unix socket in a `0700` directory, which is out of reach for other users; (3) the Docker image runs Anvil inside the firewall container only. M2 does (1) and records (2) in THREAT_MODEL.md.
- Base / OP-stack: Anvil needs OP-stack mode (`--optimism`) to handle deposit txs and predeploys properly. It still won't charge the L1 data fee, so the sender's ETH delta *underestimates* the fees. That doesn't matter for intent, but it gets documented.

## 4. Failure handling (fail closed)

New `SimulationError` subclasses, each turned into `Decision.BLOCK` with a clear reason in the audit record (M4 can upgrade some of them to ESCALATE):

| Failure | Behavior |
|---|---|
| Timeout: `asyncio.wait_for` around the *whole* simulation, including the lock wait. Default `SIMULATION_TIMEOUT_SECONDS=10` | Block, mark the fork dirty |
| Anvil process died or doesn't answer | Block. Restart in the background. Every tx is blocked until it's healthy again |
| Upstream fetch fails during the fork (`anvil_reset` or lazy state fetch errors) | Block, dirty |
| Fork rejects the tx (nonce, funds, fee below base fee, bad signature) | Block with the fork's error. Real execution would have failed too |
| Tx **reverts** in simulation | Block. It would waste gas at best, and at worst it reverts in sim but succeeds on chain because state changed, which is a "simulation lies" case |
| Trace or receipt malformed, extraction throws, or unexpected shape | Block, dirty |
| Too many waiters on the lock (bounded queue) | Block quickly instead of piling up |

Rules: there's no "simulation disabled" switch. Any exception inside `simulate()` → dirty → the next sim does a full `anvil_reset` before reusing the fork. If the reset fails → restart the process. The proxy never forwards a tx whose effects are `None`.

## 5. Where simulation can lie

| Lie | Example | M2? | Where it goes |
|---|---|---|---|
| **State changes between sim and inclusion** | Simulated on block N, included at N+3. Meanwhile an upgradeable proxy is upgraded, a "honeypot" owner flips a switch, or a sandwich bot moves the price | **No** (can't, by nature). M2 pins to the latest head, records `fork_block_number/hash`, and keeps the gap short | THREAT_MODEL.md. Later mitigations: mandate bounds (min-out, deadlines) in M4, private mempools, and delegatecall/upgradeable targets as escalation signals |
| **Block number / timestamp dependence** | `if (block.timestamp > T) drain()` with T set just after the sim | **Deferred, not in M2**: *differential simulation*, running the tx twice (now, and now + Δ via `evm_setNextBlockTimestamp`, plus a block-number bump with `anvil_mine`). If effects differ, block. Cheap because of snapshot/revert | THREAT_MODEL.md covers what remains (a contract can always pick a T beyond Δ) |
| **Contracts detecting simulation** | Checks `block.coinbase`, `prevrandao`, `basefee`, gas quirks, or Anvil-specific behavior, and acts benign in sim, malicious on chain | **Barely.** We can make Anvil look more real, e.g. set coinbase to the chain's real fee recipient (on OP-stack `0x4200…0011`). It's an arms race we can't win in general | THREAT_MODEL.md, stated plainly |
| **Lying events** | Fake `Transfer` logs from a malicious token | **Partly**: state cross-check (`TokenStateCheck.consistent`) | M4 registry closes most of it |
| **Lying upstream** | Fork state comes from the upstream | No | Already in THREAT_MODEL.md, and it now also covers simulation |
| **Same-host fork tampering** | Agent calls `anvil_setCode` on our fork | Documented (see §3) | THREAT_MODEL.md |
| **Client differences** | Anvil vs the real Base node: L1 fee, precompiles | No | THREAT_MODEL.md |

## 6. Commit sequence (OK between each)

0. **Housekeeping.** Remove the `httpx2` dev dependency from `pyproject.toml` and `uv.lock` (`uv remove --dev httpx2`). Add a `filterwarnings` entry under `[tool.pytest.ini_options]` for the Starlette deprecation warning.
   *Verify:* `uv sync`, then `uv run pytest` passes and that warning no longer shows up, `uv run ruff check .`, and `grep httpx2 uv.lock` finds nothing.
1. **Simulator node manager** (`simulate/node.py`, settings `ANVIL_PATH`, `SIMULATION_TIMEOUT_SECONDS`, `.env.example`). **Done.** Spawn Anvil, wait until ready, `anvil_reset` into fork mode over RPC, startup checks (chain id, block hash, callTracer probe), clean shutdown. Includes a short **spike** confirming Anvil 1.8.3 supports fork-mode reset over RPC and callTracer. If it doesn't, we adjust before building more.
   *Verify:* `uv run pytest -m anvil tests/integration/test_simulator_node.py`. An "upstream" Anvil plus our fork Anvil: chain ids match, a wrong chain id refuses to start, and `ps` shows no upstream URL.
2. **Effects models** in `models.py`.
   *Verify:* unit tests for frozen behavior, signed `BigInt` deltas serializing as strings, and round-trip JSON.
3. **Log decoder** (`simulate/logs.py`, pure). Receipt logs → transfers, approvals, operator approvals, raw logs.
   *Verify:* unit tests on hand-built logs: ERC-20 vs ERC-721 via topic count, dirty address padding, wrong data length, unknown topic0 → `unrecognized_logs`, extra topics → unrecognized.
4. **Trace parser** (`simulate/trace.py`, pure). callTracer JSON → `CallFrame`s, touched addresses, created contracts.
   *Verify:* unit tests on callTracer JSON fixtures captured from real Anvil: nested calls, delegatecall, create, reverted subframe, selfdestruct.
5. **Test contract fixtures** (`tests/fixtures/contracts/*.sol`, a build script, and committed bytecode, so tests don't need solc). MockERC20, MockERC721, `LyingToken` (emits a fake Transfer), `EthForwarder` (internal ETH move), `TimeBomb` (timestamp-dependent), `SimDetector` (coinbase check).
   *Verify:* the build script reproduces the committed bytecode, and a smoke test deploys each one on Anvil.
6. **Simulator** (`simulate/simulator.py`). Lock, clean-state protocol, send, receipt, trace, balances, token state checks, revert, dirty flag, timeout. Returns `Effects` or raises `SimulationError`.
   *Verify:* integration tests per scenario: ETH send, ERC-20 transfer/approve, NFT `setApprovalForAll`, internal ETH via forwarder, LyingToken → `consistent=False`, revert → `REVERTED`, two sims back-to-back don't leak state, a killed Anvil → error and recovery, and a timeout via a slow fake. Prints p50 latency.
7. **Proxy wiring.** Lifespan starts the simulator (fails closed at startup). `_send_raw_transaction` simulates before the audit write. Any simulation failure or revert → block `-32003`. `AuditRecord` gains `effects` and `simulation_error`. A test checks that agents still can't reach `anvil_*`, `evm_*` or `debug_*`.
   *Verify:* existing M1 tests still pass. New integration test: proxy → real tx is forwarded with effects in the audit line, a reverting tx is blocked and never mined upstream, and with the simulator killed, a tx is blocked.
8. **Docs.** Rewrite THREAT_MODEL.md for M2 (all of §5, same-host tampering, off-chain signatures, multi-tx flows), README quickstart (Anvil now required). In CLAUDE.md, mark M2 done and add the pre-sign / typed-data inspection milestone (Permit2 and EIP-2612 at minimum) before v0.1.
   *Verify:* read-through. `uv run ruff check .` and the full `uv run pytest`.

**Deferred (after M2):** differential timestamp/block simulation plus realistic coinbase (`TimeBomb` / `SimDetector` fixtures from commit 5 are ready for it), ERC-1155 transfer decoding, and Permit2 event decoding.

Each commit: `uv run ruff check .` plus `uv run pytest` (with `-m anvil` for integration tests), no Co-Authored-By trailer.

## Roadmap pushback (outcomes in "Decisions" above)

1. **Off-chain signatures bypass the whole design.** Permit2 / EIP-2612 permits, Seaport orders and other EIP-712 signatures never touch `eth_sendRawTransaction`. An injected agent can sign a Permit2 approval and hand it to the attacker, who spends it from *their* account. That's the most common drainer pattern today, and our proxy never sees it. *Agreed:* it goes into THREAT_MODEL.md in M2, and a pre-sign / typed-data inspection milestone is added before v0.1.
2. **Multi-tx flows (approve then swap).** Each tx is simulated alone against the head. If tx 2 arrives before tx 1 is mined upstream, tx 2 fails the nonce check in sim and gets blocked. That's fail closed but annoying. M2 accepts this. M4 should define "approved but not yet mined" pending state, and the mandate design (M3) should treat a sequence as one intent, since "approve X" alone means nothing without the swap that follows.
3. **Don't over-build M2.** The new ideas are in M3/M4. *Agreed:* hardening and the extra decoders are deferred.
4. **`httpx2` dev dependency** (2.13.1, published 2026-09-23, added in d62124c). The original claim here was that nothing imports it and that its name, one character off `httpx`, suggested a typosquat. **That was wrong (corrected 2026-10-07).** Our code doesn't import it, but Starlette 1.7.0's `starlette/testclient.py` does: it tries `import httpx2 as httpx` first and falls back to `httpx` with a `StarletteDeprecationWarning`. Starlette lists `httpx2` in its `[full]` extra. The package appears to be Pydantic's: its metadata and project URLs point to `github.com/pydantic/httpx2`, a real repo owned by the Pydantic organization. However, metadata is self-declared, and the PyPI upload has **no provenance attestation** (PyPI's integrity API returns 404 for the 2.13.1 wheel, while Starlette's wheel is attested), so nothing cryptographically ties the upload to that repo. *Decision:* remove it anyway, since we don't need it. `httpx` is already a runtime dependency and the fallback works, so the dev environment loses nothing. Commit 0 filters only that one deprecation message. If a future Starlette drops the `httpx` fallback, revisit this (and check for provenance by then).
