# Mandate Firewall (beta, work in progress)

Open-source, wallet-agnostic firewall for AI agents that transact onchain.
It checks each transaction an agent sends against the user's original instruction
(the *mandate*) and blocks anything that doesn't match.

**Status: Milestone 4 complete.** Today this is a JSON-RPC proxy with a strict
default-deny front door. You lock a *mandate* (what the agent may send or swap,
to whom, via which venue, how much in total, for how long, in how many
transactions) with the capture CLI, before the agent starts. The proxy runs
every transaction on a private fork of the chain *before* forwarding it, and a
deterministic matcher compares what the transaction actually did (ETH and token
movements, approvals, contracts called) with the mandate:

```
BLOCKED  tx 0xa679…8640
  under mandate 0x647d…b7f9
You asked:
  1. SEND at most 0.01 ETH (native)
       to 0x70997970C51812dc3A010C7d01b50e0d17dc79C8
       left before this transaction: 0.006 ETH
This transaction:
  sends 0.001 ETH (native) to 0x000000000000000000000000000000000000dEaD
Why:
  - it sends 0.001 ETH (native) to 0x000000000000000000000000000000000000dEaD, a recipient your mandate doesn't name
Nothing was charged.
```

It catches transactions that pass every spend limit and allowlist but aren't
what you asked for: a swap through the right router, of the right token, within
budget, whose output goes to an attacker. It blocks off-mandate transactions,
escalates ones it can't interpret (blocks them with a louder alert), and
charges allowed ones against the mandate's budgets. No LLM decides anything.

Verification is only as good as the simulation: a contract that behaves in
simulation and steals on chain still gets through. Read
[THREAT_MODEL.md](THREAT_MODEL.md) for exactly what it does and doesn't protect
against. Use testnets and local forks only.

## Quickstart

Requires [uv](https://docs.astral.sh/uv/) and [Foundry](https://book.getfoundry.sh/):
`anvil` runs the firewall's private simulation fork, and the examples use `cast`.

```bash
git clone <this repo> && cd mandate-firewall
uv sync
cp .env.example .env   # local defaults: agent account = anvil dev account 0, chain 84532
```

**1. Start a local chain** (terminal 1). Chain id 84532 is Base Sepolia's, so the
firewall simulates it in OP-stack mode, as it would the real testnet:

```bash
anvil --chain-id 84532
```

**2. Lock a mandate** (terminal 2). Give your instruction to the firewall, not to
the agent. An agent may already have read a poisoned web page, and an
instruction that passes through it can be rewritten. With the structured flags
(no LLM, nothing leaves your machine):

```bash
uv run mandate-firewall mandate new --send 0.01 ETH \
    --to 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 --max-transactions 3
```

```
Mandate for agent account 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
  on Base Sepolia (chain 84532)
  valid until 2026-11-06 21:36:58 UTC (in 30 min)
  you said: "send 0.01 ETH to 0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

  1. SEND at most 0.01 ETH (native)
       to 0x70997970C51812dc3A010C7d01b50e0d17dc79C8

  At most 3 transactions. Nothing else may leave this account.

Type "yes" to lock this mandate: yes
Locked mandate 0x32528771a79aaada74f6fbd436a924d9e5fea69ccafbdac8fef1eecf44b532d6
Now give the agent its task.
```

Read the summary before you type `yes`. Addresses are shown in full on purpose:
look-alike addresses copy the first and last characters. The mandate is stored
in `state/mandates.db` (mode `0600`), locked by its hash: to change it, revoke
it and create a new one. It expires after `MANDATE_LIFETIME_MINUTES` (default
30, at most 24 hours) or after `--max-transactions` transactions.

Or write the instruction in words. An LLM parses it, and every amount, address
and token in the result must appear in what you wrote, or the CLI asks you
instead of guessing. Set `LLM_API_KEY` in `.env` (never on the command line),
then:

```bash
uv run mandate-firewall mandate new "send 0.01 ETH to 0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
```

> **Privacy:** with an instruction in words, its full text, including amounts
> and addresses, is sent to the LLM provider (`LLM_BASE_URL`, api.anthropic.com
> by default). The CLI says so before it sends anything. The structured flags
> (`--send … --to …`, `--swap … --for … --via … --min-out …`) use no LLM.

A swap needs a minimum, the least you'll accept back. Without one, an agent
could sell your tokens through the right router and receive almost nothing:

```bash
uv run mandate-firewall mandate new --swap 100 USDC --for WETH --via uniswap --min-out 0.03
```

Manage mandates with `mandate list`, `mandate show <id>` and
`mandate revoke <id>` (an 8+ digit prefix of the id works). Revoking takes
effect at the firewall's next transaction.

**3. Start the firewall in front of the chain** (terminal 3):

```bash
uv run mandate-firewall serve --upstream http://127.0.0.1:8545
```

It opens the mandate store (and refuses to start without one), fetches the chain id from the upstream, then starts its own anvil as a fork
of the upstream and checks the fork (same chain id, same block hash, tracing
works). If anything fails, it refuses to start. It then listens on
`http://127.0.0.1:8546`. Look for `simulation node ready` in its log.

**4. Point your agent's RPC URL at the firewall** (`http://127.0.0.1:8546`)
instead of the node. The firewall never needs your private key: the agent signs
as usual, and the firewall inspects (and simulates) the signed transaction.

Try it with `cast` (terminal 4). The keys are anvil's public dev accounts 0 and 2:

```bash
KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
FW=http://127.0.0.1:8546

# The transfer you asked for: simulated, verified, charged to the mandate, audited, forwarded, mined.
cast send --rpc-url $FW --private-key $KEY 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 --value 0.004ether

# The same account paying someone else: blocked (-32003, "off-mandate: ... recipient not in mandate").
cast send --rpc-url $FW --private-key $KEY 0x000000000000000000000000000000000000dEaD --value 0.001ether

# More than the 0.006 ETH left: blocked (-32003, "off-mandate: over budget").
cast send --rpc-url $FW --private-key $KEY 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 --value 0.007ether

# An account with no mandate: blocked (-32003), never simulated, never reaches the node.
cast send --rpc-url $FW --private-key 0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a \
    0x70997970C51812dc3A010C7d01b50e0d17dc79C8 --value 0.01ether

# Signed for another chain: blocked (-32003), never simulated, never reaches the node.
cast send --rpc-url $FW --private-key $KEY --chain 1 --legacy 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 --value 1

# Asking the node to sign or cheat, or the firewall for a mandate: denied (-32601).
cast rpc --rpc-url $FW anvil_setBalance 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 0x1
cast rpc --rpc-url $FW mandate_new '{}'
```

The agent's error says *why* (as a phrase and as codes in `error.data`, such
as `wrong_recipient` or `over_budget`) but never your budget, what's left or
your swap minimum: an injected agent could use those.

**5. Read the alerts and the audit log.** Blocked and escalated transactions
are listed with their full "You asked / This transaction" explanation. They are
never held for approval: if one surprises you, revoke the mandate or lock a new
one.

```bash
uv run mandate-firewall alerts               # --escalations for anomalies only, --last N
```

The audit log has one JSON line per transaction, allowed or blocked. Each names
the mandate it was checked against. Verified ones carry the effects, the
verdict (decision, violations, anomalies, charges) and the explanation:

```bash
tail -n 3 logs/audit.jsonl | jq '{decision, reason, mandate_id, mandate_transaction, violations: [.verdict.violations[]?.code]}'
tail -n 1 logs/audit.jsonl | jq -r .explanation
```

The audit log contains your mandate's values (budgets, minimums) and signed
transactions: the agent must not be able to read it.

Integers (`value`, balance changes, token amounts, gas) are decimal strings,
because 256-bit numbers don't survive JSON parsers that use floats.

**6. The demos.** [`scripts/demo_m4.sh`](scripts/demo_m4.sh) needs nothing
running: it starts its own anvil and firewall on spare ports, in a temporary
directory it deletes at the end, pausing between steps. It locks "at most 0.01
ETH to Bob" and shows a payment allowed and charged, a transfer to another
address blocked, an over-budget payment blocked, and the exact rest of the
budget allowed (the mandate is then used up). Then, on a mock router shaped
like Uniswap's SwapRouter02, it locks "swap 100 mUSD for at least 0.03 mETH"
and shows an unlimited approval blocked, an exact approval allowed, **a swap
whose output goes to an attacker blocked**, a manipulated price blocked, a
`pull` + `sweep` drain blocked, and the honest swap allowed. It ends with
`mandate-firewall alerts`. You type `yes` twice.

```bash
scripts/demo_m4.sh
```

[`scripts/demo_m3.sh`](scripts/demo_m3.sh) is self-contained too. It shows
mandates: the firewall refusing to start without a store, an account without a
mandate blocked, the transaction cap, a live revoke, the missing mandate
methods, and a tampered store row.

## Configuration

Flags override environment variables (or a `.env` file; see
[.env.example](.env.example)).

| Flag | Env var | Default | |
|---|---|---|---|
| `--upstream` | `UPSTREAM_RPC_URL` | `http://127.0.0.1:8545` | Put URLs that contain an API key in the env, not on the command line. |
| `--host` | `PROXY_HOST` | `127.0.0.1` | The proxy has no authentication; keep it on loopback. |
| `--port` | `PROXY_PORT` | `8546` | |
| `--audit-log` | `AUDIT_LOG_PATH` | `logs/audit.jsonl` | Created with mode 0600: it contains signed transactions. |
| `--mandate-db` | `MANDATE_DB_PATH` | `state/mandates.db` | The mandate store. The firewall refuses to start without it and only ever writes transaction counters and budget spending to it. |
| `--registry` | `REGISTRY_PATH` | (shipped) | A directory with your own `<chain_id>.json` token and venue registry. The firewall refuses to start without a valid registry for the upstream's chain. |
| `--log-level` | `LOG_LEVEL` | `INFO` | `DEBUG` also logs every forwarded read method. |
| | `ALLOW_LEGACY_UNPROTECTED` | `false` | Allow pre-EIP-155 transactions (replayable on any chain). |
| | `ANVIL_PATH` | `anvil` | The anvil binary for the simulation fork: a name on `PATH` or a path. |
| | `SIMULATION_TIMEOUT_SECONDS` | `10` | A transaction not simulated in time is blocked. |
| | `MAX_TOKEN_STATE_CHECKS` | `50` | Token balance/allowance checks per transaction; more and it's blocked. |
| | `SIMULATOR_NETWORK` | `auto` | `auto`, `ethereum` or `optimism`. `auto` picks `optimism` for Base and OP Mainnet (and their Sepolia testnets). Set `optimism` for other OP-stack chains. |

The capture CLI (`mandate-firewall mandate …`) reads its own settings. The
firewall never reads them, and never holds the LLM key:

| Env var | Default | |
|---|---|---|
| `MANDATE_DB_PATH` | `state/mandates.db` | Created `0600` in a `0700` directory by `mandate new`. |
| `MANDATE_PRINCIPALS` | (none) | The agent accounts mandates may be created for, comma-separated, each with its exact EIP-55 checksum. |
| `MANDATE_CHAIN_ID` | `84532` | Picks the token and venue registry. |
| `MANDATE_LIFETIME_MINUTES` | `30` | Default lifetime, 1 to 1440 (`--minutes` overrides). |
| `MANDATE_MAX_TRANSACTIONS` | `3` | Default transaction cap (`--max-transactions` overrides). |
| `REGISTRY_PATH` | (shipped) | A directory with your own `<chain_id>.json` registry. |
| `ADDRESS_BOOK_PATH` | (none) | JSON `{"Bob": "0x…"}` for named recipients. Refused if other users can write it. |
| `LLM_API_KEY` | (none) | For instructions in words. From the environment or `.env` only. |
| `LLM_MODEL` | `claude-opus-5-5` | |
| `LLM_BASE_URL` | `https://api.anthropic.com` | https only (plain http for loopback). |

## Development

```bash
uv sync                  # creates .venv with Python 3.12 and installs dev deps
uv run pytest            # all tests; anvil/forge ones are skipped if Foundry isn't installed
uv run pytest -m llm     # opt-in: the live LLM extractor test (needs LLM_API_KEY; costs a few calls)
uv run pytest -m anvil   # only the integration tests against a real anvil
uv run ruff check .      # lint
uv run ruff format .     # format
```

The test contracts in `tests/fixtures/contracts/` are committed as compiled
artifacts, so tests don't need a Solidity compiler. To rebuild them (forge, solc
0.8.37): `uv run python tests/fixtures/contracts/build.py`, or add `--check` to
verify the committed artifacts are reproducible.

## License

Apache-2.0. See [LICENSE](LICENSE).
