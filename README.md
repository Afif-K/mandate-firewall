# Mandate Firewall (beta, work in progress)

Open-source, wallet-agnostic firewall for AI agents that transact onchain.
It checks each transaction an agent sends against the user's original instruction
(the *mandate*) and blocks anything that doesn't match.

**Status: Milestone 2 complete.** Today this is a JSON-RPC proxy with a strict
default-deny front door. It runs every transaction your agent sends on a private
fork of the chain *before* forwarding it, records what the transaction actually
did (ETH and token movements, approvals, every contract call), and blocks it if
it can't be simulated cleanly or would revert. **It does not check transactions
against a mandate yet**, so an injected transfer that simulates fine is still
forwarded (with its effects on record). Read [THREAT_MODEL.md](THREAT_MODEL.md)
for exactly what it does and doesn't protect against. Use testnets and local
forks only.

## Quickstart

Requires [uv](https://docs.astral.sh/uv/) and [Foundry](https://book.getfoundry.sh/):
`anvil` runs the firewall's private simulation fork, and the examples use `cast`.

```bash
git clone <this repo> && cd mandate-firewall
uv sync
```

**1. Start a local chain** (terminal 1). Chain id 84532 is Base Sepolia's, so the
firewall simulates it in OP-stack mode, as it would the real testnet:

```bash
anvil --chain-id 84532
```

**2. Start the firewall in front of it** (terminal 2):

```bash
uv run mandate-firewall serve --upstream http://127.0.0.1:8545
```

It fetches the chain id from the upstream, then starts its own anvil as a fork
of the upstream and checks the fork (same chain id, same block hash, tracing
works). If anything fails, it refuses to start. It then listens on
`http://127.0.0.1:8546`. Look for `simulation node ready` in its log.

**3. Point your agent's RPC URL at the firewall** (`http://127.0.0.1:8546`)
instead of the node. The firewall never needs your private key: the agent signs
as usual, and the firewall inspects (and simulates) the signed transaction.

Try it with `cast` (terminal 3). The key is anvil's public dev account 0:

```bash
KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
FW=http://127.0.0.1:8546

# A normal transfer: simulated, audited with its effects, forwarded, mined.
cast send --rpc-url $FW --private-key $KEY 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 --value 0.01ether

# Signed for another chain: blocked (-32003), never simulated, never reaches the node.
cast send --rpc-url $FW --private-key $KEY --chain 1 --legacy 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 --value 1

# Asking the node to sign or cheat: denied (-32601).
cast rpc --rpc-url $FW anvil_setBalance 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 0x1
```

**4. Read the audit log.** One JSON line per transaction, allowed or blocked.
Simulated ones carry their effects (a transaction blocked before simulation,
like the wrong-chain one, has none):

```bash
tail -n 2 logs/audit.jsonl | jq '{decision, reason, hash, sender, to, value}'
tail -n 2 logs/audit.jsonl | jq 'select(.effects) | .effects | {status, native_balance_changes, token_transfers}'
```

Integers (`value`, balance changes, token amounts, gas) are decimal strings,
because 256-bit numbers don't survive JSON parsers that use floats.

**5. The full M2 demo.** With anvil and the firewall running as above,
[`scripts/demo_m2.sh`](scripts/demo_m2.sh) walks through seven steps, pausing
between each: an ETH transfer, an ERC-20 transfer checked against the token's
storage, a reverting transfer that's blocked, a token whose events lie, a denied
cheat method, and the simulator being killed and restarted.

```bash
scripts/demo_m2.sh
```

## Configuration

Flags override environment variables (or a `.env` file; see
[.env.example](.env.example)).

| Flag | Env var | Default | |
|---|---|---|---|
| `--upstream` | `UPSTREAM_RPC_URL` | `http://127.0.0.1:8545` | Put URLs that contain an API key in the env, not on the command line. |
| `--host` | `PROXY_HOST` | `127.0.0.1` | The proxy has no authentication; keep it on loopback. |
| `--port` | `PROXY_PORT` | `8546` | |
| `--audit-log` | `AUDIT_LOG_PATH` | `logs/audit.jsonl` | Created with mode 0600: it contains signed transactions. |
| `--log-level` | `LOG_LEVEL` | `INFO` | `DEBUG` also logs every forwarded read method. |
| | `ALLOW_LEGACY_UNPROTECTED` | `false` | Allow pre-EIP-155 transactions (replayable on any chain). |
| | `ANVIL_PATH` | `anvil` | The anvil binary for the simulation fork: a name on `PATH` or a path. |
| | `SIMULATION_TIMEOUT_SECONDS` | `10` | A transaction not simulated in time is blocked. |
| | `MAX_TOKEN_STATE_CHECKS` | `50` | Token balance/allowance checks per transaction; more and it's blocked. |
| | `SIMULATOR_NETWORK` | `auto` | `auto`, `ethereum` or `optimism`. `auto` picks `optimism` for Base and OP Mainnet (and their Sepolia testnets). Set `optimism` for other OP-stack chains. |

## Development

```bash
uv sync                  # creates .venv with Python 3.12 and installs dev deps
uv run pytest            # all tests; anvil/forge ones are skipped if Foundry isn't installed
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
