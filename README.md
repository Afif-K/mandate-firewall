# Mandate Firewall (beta, work in progress)

Open-source, wallet-agnostic firewall for AI agents that transact onchain.
It checks each transaction an agent sends against the user's original instruction
(the *mandate*) and blocks anything that doesn't match.

**Status: Milestone 1 complete.** Today this is a JSON-RPC proxy that decodes,
audits and forwards every transaction your agent sends, with a strict
default-deny front door. **It does not check transactions against a mandate
yet**, so an injected transfer that is well-formed and for the right chain is
still forwarded. Read [THREAT_MODEL.md](THREAT_MODEL.md) for exactly what it
does and doesn't protect against. Use testnets and local forks only.

## Quickstart

Requires [uv](https://docs.astral.sh/uv/) and [Foundry](https://book.getfoundry.sh/)
(for `anvil` and `cast`).

```bash
git clone <this repo> && cd mandate-firewall
uv sync
```

**1. Start a local chain** (terminal 1):

```bash
anvil
```

**2. Start the firewall in front of it** (terminal 2):

```bash
uv run mandate-firewall serve --upstream http://127.0.0.1:8545
```

It fetches the chain id from the upstream and refuses to start if it can't.
It then listens on `http://127.0.0.1:8546`.

**3. Point your agent's RPC URL at the firewall** (`http://127.0.0.1:8546`)
instead of the node. The firewall never needs your private key: the agent signs
as usual, and the firewall inspects the signed transaction.

Try it with `cast` (terminal 3). The key is anvil's public dev account 0:

```bash
KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
FW=http://127.0.0.1:8546

# A normal transfer: decoded, audited, forwarded, mined.
cast send --rpc-url $FW --private-key $KEY 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 --value 0.01ether

# Signed for another chain: blocked (-32003), never reaches the node.
cast send --rpc-url $FW --private-key $KEY --chain 1 --legacy 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 --value 1

# Asking the node to sign or cheat: denied (-32601).
cast rpc --rpc-url $FW anvil_setBalance 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 0x1
```

**4. Read the audit log.** One JSON line per transaction, allowed or blocked:

```bash
tail -n 2 logs/audit.jsonl | jq '{decision, reason, hash, sender, to, value}'
```

Integers from the transaction (`value`, gas fields, nonce, chain id) are
decimal strings, because 256-bit numbers don't survive JSON parsers that use
floats.

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

## Development

```bash
uv sync                  # creates .venv with Python 3.12 and installs dev deps
uv run pytest            # all tests; the anvil ones are skipped if anvil isn't installed
uv run pytest -m anvil   # only the integration tests against a real anvil
uv run ruff check .      # lint
uv run ruff format .     # format
```

## License

Apache-2.0. See [LICENSE](LICENSE).
