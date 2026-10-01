# Mandate Firewall (beta, work in progress)

Open-source, wallet-agnostic firewall for AI agents that transact onchain.
It checks each transaction an agent sends against the user's original instruction
(the *mandate*) and blocks anything that doesn't match.

Status: Milestone 1 (RPC proxy). Not ready for use.

## Development

Requires [uv](https://docs.astral.sh/uv/) and [Foundry](https://book.getfoundry.sh/) (for `anvil`).

```bash
uv sync                  # creates .venv with Python 3.12 and installs dev deps
uv run pytest            # run tests
uv run ruff check .      # lint
uv run ruff format .     # format
```

## License

Apache-2.0. See [LICENSE](LICENSE).
