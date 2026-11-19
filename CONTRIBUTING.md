# Contributing

Thanks for your interest. This is a beta: read the [README](README.md) and
[THREAT_MODEL.md](THREAT_MODEL.md) first. For a security issue, follow
[SECURITY.md](SECURITY.md) instead of opening an issue.

## Setup

You need [uv](https://docs.astral.sh/uv/) and, for the integration tests,
[Foundry](https://book.getfoundry.sh/) (`anvil`, `forge`).

```bash
uv sync
```

## Before you open a pull request

```bash
uv run ruff check .
uv run ruff format --check .
uv run pytest                  # unit and integration tests (anvil/forge ones skip without Foundry)
uv run pytest -m benchmark     # the 51 scenario-suite cells, about a minute; CI runs them too
```

The website's browser tests need Chrome and skip without it; set
`REQUIRE_BROWSER=1` to make a missing Chrome an error, as CI does.

- **Every verifier rule and every attack scenario gets a test.**
- **Update THREAT_MODEL.md in the same pull request** when a change affects what
  the firewall protects against, or doesn't.
- If you change a scenario or an expectation, rerun `uv run python -m benchmark`
  and commit the regenerated `benchmark/results.json`, `benchmark/RESULTS.md` and
  `benchmark/traces.json`. Never edit them by hand: each suite cell checks its run
  against `traces.json`. The website rebuilds from them on the next push.
- **The website's prose is hand-written; its numbers aren't.** Tables, recorded
  runs and the A5 example come from the suite's files. The pitch, "How it works"
  and the known gaps in `website/index.html.in` are text. When a change alters
  THREAT_MODEL.md's top gaps or the README's pitch, update them in the same pull
  request.
- Type hints everywhere; Pydantic models for structured data.
- Small, focused commits with clear messages.

## Design rules a change must keep

- Never touch private keys: inspect already-signed transactions only.
- The agent can never create or modify a mandate.
- The deterministic matcher alone allows, blocks or escalates. No LLM is in that
  path, and no LLM sees untrusted content (calldata, logs, revert data, token
  names).
- Fail closed: if decoding, simulation or verification fails, block or escalate.
- Default-deny RPC methods: forward only an explicit allowlist of read methods.

## Safety

Testnets and local anvil chains only. Use anvil's public dev keys or throwaway
keys, never real ones, and never commit a `.env` file. Before a release,
`scripts/audit_history.py` and gitleaks (with the repo's `.gitleaks.toml`) check
the whole history.

## License

By contributing, you agree that your contributions are licensed under the
Apache License 2.0, like the rest of the project (see [LICENSE](LICENSE)).
