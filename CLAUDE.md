# Mandate Firewall (working name)

Open-source, wallet-agnostic firewall for AI agents that transact onchain.

## What this project does
Before an AI agent's transaction reaches the blockchain, the firewall:
1. Captures the user's original instruction as a locked, structured **mandate**
   (action, assets, amount bounds, counterparties/venues, expiry) BEFORE the
   agent reads any untrusted content.
2. Simulates each proposed transaction on a forked chain (Anvil) to get its
   real effects: balance deltas, approvals, recipients, contracts touched.
3. Verifies the effects against the mandate with a deterministic matcher,
   which alone decides. No LLM allows or blocks a transaction.
4. Returns allow / block / escalate, with a plain-English diff:
   "You asked: X. This transaction does: Y."

The goal: catch prompt-injected transactions that pass every spend limit and
allowlist but are not what the user asked for. Existing wallet guardrails
(Coinbase, Safe, Privy, etc.) are rule-based; we sit on top of them and add
intent verification. Inspired by the trusted/untrusted separation in
"Defeating prompt injections by design" (CaMeL).

## Goals
- A tool developers actually use: protect an agent in under 5 minutes.
- A public benchmark comparing: no defense vs rule-based guardrails vs
  mandate verification, including "within-policy, off-mandate" attacks.
- Credibility in AI engineering and AI security.

## Non-negotiable design principles
- **Never touch private keys.** Inspect already-signed transactions
  (`eth_sendRawTransaction`); refuse to forward blocked ones.
- **The agent can never modify a mandate.** Mandates come only from the
  user's trusted instruction and are confirmed by the user.
- **The verifier LLM never sees untrusted content.** It receives only the
  mandate and simulated effects. Replace attacker-controlled strings (e.g.
  token names/symbols) with canonical values from a verified registry.
- **The LLM can only make decisions stricter.** Deterministic checks are a
  hard gate; the LLM may escalate or block, never override a block.
- **Fail closed.** If decoding, simulation, or the LLM fails, block or
  escalate. Never silently allow.
- **Default-deny RPC methods.** Intercept transaction-sending methods,
  forward an explicit allowlist of read-only methods, reject everything else.
- **No unverified startup.** If the upstream RPC is unreachable at startup
  (so its chainId can't be fetched), refuse to start.
- **Honest about limits.** Maintain a threat model; label releases beta.

## Out of scope (do not build)
Wallets, key management, a large policy engine. Keep a minimal rule layer
and focus effort on mandate capture, verification, and evaluation.

## Architecture
```
agent -> [RPC proxy] -> decode -> simulate (Anvil fork) -> effects
                                                      |
user instruction -> [mandate capture] -> locked mandate
                                                      v
                              verifier (matcher + isolated LLM)
                                                      v
                      allow (forward) / block / escalate (human)
                                   + audit log
```
Entry points: RPC proxy first; later an MCP server and wallet pre-sign hooks.

## Tech stack
Python 3.12 (pinned via uv; package supports >=3.11), web3.py, FastAPI, Foundry/Anvil, Pydantic, SQLite, an LLM API,
Slack/Telegram for escalation. Development on testnet (Base Sepolia).
License: Apache-2.0. Packaging: pip-installable + Docker.
Env & deps: `uv sync`, then `uv run pytest`, `uv run ruff check .`.

## Conventions
- Type hints everywhere; Pydantic models for all structured data
  (transactions, effects, mandates, verdicts).
- Tests with pytest; every verifier rule and attack scenario gets a test.
- Lint/format with ruff.
- Small, focused commits with clear messages.
- Do not add Co-Authored-By trailers to commit messages.
- Config and secrets via environment variables; `.env` is gitignored and
  never committed. Provide `.env.example`.

## Safety rules for development
- Testnet and local Anvil forks only. Never use real funds or real private
  keys. Generate throwaway test keys for local testing.
- Never print or log private keys or API keys.

## Roadmap
- [x] M1: RPC proxy that intercepts `eth_sendRawTransaction`, decodes, logs, forwards
- [x] M2: Anvil simulation producing structured effects (plan and decisions: docs/m2-plan.md)
- [x] M3: Mandate capture: user instruction -> locked, structured mandate
      (plan and decisions: docs/m3-plan.md)
- [x] M4: Verifier: the deterministic matcher decides; explanations are deterministic
      templates (the optional LLM `explain` command is deferred). Anomalies escalate:
      block plus alert, and the human acts on the mandate, never on a transaction.
      Swaps require a minimum (plan and decisions: docs/m4-plan.md)
- [ ] M5: Standing mandates: per-period budgets and transaction caps, expiries beyond
      24 hours, renewal and revocation. Human input once per mandate, never per
      transaction; transaction-time decisions are fully automated
- [ ] M6: Real agent integration; demo an injection that rule-based guardrails miss.
      Capture must sit in front of the agent: the user's instruction reaches the
      firewall before the agent reads any untrusted content
- [ ] M7: Pre-sign / typed-data inspection: check EIP-712 signatures before the agent
      signs them (Permit2 and EIP-2612 permits at minimum). Off-chain signatures never
      reach eth_sendRawTransaction, so the proxy can't see them (see THREAT_MODEL.md)
- [ ] Router calldata check (before v0.1): decode known router calldata (SwapRouter02
      `exactInputSingle`, `exactInput`, `multicall`) and require the router's own
      `amountOutMinimum` to be at least the mandate's minimum for the amount sold.
      The simulated-fill check doesn't protect the real fill if the price moves after
      simulation (see THREAT_MODEL.md). Venue calls that can't be decoded are blocked
- [ ] v0.1 release: README, demo GIF, quickstart, threat model
- [ ] M8: Benchmark (build on CrAIBench/AgentDojo scenarios), results, open dataset, writeup
- [ ] M9: User-wallet EIP-712 mandate signing: the user's own wallet signs the canonical
      mandate and the firewall checks the signer. (Placement before/after v0.1 is open.)

**Current milestone: M5**

## How to work with me
- I'm a CS/AI engineering student building this to learn deeply and to ship
  something real. Explain your reasoning step by step, with examples.
- Propose a plan before writing significant code; wait for my OK.
- Explain *why* the code works, not just what it does, especially for
  blockchain concepts (transactions, RLP, calldata, ABIs, forking).
- Push back when a design choice is weak or insecure, and suggest better options.
- Keep me focused on the current milestone.
