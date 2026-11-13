# Security policy

## Status

Mandate Firewall is **beta software (v0.1)**. Use it on testnets and local forks
only, never with real funds. It has not had an external security audit.
[THREAT_MODEL.md](THREAT_MODEL.md) describes exactly what it protects against and
what it doesn't.

Only the latest release on `main` gets fixes.

## Reporting a vulnerability

Please report vulnerabilities **privately**, through GitHub's private
vulnerability reporting: the repository's **Security** tab, then **Report a
vulnerability**. Don't open a public issue or pull request for a vulnerability.

A useful report says:

- what you did, and the mandate it ran under;
- what the firewall decided (allow, block or escalate) and what it should have
  decided;
- how to reproduce it, ideally on a local anvil chain with anvil's public dev
  keys.

Never include real private keys, seed phrases or API keys in a report.

This is a beta maintained by one person, so responses are best effort.

## Scope

In scope, for example:

- a transaction the firewall allows although its effects don't match the mandate;
- any way for the agent (or content it reads) to create, change or extend a
  mandate, or to learn a mandate's values (budgets, what's left, swap minimums);
- any way for an LLM, or attacker-controlled data such as token names, calldata
  or revert data, to influence an allow, block or escalate decision;
- the firewall failing open: forwarding a transaction when decoding, simulation
  or verification fails, or forwarding a method that isn't on its read-only
  allowlist;
- a gap that THREAT_MODEL.md doesn't list, or one that is worse than it says.

Known gaps listed under "What it does NOT protect against" in THREAT_MODEL.md
are known; a new variant of one, or evidence that one is worse than described,
is still welcome.

Out of scope: the rule-based guard in `benchmark/` (it exists only for the
comparison and isn't part of the product), the test contracts under `tests/`,
and anything that needs real funds to demonstrate.
