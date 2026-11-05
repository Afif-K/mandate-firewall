# M3 plan: mandate capture

Status: **approved 2026-10-09**. Commit 0 (this document) done.

## Decisions (agreed 2026-10-09)

1. **Mandates are effects-shaped budgets**, not scripts of calls. M3 supports two intents, `transfer` and `swap`. The schema is versioned (`schema_version`), and everything else is refused as unsupported. See §1.
2. **Option B for the trust boundary.** The user gives the instruction to the firewall directly, through the capture CLI. The agent RPC has **no** mandate methods: `methods.py` stays default-deny and a test asserts that `mandate_*` and `firewall_*` names are rejected. In CLAUDE.md, the real-agent-integration milestone gets an explicit requirement: in real integrations, capture sits *in front of* the agent, so the instruction reaches the firewall before the agent reads anything. See §3.
3. **Signing is deferred.** In M3 the boundary is OS permissions: the agent runs as a different user or container (already required since M1/M2) and can't reach the mandate store. A roadmap item is added for **user-wallet EIP-712 mandate signing**. See §3.
4. **The "no mandate → block" gate is on in M3** (commit 7). A transaction from a sender with no valid active mandate is blocked with `-32003`. See §4.
5. **The Messages API is called directly over our existing `httpx`; no Anthropic SDK** (revised 2026-11-05, in commit 5). The original decision was to use the SDK if a provenance re-check of `httpx2` passed. The check found no PyPI provenance attestations for the SDK or its HTTP stack (`anthropic`, `httpx2`, `httpcore2`). A missing attestation means the upload is **unverified, not malicious**: nothing cryptographically ties it to its source repository, so we can't check that it was built from the code its metadata points to. Our rule is to **minimize the unverified code we take on**. Calling the API directly adds no dependency at all (`httpx` is already one, and is itself unattested, so it doesn't make the rule absolute). **Only the capture code may call the LLM API or read its key. The proxy process must never load it**, and tests enforce this. See §5.
6. **Defaults:** expiry 30 minutes, hard cap 24 hours for one-shot mandates, `max_transactions` 3.
7. **Planned M4 direction** (agreed in principle): the deterministic matcher makes the decision. The LLM in M4 only writes explanations. It never allows or blocks anything. See "Roadmap pushback", item 3.
8. **Standing mandates are a core use case, not a footnote.** M3 stays one-shot, but the schema reserves the slots standing mandates need (a `kind` field, per-period budgets, expiries beyond 24 hours), so they can be added later without a schema rewrite. A **standing-mandates milestone** goes right after M4, before real agent integration, and the roadmap is renumbered. The reasoning: **human input happens once per mandate, never per transaction, and transaction-time decisions are fully automated.** See §1, "Designed for standing mandates", and §8.
9. **Typed addresses must carry their EIP-55 checksum** (decided 2026-11-05, after commit 4). All-lowercase and all-uppercase addresses are refused at capture, with a message that explains why: without a checksum, a typo can't be detected, and wallets and block explorers show the checksummed form. Frequent recipients go in the operator's address book, which is the low-friction path. The first version of commit 4 accepted lowercase with a warning note; that was changed in a follow-up commit. See §2.

## Context

M1 built the choke point and M2 tells us what each transaction does (`Effects`). M3 adds the other half: a **locked, structured statement of what the user asked for**, which reaches the firewall through a channel the agent can't write to. M4 compares `Effects` against it.

M3 makes no intent decisions. It adds one new reason to block: **no valid mandate covers this sender.** It does not check whether the transaction matches the mandate. That is M4, and THREAT_MODEL.md will say so plainly.

What exists today that M3 reuses:
- `Settings` (`config.py`) reads configuration from the environment. Secrets never come from command-line flags, the same rule as `UPSTREAM_RPC_URL`.
- The strict types in `models.py` (`Address`, `Uint256`, `Hash32`), so a mandate can't hold a non-checksummed address or a float amount.
- `AuditRecord` (`audit.py`) gains `mandate_id`.
- `Proxy._send_raw_transaction` (`proxy/app.py`) is where the gate goes, after `_check(tx)` and before simulation.
- The fail-closed and "refuse to start" patterns used for the audit log and the simulator.

---

## 1. The mandate schema

### Constrain effects, not calldata

There are two ways to describe what the user allowed:

- **Calldata-shaped:** "the agent may call `swapExactTokensForTokens` on router R with these arguments." This is brittle. The same intent can be carried out through `approve` + `swap`, Permit2, a multicall, or another router function. It also trusts decoded calldata, which M1 already labels as a claim (`models.py`, `DecodedCall`).
- **Effects-shaped:** "when this is over, the account may have lost **at most** 100 USDC and must have gained **at least** 0.03 WETH. Approvals may go **only** to router R and be **at most** 100 USDC. Nothing else may leave the account." This is what M2 measures, so M4 compares like with like.

We use the effects-shaped form.

### A mandate is a budget, not a script

For "swap 100 USDC for WETH on Uniswap", an agent might send one transaction (Permit2 or a multicall) or two (`approve`, then `swap`). An ordered list of steps would force us to guess which. Instead:

- **Intents** are outcomes (`transfer`, `swap`). Each has cumulative bounds that are spent across the transactions charged to the mandate.
- **Enablers** (token approvals) aren't intents. An approval is allowed only if it serves an active intent: the spender is one of that intent's venues, the token is its sell asset, and the amount is at most the remaining sell budget. **Unlimited approvals are never allowed.** M3 encodes the rule in the schema. M4 enforces it against effects.
- **Default deny:** any outflow from the principal that no intent covers is off-mandate. That includes ETH beyond gas, token transfers, approvals, `ApprovalForAll`, and unrecognized logs. Inflows are fine.

So approve-then-swap is one mandate, and both transactions draw on the same budget. Tracking what is spent (the ledger) is M4's job, because spending depends on verification. M3 defines the fields and the storage the ledger needs.

### Proposed model (`mandate/models.py`, frozen, strict types from `models.py`)

```python
class MandateKind(StrEnum):  ONE_SHOT = "one_shot"   # STANDING added by the standing-mandates milestone

class Period(BaseModel):     # reserved; M3 rejects any non-null period (see below)
    unit: Literal["day", "week", "month"]
    anchor: datetime          # windows start here and repeat every `unit`

class AssetRef(BaseModel):   # from the trusted registry, never from on-chain names or symbols
    chain_id: int
    address: Address | None   # None = native ETH
    decimals: int             # registry value, display only

class Budget(BaseModel):     # cumulative cap on what may leave the principal
    max: Uint256              # base units; required; < 2**256-1 (no "unlimited")
    period: Period | None     # None = over the mandate's whole life. M3: must be None

class Ratio(BaseModel):      # min_buy_per_sell = numerator / denominator, in base units
    numerator: Uint256
    denominator: Uint256      # > 0

class TransferIntent(BaseModel):
    kind: Literal["transfer"]
    asset: AssetRef
    budget: Budget
    recipient: Address        # exact

class SwapIntent(BaseModel):
    kind: Literal["swap"]
    sell: AssetRef
    sell_budget: Budget
    buy: AssetRef
    min_buy_per_sell: Ratio | None   # None = user gave no minimum (flagged at confirmation)
    venues: tuple[Address, ...]      # routers from the registry; also the only allowed spenders
    # implicit, checked by M4: the bought asset must arrive at the principal

Intent = Annotated[TransferIntent | SwapIntent, Field(discriminator="kind")]

class Limits(BaseModel):
    max_transactions: int     # default 3
    period: Period | None     # M3: must be None (the cap is over the mandate's whole life)

class Mandate(BaseModel):
    schema_version: Literal[1]
    kind: MandateKind
    chain_id: int
    principal: Address        # the agent account this mandate governs
    intents: tuple[Intent, ...]   # 1..N
    limits: Limits
    created_at: datetime
    expires_at: datetime      # one_shot: at most 24 h after created_at
    instruction: str          # the user's text (trusted), for the audit log and M4's diff
    nonce: Hash32             # random, so two identical instructions get different ids
```

Why the swap minimum is a ratio and not an absolute amount: "at least 0.03 WETH for 100 USDC" is the same as "at least 0.0003 WETH per USDC". For a one-shot swap the two are equivalent. For a standing "buy WETH with 50 USDC every week" only the ratio makes sense, and it also handles partial fills. M4 checks it with integers, no division: `bought × denominator ≥ sold × numerator`.

### Designed for standing mandates (Decision 8)

Autonomy is the point of the project: the user says once "pay rent of 1,000 USDC to 0xLandlord on the 1st of every month" or "DCA 50 USDC into WETH weekly", and the agent acts for months. The principle:

> **Human input happens once per mandate, never per transaction. Transaction-time decisions are fully automated.**

That's why the user's attention goes to the moment of capture, where a human is present and reads a deterministic summary. At transaction time no human is there, and nothing in the decision path may need one. Escalation remains for anomalies. It is never the normal way to approve a transaction. It's also why the LLM belongs at capture, not at verification (Decision 7).

What the M3 schema already contains so standing mandates fit without a rewrite:
- `kind`. Standing mandates add the `STANDING` value. The field itself doesn't change.
- `Budget.period` and `Limits.period`. A standing mandate sets them: "at most 1,000 USDC per month, at most 2 transactions per month". The ledger's storage is keyed by `(mandate_id, period_start)` from M3 on (§3), so per-period spending needs no new tables.
- `expires_at` is just a timestamp. The 24-hour cap is a validator rule tied to `kind = one_shot`, not a type limit. Standing mandates get their own cap.
- `Ratio` for swap minimums (above).

Why the fields exist now and aren't added later: the mandate id is a hash of the canonical JSON (§3). If a field is added later with a default, either old mandates hash differently or "field missing" and "field = null" have to mean the same thing, which is a classic source of parser differentials. With every field present from version 1 (`period: null`), the standing milestone only adds enum values and relaxes validators.

What stays open for the standing milestone: whether `Period` keeps its exact shape (fixed windows from an anchor vs. rolling windows), calendar months and time zones, how a one-shot and a standing mandate coexist for one principal (M3 allows one active mandate per principal), renewal and revocation UX, and caps on lifetime and total exposure. **M3 rejects any non-null `period`, so no stored M3 mandate depends on the reserved shape.** If the standing milestone changes `Period`, nothing stored breaks.

### Mandate ↔ Effects (the contract with M4)

| Mandate field | Compared against in `Effects` |
|---|---|
| `chain_id`, `principal` | `effects.chain_id`, `effects.sender` |
| transfer `asset`, `budget.max`, `recipient` | `token_transfers` from the principal, or `native_balance_changes` for ETH (gas excluded using `gas_cost`) |
| swap `sell`, `sell_budget.max` | the principal's net outflow of `sell` (transfers out minus in) |
| swap `min_buy_per_sell` | the principal's net inflow of `buy` vs. its net outflow of `sell` |
| swap `venues` | `token_approvals[].spender`, and `calls[].target` at depth 1 |
| "nothing else leaves" | every other negative delta, approval, `operator_approvals` entry and `unrecognized_logs` entry → off-mandate or escalate |
| (not a mandate field) | `token_state_checks[].consistent == False` → escalate, whatever the mandate says |

Worked example. The user says "swap 100 USDC for WETH on Uniswap". The injected transaction is a real Uniswap swap of 100 USDC with `recipient = attacker`. It passes a spend limit and a router allowlist. Its effects: the principal loses 100 USDC, gains 0 WETH, and the WETH `Transfer` goes to the attacker. Inflow of `buy` to the principal is 0, below any minimum and below the implicit "bought asset arrives at the principal" rule, so it's off-mandate.

### Why not AP2's format

Google's Agent Payments Protocol (AP2) chains signed mandates. An *IntentMandate* is signed by the user (natural-language description, merchants, SKUs, refundability, intent expiry), a *CartMandate* is signed by the merchant (exact items and price), and a *PaymentMandate* goes to the payment network. Each is a JWS token signed with ES256.

We don't adopt the format. AP2's intent constraints are commerce-shaped (merchants, SKUs, refunds) and partly natural language, and they're largely enforced by a merchant checking a cart. Ours must be fully structured and machine-checkable against EVM effects with nobody in the loop. We do take its ideas: intent kept separate from execution (mandate vs. effects, like IntentMandate vs. CartMandate), mandatory expiry, a user-attested object (EIP-712 signing later, Decision 3), and a human present at creation. An `export --ap2` adapter is possible later. Not M3.

---

## 2. Capture: instruction → mandate

### The LLM is a parser whose output nobody trusts

The security control is **the user confirming a summary rendered deterministically from the compiled mandate**. The LLM only saves typing.

```
user text ──► LLM extractor ──► Draft (strings only) ──► compiler (pure Python) ──► Mandate ──► rendered summary ──► user types "yes"
                 ▲                                  │ ambiguity / grounding failure
                 └──────── clarifying question ◄────┘ (the answer is appended as trusted user text)
```

**Step 1, extraction (LLM).** One call with structured outputs (the API constrains the response to a JSON schema). The response is a **Draft**, deliberately weaker than a Mandate. Every value is a string copied from the instruction:

```python
class DraftIntent(BaseModel):
    kind: Literal["transfer", "swap"]
    asset_symbol: str; amount_text: str
    recipient_text: str | None
    buy_symbol: str | None; min_out_text: str | None; venue_name: str | None

class Draft(BaseModel):
    intents: list[DraftIntent]
    ambiguities: list[str]     # anything unclear, as questions for the user
    unsupported: str | None    # e.g. "bridging", "standing schedule"
```

The LLM never produces base units, token addresses or chain ids, and never converts units. The prompt says: copy, don't compute; if anything is unclear, list it under `ambiguities`. The Draft is validated again with Pydantic after the API's own schema check.

**Step 2, compilation (deterministic, pure, the most heavily tested part).** Every value must be grounded:
- **Token symbols** resolve only through the trusted registry (§2b). An unknown symbol, or one matching several entries, means we ask.
- **Addresses** must be valid hex with their exact EIP-55 checksum **and appear verbatim in the user's text**, or come from the operator's address book ("Bob" → 0x…). All-lowercase and all-uppercase addresses carry no checksum and are refused with an explanation (Decision 9). An address the user never typed is a hard error. This is the "no invented fields" rule.
- **Amounts:** `amount_text` must appear in the user's text. It's parsed with `Decimal`, never `float`, converted with registry decimals, and refused if it has more decimal places than the token supports.
- **Venues** resolve through the registry ("Uniswap" → this chain's router addresses). A swap with no venue means we ask.
- **Expiry** comes from config (default 30 min, cap 24 h) and is shown at confirmation. **Principal** comes from config (`MANDATE_PRINCIPALS`).
- Non-empty `ambiguities` or a set `unsupported` means no mandate: we ask, or refuse with the reason.

**Step 3, confirmation.** A template renders the compiled mandate, never LLM prose:

```
Mandate for 0xAgent… on Base Sepolia (84532), expires 14:32 UTC (in 30 min)
  1. SWAP  sell at most 100 USDC (0x036C…CF7e)
           for WETH (0x4200…0006), minimum: NONE ⚠ you could receive far less
           only via: Uniswap Universal Router (0x…)
  At most 3 transactions. Nothing else may leave this account.
Type "yes" to lock this mandate:
```

### Ambiguity: ask, never guess

| Instruction | Result |
|---|---|
| "send 50 USDC to 0xB0b…" | compiles |
| "send some USDC to 0xB0b…" | ask: how much? (no grounded amount) |
| "send 50 USDC to Bob" | address book hit → compiles; no hit → ask for the address |
| "send 50 USDC to 0x7099…79c8" (all lowercase or all uppercase) | ask for the checksummed form: without a checksum a typo can't be detected (Decision 9) |
| "send 50 USDC to 0x7099…79c8" with a wrong mixed-case checksum | ask: the address probably contains a typo |
| "send 50 USDC" | ask: to whom? |
| "swap my USDC for ETH" | ask: how much, and on which venue? |
| "buy the token from that tweet" | ambiguous and unsupported. Also a red flag: the instruction leans on untrusted content |
| "DCA 50 USDC into WETH every week" | unsupported in M3 ("standing mandates are not supported yet") |

Answers to clarifying questions are appended to the trusted instruction and extraction runs again. After 3 rounds the CLI gives up and points to the structured form.

### Structured path, no LLM

`mandate-firewall mandate new --swap 100 USDC --for WETH --via uniswap` builds the same Draft and goes through the **same compiler** and confirmation. Tests don't need an LLM, capture still works when the LLM is down, and protecting an agent in five minutes doesn't need an API key. No extra dependency is needed for the LLM path either (Decision 5): it uses `httpx`, which the proxy already depends on.

### 2b. Trusted token and venue registry

A data file per chain (`registry/<chain_id>.json`, shipped for Base Sepolia, with an operator override via `REGISTRY_PATH`): symbol → address and decimals, venue name → router addresses. Loading is strict: duplicate symbols, bad checksums or an unknown chain id fail at startup. M4 reuses the registry to show canonical names instead of attacker-chosen token names. Every address is checked against the issuer's own documentation in its commit (Circle for USDC, Uniswap's deployment list for routers), and the source is noted in the file. None are written from memory.

---

## 3. The trust boundary

### The threat

Anything the agent can write, an attacker who injected the agent can write. So **no path from the agent's side may create, change, extend or select a mandate's contents.**

### Where the instruction enters

| Option | How | Problem |
|---|---|---|
| A. Agent forwards the instruction | `firewall_createMandate` over RPC | The agent may already have read poisoned content and can rewrite the instruction ("…to 0xAttacker"). The only defense left is the user noticing at confirmation, which fatigue makes weak |
| **B. User → firewall directly (chosen)** | Capture CLI on the firewall's side; the user then gives the agent its task | One extra step for the user in M3. Real integrations must put capture in front of the agent (real-agent-integration milestone) |
| C. Agent proposes, user confirms remotely | A plus a phone/Telegram confirmation | Same core weakness as A, plus a remote channel to secure |

B is the CaMeL pattern: the trusted instruction is captured before the planner sees untrusted data, and the mandate's content never passes through the agent.

### How mandates reach the proxy

- The capture CLI runs as the **firewall's OS user** and writes to a SQLite store (`MANDATE_DB_PATH`), file mode `0600` in a `0700` directory.
- The proxy opens the store for mandate content **read-only**. Its only writes are transaction counters (§4).
- The agent already has to run as a different user or container (M1/M2: against proxy bypass and anvil tampering), so it can't reach the store. **File permissions are the authentication.** The proxy warns at startup if the store or its directory is accessible to group or others, as it does for the audit log.
- Confirmation requires an interactive terminal (`isatty` on stdin). That's defense in depth against a scripted "yes". It isn't a boundary: whoever can run commands as the firewall user can create mandates.

### Locking

- **Content hash.** `mandate_id = sha256(canonical JSON)`. Canonical means: keys sorted, no whitespace, every field present (nulls included), integers as decimal strings (as `Uint256` already serializes), datetimes as UTC ISO 8601 with second precision and a `Z`, UTF-8. The id is stored with the content and recomputed on every load. A mismatch counts as no mandate, so the transaction is blocked. Every audit record carries the id, so the log shows exactly which confirmed mandate a transaction was charged to.
- **Immutable.** Content rows are append-only. Status changes (`revoked`, `exhausted`; `expired` is derived from the clock) are rows in a separate event table. "Editing" means revoking and creating a new mandate. No code path updates a content row, and a test checks that.
- **Expiry** is required: default 30 min, cap 24 h for one-shot mandates. It's checked against the proxy's clock when each transaction arrives.
- **Use-limited, not single-use.** Single-use per transaction would break approve-then-swap. A mandate covers at most `max_transactions` transactions, and its intents' budgets can't be exceeded in total. Once used up it's `exhausted` for good. M3 enforces the transaction cap. Budget accounting is M4. Counters are keyed by `(mandate_id, period_start)`, with `period_start` = `created_at` while `period` is null, so per-period counting later needs no migration.

### Signing (deferred, Decision 3)

A key on the same host as the store adds almost nothing: anyone who can write the store can usually read the key. The version that adds real protection is the **user's own wallet signing the mandate as EIP-712 typed data**, checked against a configured owner address. That enables remote creation (from a phone) and gives audit-grade proof that the user approved the mandate. The canonical encoding above is designed so that signature can be added later without a schema change. It's a separate roadmap item (§8).

---

## 4. Binding: which mandate covers which transaction

- **Key: `(chain_id, sender)`.** The sender is recovered from the signature (M1), so the agent can't fake it.
- **At most one active mandate per principal** in M3. Creating a second one fails unless `--replace` is given, which revokes the first. With several active mandates it would be ambiguous which budget to charge, and an agent-supplied "use mandate X" tag would let an injected agent pick the broadest one. Later, M4 can check a transaction against each candidate and charge only one it fully fits. The standing-mandates milestone revisits this for one-shot and standing mandates side by side.
- **The gate (commit 7, Decision 4).** In `_send_raw_transaction`, after `_check(tx)` and before simulation: look up the active mandate for `(tx.chain_id, tx.sender)`. If there's none, it's expired, revoked or exhausted, its hash doesn't match, or `max_transactions` is reached → block `-32003` with the reason. Otherwise simulate as in M2. The counter is incremented and fsynced together with the audit write that comes before forwarding. If that write fails, the transaction is blocked. Blocked transactions don't count against the cap.

**Honest caveat.** Until M4, a transaction from a principal that *has* an active mandate is forwarded without comparing its effects to the mandate. M3 narrows the window (a confirmed mandate must exist, unexpired, under its transaction cap). It doesn't close it. THREAT_MODEL.md says this in bold.

---

## 5. LLM provider and API key

- **Provider:** Anthropic, behind a small `MandateExtractor` protocol (`extract(text) -> Draft`). Supporting another provider means one more class. The model is configurable (`LLM_MODEL`), defaulting to `claude-opus-5-5`. Capture is a few short calls per mandate, so cost isn't a concern. Structured outputs (`output_config.format`) are generally available.
- **Raw HTTP, not the SDK (Decision 5).** The provenance check run in commit 5 (2026-11-05) queried PyPI's integrity API (`/integrity/<project>/<version>/<wheel>/provenance`):

  | Package | Version | Attestation |
  |---|---|---|
  | starlette (control, known attested) | 1.7.0 | yes: GitHub `Kludex/starlette`, `publish.yml` |
  | anthropic | 2.6.0 (uploaded that day), 2.5.0 | none (404) |
  | httpx2 | 2.16.0 | none (404) |
  | httpcore2 (new; required by httpx2) | 2.16.0 | none (404) |
  | *already ours:* httpx, httpcore, fastapi, pydantic-core | locked versions | none (404) |
  | *already ours:* pydantic, uvicorn, web3, eth-account, anyio | locked versions | yes |

  The metadata of all three points to the expected repositories (`anthropics/anthropic-sdk-python`, `pydantic/httpx2`), but that is self-declared. **Unverified is not malicious**; we found nothing wrong with these packages. The finding is that we can't verify them, and taking them on would add about eight transitive packages, three of them unverified, to a security tool. Since our rule is to minimize unverified code, capture calls the Messages API with `httpx`, which is already a dependency. The price: we own the request format and must follow API changes ourselves. The request is written against the live API docs (versioning, errors, structured outputs, refusals and fallback), not from memory, and the opt-in live test (`pytest -m llm`) catches drift. If the SDK and its HTTP stack publish attestations later, revisit this. `httpx2` isn't installed, so the Starlette `filterwarnings` entry from M2 commit 0 stays as it is.
- **The request** (`capture/extractor.py`): `POST /v1/messages` with `Authorization: Bearer <key>`, `anthropic-version: 2026-10-21`, structured outputs with a hand-written JSON schema (the API doesn't accept length or array-size limits, so `Draft` enforces them after parsing), and server-side fallback (`fallbacks: "default"`, beta header `server-side-fallback-2026-07-01`). With fallback, a request declined by a safety classifier is answered by a recommended fallback model in the same call. Its output is just as untrusted and goes through the same compiler. No retries: capture is interactive, and the user can retry or use the structured path.
- **Only capture talks to the LLM (Decision 5).** Layout: `mandate/` (models, canonical encoding, registry, store, compiler, Draft) never talks to the LLM and is what the proxy uses. `capture/` (settings, extractor, later the CLI flow) does. `cli.py` will import `capture` lazily inside the `mandate` subcommand (commit 6), so `serve` never loads it. Enforced by tests: (1) a subprocess builds the proxy app the way `serve` does and asserts nothing from `mandate_firewall.capture` (or an SDK) was imported; (2) an AST walk fails if any module outside `capture/` imports it, relative imports included; (3) no module anywhere imports `anthropic`, `httpx2` or `httpcore2`; (4) the strings `api.anthropic.com`, `llm_api_key` and `/v1/messages` appear only in `capture/`. The proxy process never holds the key: it lives in a separate `CaptureSettings` that only `capture/` reads, and the proxy's `Settings` ignores it.
- **Keeping the key secret:**
  - `LLM_API_KEY: SecretStr`. Its `repr` and `str` show `**********`. It's read from the environment or `.env`, **never from a flag** (command lines are visible in `ps`). It must be printable ASCII without spaces, so a pasted newline can't reach an HTTP header, and the validation error never echoes it.
  - It goes into exactly one header that our code builds. There's no SDK, so there's no other credential to fall back to (`ANTHROPIC_API_KEY`, `ant auth` profiles) and no SDK debug logging to guard against. `trust_env=False`: proxy variables and `~/.netrc` can't redirect the request or add credentials. Redirects aren't followed. `LLM_BASE_URL` must be https (plain http only for loopback) and may not carry credentials or a query.
  - Failures become `ExtractionError(kind, status_code, request_id, detail)`. `detail` is at most an identifier-like error type or refusal category (`rate_limit_error`, `cyber`) or a field location. The API's message text, model output and validation input values are never shown. Errors are raised `from None`, so tracebacks don't chain the httpx exception.
  - Test: the key is a sentinel string. Real HTTP runs against a local server with every logger at DEBUG (httpx, httpcore): an auth failure, malformed output, a refusal, a success and a refused connection. The sentinel must not appear in caplog, stdout, stderr, or the errors' `str`/`repr`. Checking that it stays out of the store and the audit log moves to commits 6 and 7, where those are written.
- **Privacy (README):** the instruction text, including amounts and addresses, is sent to the LLM provider. The structured path avoids that.

---

## 6. Failure handling (fail closed)

| Failure | Behavior |
|---|---|
| LLM unreachable, refuses, times out, or returns invalid output | No mandate. Tell the user and offer the structured path. Never fall back to a partial draft |
| Draft has ambiguities, ungrounded values, unknown symbols or an unsupported action | Ask (at most 3 rounds), then refuse |
| User doesn't type exactly `yes`, or stdin isn't a terminal | Nothing is stored |
| Store missing or unreadable at proxy startup | **Refuse to start**, like the audit log |
| Store or its directory accessible to group/others | Warn at startup |
| No active mandate, or it's expired, revoked, exhausted or for another chain | Block `-32003`, reason in the audit record |
| Hash mismatch on load | Block, log an error ("mandate store integrity failure") |
| Store read error while handling a transaction | Block |
| Counter write fails | Block (same rule as a failed audit write) |
| Clock wrong | Expiry uses the proxy's wall clock. Documented, not solved |

There's no setting that turns the gate off.

---

## 7. What M3 does NOT solve (goes into THREAT_MODEL.md, commit 8)

1. **Effects aren't compared with the mandate yet (M4).** While a mandate is active, any transaction from that principal that simulates cleanly is forwarded, up to `max_transactions`, until it expires.
2. **The user can confirm a bad mandate:** fatigue, a misread address. Canonical names and the ⚠ for a missing minimum help. They don't fix it.
3. **A poisoned instruction.** If the user pastes an address copied from a scam page, the mandate faithfully authorizes the scam. Mandates capture intent; they don't judge it.
4. **Same-host compromise.** Anyone who runs as the firewall user can create mandates. There's no signing in M3.
5. **Authorized but badly executed.** An injected agent can still do what was authorized, badly (a bad price). Swap minimums and M4 cover part of this.
6. **Swaps without a stated minimum** are flagged at confirmation, not bounded.
7. **Standing mandates aren't supported yet**, only one-shot (planned milestone right after M4).
8. **Off-chain signatures** (Permit2, EIP-2612) remain invisible until the pre-sign milestone. A mandate doesn't help against them.
9. **The registry is trusted.** A wrong entry means a wrong mandate. It's curated by the operator and not verified on chain.
10. **Wall-clock expiry.** A transaction forwarded just before expiry may be mined after it.
11. **The instruction goes to the LLM provider** when the LLM path is used.

---

## 8. Roadmap changes (applied to CLAUDE.md 2026-10-09, in its own commit after commit 0)

Renumbered, per Decisions 2, 3 and 8:

- M3: mandate capture (this plan)
- M4: verifier. The deterministic matcher decides. The LLM only explains (Decision 7). Plain-English verdicts, human escalation for anomalies
- **M5 (new): standing mandates.** Per-period budgets and transaction caps, expiries beyond 24 hours, renewal and revocation, one-shot and standing mandates side by side. Human input once per mandate, decisions per transaction fully automated
- M6 (was M5): real agent integration. **Capture must sit in front of the agent**: the user's instruction reaches the firewall before the agent reads any untrusted content. Demo an injection that rule-based guardrails miss
- M7 (was M6): pre-sign / typed-data inspection (Permit2, EIP-2612 at minimum)
- v0.1 release
- M8 (was M7): benchmark
- **M9 (new): user-wallet EIP-712 mandate signing.** The user's own wallet signs the canonical mandate. The firewall verifies the signer against a configured owner address

Where M9 sits (before or after v0.1) is open (confirmed 2026-10-09: stays M9 for now). It's listed last because OS permissions cover the single-host setup.

---

## 9. Commit sequence (OK between each)

0. **This plan** (`docs/m3-plan.md`). **Done.**
   *Verify:* read-through.
1. **Mandate models and canonical hash** (`mandate/models.py`, `mandate/canonical.py`).
   *Verify:* unit tests: frozen; discriminated union; `Budget.max` required and below 2**256−1; non-null `period` rejected; `Ratio.denominator > 0`; one-shot expiry within 24 h; no fields missing in canonical JSON; a known-answer hash (fixed mandate → fixed hex); the same hash regardless of input key order.
   **Done.** How it differs from the sketch in §1 and §3:
   - *Integers in canonical JSON:* uint256 values (budgets, ratios) are decimal strings, as planned. Small bounded integers (`chain_id`, `decimals`, `max_transactions`, `schema_version`) stay JSON numbers, capped below 2**53 so every parser reads the same value. With ASCII keys, no floats and integers below 2**53, Python's `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)` gives the same bytes as RFC 8785.
   - *Every field is required*, with no defaults (including `period: null`), so "missing" and "null" can't both spell one mandate. `extra="forbid"` everywhere.
   - *Strict values:* `chain_id`, `decimals`, `max_transactions` and `schema_version` reject `True`, `1.0` and `"1"` (pydantic's plain `int` and `Literal[1]` accept the first two). Budgets and ratio terms must be > 0 and < 2**256−1, since that maximum reads as "unlimited" to contracts.
   - *Times* have one spelling: `YYYY-MM-DDTHH:MM:SSZ`, whole seconds. Unix numbers, offsets and fractions are rejected in strings. Aware Python datetimes are converted to UTC; naive ones are rejected.
   - *Extra cross-field rules:* every asset is on the mandate's chain; a swap sells and buys different assets; venues are unique and never the principal; two intents over the same asset and counterparty (same transfer recipient, or same sell/buy pair) are rejected, because M4 couldn't tell which budget a transaction draws on.
   - *`parse_canonical(bytes)`* (for the store in commit 3) accepts only the exact canonical bytes: it parses, re-encodes and compares. That also rejects duplicate keys, a BOM, trailing newlines and `\u` escapes. Errors name the problem, never the field values.
   - Pydantic already refuses strings with lone surrogates (they can't be UTF-8), so no extra check was needed.
   - The known-answer id in the tests was computed with `shasum -a 256` over the hand-written JSON, not with our own code.
2. **Registry** (`mandate/registry.py`, `registry/84532.json`).
   *Verify:* unit tests: duplicate symbols, bad checksums and unknown chains rejected. Addresses checked by hand against issuer docs, sources noted in the file.
   **Done.** The file is `src/mandate_firewall/mandate/registry_data/84532.json` (inside the package, so the wheel ships it). How it differs from §2b:
   - *Sources:* USDC from Circle's address page, WETH from Base's contract page, SwapRouter02 from Uniswap's Base deployments page, each with the row and the date checked. Pages were read raw (curl and grep), not through a summarizer, so the hex came straight from the issuer. Each address was also checked on chain against `https://sepolia.base.org`: chain id, code present, `decimals()` 6 and 18, and `SwapRouter02.WETH9()` returning the listed WETH.
   - *Uniswap = SwapRouter02 only.* UniversalRouter and Permit2 are left out on purpose. With them the ERC-20 approval goes to Permit2, and the router is authorized through a Permit2 allowance (a Permit2 event M2 doesn't decode) or an off-chain signature (M7). SwapRouter02 takes a plain ERC-20 approval that effects show directly. Most agent toolkits default to UniversalRouter, so M4 or M6 has to revisit this (Permit2 event decoding was already deferred from M2).
   - *Symbols are unique ignoring case*, including the native symbol, checked at load. So "a symbol matching several entries" can't happen and the compiler only has to handle unknown symbols. Symbols are ASCII only, so a Cyrillic lookalike is simply unknown.
   - *Addresses must be written with their exact EIP-55 checksum* (a lowercase address carries no typo protection), unique across tokens and venues, never the zero address. The check runs on the raw input: the first version ran after `Address` had already checksummed it and accepted lowercase. The tests caught that.
   - *Every entry needs an https `source`*. Duplicate JSON keys, unknown fields and files over 1 MB are rejected.
   - *Operator override:* `load_registry(chain_id, directory)`. A file there replaces the shipped one for its chain. A directory without a file for the chain is an error, never a fallback. The `REGISTRY_PATH` setting is added in commit 6, where the CLI first uses it.
   - *Lookups:* `asset(symbol)` ignores case; the native symbol means native ETH. `venue(name)`. `symbol_for(address)` is for M4's canonical names.
3. **Mandate store** (SQLite: append-only content, status events, counters keyed by `(mandate_id, period_start)`; `0600`/`0700`; one active mandate per principal; hash check on load).
   *Verify:* unit tests: a tampered row fails to load; a second active mandate is rejected; expiry and revoke; the permission warning; no code path updates content rows.
   **Done** (`mandate/store.py`). How it differs from §3 and §4:
   - *Append-only is enforced by SQLite triggers*, not only by our code: `UPDATE`/`DELETE` on `mandates` and `events` abort, and counters can only go up and are never deleted. A source scan also checks that the store code never writes `UPDATE mandates`, `UPDATE events` or `DELETE FROM`.
   - *Every read re-checks the row:* the bytes must pass `parse_canonical`, hash to the row's id, and agree with the lookup columns (`chain_id`, `principal`, `created_at`, `expires_at`). Otherwise someone could point a valid mandate at another principal, or extend its expiry, by editing an index column. A failing row raises `MandateIntegrityError` and is never skipped. Two active mandates for one principal (only possible by editing the file) also raise.
   - *Status* is derived on read, in this order: revoked > exhausted (event, or count ≥ `max_transactions`) > expired (`now ≥ expires_at`) > active.
   - *`add(replace=True)`* revokes the old mandate and inserts the new one in one transaction. If the insert fails, the revoke is rolled back. `add` refuses a mandate that has already expired, or one created more than a minute in the future (clock skew).
   - *`record_transaction`* checks and increments inside `BEGIN IMMEDIATE`, which takes the write lock before the check. With a plain `BEGIN`, a second process could take the last slot between our check and our write. A test forces exactly that interleaving and fails if `IMMEDIATE` is removed. (A first threaded version of that test passed even without `IMMEDIATE`, because the threads never overlapped; it was replaced.) The proxy will call this together with the audit write (commit 7).
   - *SQLite settings:* WAL journal, `synchronous=FULL` (each commit is fsynced before it returns), foreign keys on, `STRICT` tables, `PRAGMA user_version = 1`. A file with another version, or with tables but no version, is refused. `busy_timeout` is a constructor argument (default 5 s), so the proxy can choose a shorter wait in commit 7.
   - *Files:* `create=True` (the CLI) makes the directory `0700` and the file `0600`; SQLite gives its `-wal`/`-shm` files the same mode. Without `create` (the proxy, commit 7), a missing file is an error. On every open, the store warns if the file or its directory is accessible to group or others.
   - *SQLite errors* while opening, reading or writing become `MandateStoreError`, after rolling back.
   - *Not tamper-evident against the firewall's own OS user:* whoever can write the file can drop the triggers and delete a `revoked` event or a counter row. Content can't be changed without detection (the hash), but status and counts can. This goes into THREAT_MODEL.md in commit 8.
4. **Compiler** (`mandate/compile.py`, pure: Draft → Mandate or a question for the user).
   *Verify:* table-driven tests for every row of the ambiguity table in §2, plus an ungrounded address, too many decimals, float-looking input, an unknown venue, a standing instruction refused as unsupported.
   **Done** (`mandate/draft.py`, `mandate/compile.py`). How it differs from §2:
   - *The Draft lives in `mandate/`*, not `capture/`, because the structured CLI path builds one too and the compiler consumes it. It's plain Pydantic, with no SDK.
   - *Every Draft field except `kind` is optional.* A missing amount, recipient or venue is null, and the compiler turns it into a question. We don't depend on the LLM listing it under `ambiguities`. Strings are capped at 200 characters, with at most 5 intents and 10 ambiguities.
   - *Three outcomes:* `Compiled(mandate, notes)`, `NeedsClarification(questions)`, `Unsupported(reason)`. A bad configuration (lifetime outside (0, 24 h], cap < 1, invalid principal, a bad address-book entry) raises `CompileError`, because the user can't fix it by answering. All questions come in one round, numbered per intent when there are several.
   - *Symbols and venue names are grounded too*, not just addresses and amounts. They must appear in the instruction as a word (ignoring case), so an extractor that turns "USDC" into "WETH" is caught.
   - *Amount grammar:* ASCII digits with an optional `.digits`. Exponents, signs, `.5`/`5.`, `_` and non-ASCII digits are refused (Python's `\d` and `int()` accept `١٢`). **Commas are refused, not parsed:** "1,500" is 1500 or 1.5 depending on the locale, so we ask. An amount must appear as a whole number: "5" doesn't match inside "50", "1.5", "-5", "0x5" or "5e3".
   - *No `Decimal` arithmetic:* base units are computed with integers. Decimal's default 28-digit context rounds larger 18-decimal amounts; a test uses a 36-digit value. Trailing zeros don't count as extra decimals ("1.5000000" USDC is fine).
   - *Addresses:* matched verbatim (case included), never as part of longer hex. Only the exact EIP-55 spelling compiles. All-lowercase or all-uppercase is a question asking for the checksummed form (Decision 9). The first version accepted lowercase with a note; changed in a follow-up commit. A wrong mixed-case checksum is a question. Recipients that lose funds are refused: the zero address, the principal, and any registry token or venue contract.
   - *Swap minimum:* "at least X buy for Y sell" becomes `Ratio(X, Y)` in base units, unreduced. Without a minimum, the swap compiles with a note. A swap whose output goes to another recipient is `Unsupported` (swap, then transfer).
   - *Standing backstop:* recurring wording (every, daily, weekly, monthly, hourly, recurring, DCA, each/per day/week/month) is refused in Python even if the extractor didn't flag it.
   - *Untrusted strings are sanitized when printed:* control and format characters (terminal escapes, bidi overrides) become `?`, and long values are cut.
   - *Limit, stated in the module docstring:* grounding proves a value appears in the user's words, not that it's attached to the right thing ("send 5 USDC to 0xB0b…, not 500" with 500 extracted is grounded). The confirmation step is the control for that.
   - Each guard was mutated (19 mutations) and every one was caught by a test. Run the mutation loop with `PYTHONDONTWRITEBYTECODE=1`: a stale `.pyc` once made two mutations look like survivors.
5. **LLM extractor** (`capture/extractor.py`: `httpx2` provenance re-check recorded in the commit message, SDK as the `llm` extra, `CaptureSettings` with `SecretStr`, error wrapping, `FakeExtractor` for tests, the two import-boundary tests).
   *Verify:* unit tests with mocked HTTP; the sentinel-key leak test; the import-boundary tests; an optional live test marked `llm`, skipped without a key (like `anvil`); re-check the Starlette `filterwarnings` entry.
   **Done** (`capture/settings.py`, `capture/extractor.py`). How it differs:
   - *No SDK, no `llm` extra:* the provenance check failed (§5 table), so the extractor calls the Messages API over `httpx` (Decision 5, revised). The Starlette `filterwarnings` entry stays, since `httpx2` is still not installed.
   - *Live test is opt-in, not just skip-without-key:* `addopts = ["-m", "not llm"]` deselects it by default, so a developer with a key in `.env` doesn't pay on every `pytest` run. Run it with `uv run pytest -m llm`. A later `-m` (such as `-m anvil`) replaces the default.
   - *More import-boundary checks than planned:* four instead of two (§5).
   - *Server-side fallback is on* (beta), so a classifier false positive on a benign instruction doesn't stop capture.
   - *Every guard was mutated and caught:* trust_env, redirects, error-type sanitizing, the stop-reason gate, exactly one text block, the response size cap, `from None`, no values in validation details, duplicate JSON keys, and a planted relative `capture` import in the proxy (caught by both the AST and the subprocess test). Two harness mistakes were found and fixed on the way: an ambiguous pattern that didn't apply a mutation, and a size-cap test whose payload failed for another reason.
6. **Capture CLI** (`mandate new | show | list | revoke`, clarification loop, template rendering, terminal-only confirmation, structured flags).
   *Verify:* tests drive stdin with the fake extractor; confirmation without a terminal fails; one manual run against the real API on your machine.
   **Done** (`capture/commands.py`, `mandate/render.py`, `cli.py`, new `CaptureSettings` fields). How it differs:
   - *Addresses are rendered in full*, unlike the sketch in §2 (`0x036C…CF7e`). Address poisoning attacks generate addresses that match the first and last characters of a real one, so a shortened address is exactly what they need the user to see. Amounts are converted from base units with integers, never rounded. Tokens and venues get registry names; anything not in the registry is shown as `UNREGISTERED TOKEN` / `UNREGISTERED CONTRACT` next to its full address.
   - *The renderer is in `mandate/`* (no LLM involved), so M4's "You asked: X" explanation can reuse it.
   - *The terminal check covers stdin and stdout* and runs first, before any LLM call. A summary piped somewhere the user can't see would be confirmed blind. The answer must be exactly `yes` (surrounding spaces ignored, case not).
   - *Settings:* `MANDATE_DB_PATH`, `MANDATE_PRINCIPALS` (comma-separated, exact checksums, like registry addresses), `MANDATE_CHAIN_ID`, `REGISTRY_PATH`, `ADDRESS_BOOK_PATH`, `MANDATE_LIFETIME_MINUTES`, `MANDATE_MAX_TRANSACTIONS`, all in `CaptureSettings`. `--principal` may only pick one of the configured accounts. `--minutes` and `--max-transactions` override the defaults per mandate.
   - *The address book is a JSON file* of name → checksummed address. Whoever can write it can redirect "send to Bob", so a file writable by group or others is **refused**, not just warned about (the store only warns, because its content is hash-checked).
   - *An existing active mandate is checked before the LLM call*, so a conflict costs nothing. `store.add` checks again atomically. `mandate new` also verifies **every** row first, not just this principal's: a tampered row filed under another account would otherwise go unnoticed, and this is when a person is present to see it. A test found this gap.
   - *Rounds:* at most 3 rounds of questions on the LLM path (4 extractions), then the CLI refuses and prints the structured form. The structured path never asks: questions there mean the flags are incomplete, so it lists them and stops.
   - *The LLM path prints where the instruction goes* ("it is sent to api.anthropic.com") before calling it.
   - *Settings errors name the field and the problem*, never the rejected value (it could be the key).
   - *`show` and `revoke` accept a unique id prefix* of 8+ hex digits. `revoke` asks for no confirmation: it only ever makes the agent able to do less. `show`, `list` and `revoke` never create the store.
   - *Import boundary:* `cli.py` imports `capture.commands` inside `main()` only. The AST test now forbids module-level capture imports everywhere outside `capture/`, allows the function-level one only in `cli.py`, and the subprocess test still checks that building the proxy loads nothing from `capture/`.
   - *Mutations:* the terminal check, exact `yes`, configured principals, address book permissions, the full-store scan, the early active check, the clarification append and value-free settings errors each fail a test when broken. The CLI's own `safe_text` on questions survives a mutation, as expected: the compiler already cleans every Draft string inside a question, so the CLI's pass is a second layer that no test can isolate.
7. **Proxy binding and gate** (store opened at startup, refuse to start without it, the gate, `mandate_id` in `AuditRecord`, counter written with the audit record, test that agents can't reach `mandate_*`/`firewall_*`).
   *Verify:* existing M1/M2 tests pass after fixtures create a mandate. New integration tests: no mandate → blocked and never mined upstream; expired → blocked; cap reached → blocked; with a mandate → forwarded, with `mandate_id` in the audit line; a tampered store row → blocked.
8. **Docs and demo:** THREAT_MODEL.md (§7), README (capture quickstart, privacy note), CLAUDE.md (mark M3 done; the §8 roadmap is already in), `scripts/demo_m3.sh`.
   *Verify:* read-through; full `uv run pytest`; `uv run ruff check .`.

Each commit: `uv run ruff check .` plus `uv run pytest` (with `-m anvil` for integration tests), no Co-Authored-By trailer.

## Roadmap pushback (outcomes in "Decisions" above)

1. **`httpx2` returns with the SDK.** *Outcome:* use the SDK after a provenance re-check in commit 5, capture-only, enforced by tests (Decision 5). *Revised in commit 5:* the check found no attestations, so the API is called over `httpx` instead.
2. **"Capture before the agent reads untrusted content" holds only if the user talks to the firewall first.** Most agent frameworks deliver the chat to the agent. *Outcome:* written into the real-agent-integration milestone (Decision 2, §8).
3. **The LLM's place in M4.** With effects-shaped mandates, the fuzzy part is resolved at capture time with the human present. An LLM deciding at transaction time is the least trustworthy place for one, and since it may only make decisions stricter, its value there is small. *Outcome:* M4's matcher decides and the LLM only explains (Decision 7).
4. **Single-use → use-limited budget**, since single-use per transaction breaks approve-then-swap (§3). *Outcome:* agreed (Decision 6).
5. **Same-host signing is theater; user-wallet EIP-712 signing is the real version.** *Outcome:* deferred to M9 (Decision 3).
6. **Standing mandates** are what autonomous agents need. *Outcome:* promoted to M5, with the schema designed for them now (Decision 8).
