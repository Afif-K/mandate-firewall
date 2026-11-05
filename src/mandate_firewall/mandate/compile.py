"""The compiler: Draft -> Mandate, or a question for the user, or a refusal.

Pure and deterministic. No I/O, no clock, no randomness unless the caller
leaves `nonce` out. This is where the untrusted Draft (an LLM's reading of
the instruction) meets trusted data. The rule is that nothing reaches the
Mandate unless it is grounded (docs/m3-plan.md §2):

- Token symbols and venue names resolve only through the registry, and the
  symbol or name must appear in the user's instruction as a word.
- Addresses must appear verbatim in the instruction, spelled with a valid
  EIP-55 checksum or all lowercase. The other source is the operator's
  address book, by a name the user typed. An address the user never wrote
  is refused.
- Amounts must appear in the instruction as written. They are parsed by a
  strict grammar and converted with integer arithmetic only.
- Chain, principal, expiry and transaction cap come from the caller
  (config), never from the Draft.

Grounding checks that each value appears in the user's words. It can't
check that the value is attached to the right thing: in "send 5 USDC to
0xB0b..., not 500", an extractor that picks 500 passes grounding. The control
for that is the user reading the rendered mandate before typing "yes".

Anything unclear becomes a question. We ask; we never guess.
"""

import re
import secrets
import unicodedata
from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Literal

from eth_utils import to_checksum_address
from pydantic import BaseModel, ConfigDict, Field

from mandate_firewall.mandate.draft import Draft, DraftIntent
from mandate_firewall.mandate.models import (
    DEFAULT_LIFETIME,
    DEFAULT_MAX_TRANSACTIONS,
    MAX_INSTRUCTION_CHARS,
    ONE_SHOT_MAX_LIFETIME,
    AssetRef,
    Budget,
    Intent,
    Limits,
    Mandate,
    MandateKind,
    Ratio,
    SwapIntent,
    TransferIntent,
)
from mandate_firewall.mandate.registry import Registry, UnknownSymbolError, UnknownVenueError
from mandate_firewall.models import UINT256_MAX

ZERO_ADDRESS = "0x" + "00" * 20

# An amount as people write it: digits, optionally a dot and more digits.
# ASCII digits only: Python's \d and int() also accept other scripts' digits
# ("٥" is 5). No sign, no exponent, no ".5" or "5.", no separators.
_AMOUNT = re.compile(r"[0-9]+(?:\.[0-9]+)?", re.ASCII)
_MAX_AMOUNT_CHARS = 90  # 2**256 has 78 digits; this only bounds the work

_HEX_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}", re.ASCII)

# One-shot only in M3. A recurring instruction must not compile into a
# one-shot mandate just because the extractor missed the schedule. This is a
# deterministic backstop to the extractor's own `unsupported` flag.
_STANDING = re.compile(
    r"\b(?:every|daily|weekly|monthly|hourly|recurring|dca|"
    r"each\s+(?:day|week|month)|per\s+(?:day|week|month))\b",
    re.IGNORECASE | re.ASCII,
)


class CompileError(Exception):
    """A bug or a bad configuration, not something the user can fix by
    answering a question. No mandate is produced."""


class _Result(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Compiled(_Result):
    outcome: Literal["compiled"] = "compiled"
    mandate: Mandate
    # Facts the confirmation screen must show next to the mandate, such as a
    # swap without a minimum or an address taken from the address book.
    notes: tuple[str, ...]


class NeedsClarification(_Result):
    outcome: Literal["clarify"] = "clarify"
    questions: tuple[str, ...] = Field(min_length=1)


class Unsupported(_Result):
    outcome: Literal["unsupported"] = "unsupported"
    reason: str


CompileResult = Compiled | NeedsClarification | Unsupported


def compile_draft(
    draft: Draft,
    *,
    instruction: str,
    registry: Registry,
    principal: str,
    now: datetime,
    lifetime: timedelta = DEFAULT_LIFETIME,
    max_transactions: int = DEFAULT_MAX_TRANSACTIONS,
    address_book: Mapping[str, str] | None = None,
    nonce: str | None = None,
) -> CompileResult:
    """Compile a Draft against the user's instruction.

    `instruction` is the user's trusted text, with any answers to earlier
    questions appended. Every value in the Draft must be grounded in it.
    `principal`, `lifetime` and `max_transactions` come from configuration.
    A bad value there raises CompileError, because the user can't fix it.
    """
    if not timedelta(0) < lifetime <= ONE_SHOT_MAX_LIFETIME:
        raise CompileError("mandate lifetime must be more than zero and at most 24 hours")
    if max_transactions < 1:
        raise CompileError("max_transactions must be at least 1")
    try:
        principal = _checksummed(principal)
    except ValueError:
        raise CompileError("the configured principal is not an address") from None
    book = _load_address_book(address_book or {})

    if len(instruction) > MAX_INSTRUCTION_CHARS:
        return Unsupported(
            reason=f"the instruction is longer than {MAX_INSTRUCTION_CHARS} characters"
        )
    if draft.unsupported is not None:
        return Unsupported(reason=_clean(draft.unsupported, limit=200))
    if _STANDING.search(instruction):
        return Unsupported(
            reason="recurring (standing) mandates are not supported yet; "
            "describe one payment or one swap"
        )

    questions: list[str] = [_clean(q, limit=500) for q in draft.ambiguities]
    if not draft.intents:
        questions.append("What should the agent do? Describe one transfer or one swap.")

    ctx = _Context(instruction, registry, principal, book)
    intents: list[Intent] = []
    notes: list[str] = []
    for number, draft_intent in enumerate(draft.intents, start=1):
        label = f"#{number}" if len(draft.intents) > 1 else ""
        compiler = _compile_transfer if draft_intent.kind == "transfer" else _compile_swap
        result = compiler(draft_intent, ctx, label)
        if isinstance(result, Unsupported):
            return result
        intent, intent_questions, intent_notes = result
        questions += intent_questions
        notes += intent_notes
        if intent is not None:
            intents.append(intent)

    if not questions:
        questions += _cross_intent_questions(intents)
    if questions:
        return NeedsClarification(questions=tuple(dict.fromkeys(questions)))

    created = now.replace(microsecond=0)
    try:
        mandate = Mandate(
            schema_version=1,
            kind=MandateKind.ONE_SHOT,
            chain_id=registry.chain_id,
            principal=principal,
            intents=tuple(intents),
            limits=Limits(max_transactions=max_transactions, period=None),
            created_at=created,
            expires_at=created + lifetime,
            instruction=instruction,
            nonce=nonce if nonce is not None else "0x" + secrets.token_hex(32),
        )
    except ValueError as exc:  # ValidationError: a check above is missing
        raise CompileError(f"compiled mandate is invalid: {type(exc).__name__}") from None
    return Compiled(mandate=mandate, notes=tuple(dict.fromkeys(notes)))


# --- per-intent ------------------------------------------------------------------


class _Context:
    def __init__(
        self, instruction: str, registry: Registry, principal: str, book: dict[str, str]
    ) -> None:
        self.instruction = instruction
        self.registry = registry
        self.principal = principal
        self.book = book
        # Addresses a transfer must never go to: tokens and venues lose
        # whatever is sent to them, the principal would be sending to itself.
        self.forbidden_recipients = {
            ZERO_ADDRESS: "the zero address",
            principal: "the agent's own account",
            **{t.address: f"the {t.symbol} token contract" for t in registry.tokens},
            **{c.address: f"a {v.name} contract" for v in registry.venues for c in v.contracts},
        }


_IntentResult = tuple[Intent | None, list[str], list[str]] | Unsupported


def _compile_transfer(d: DraftIntent, ctx: _Context, label: str) -> _IntentResult:
    what = f"For transfer {label}".strip()
    if d.buy_symbol is not None or d.min_out_text is not None or d.venue_name is not None:
        return None, [f"{what}: it mentions a token to buy or a venue. Did you mean a swap?"], []

    questions: list[str] = []
    notes: list[str] = []
    asset = _asset(d.asset_symbol, ctx, what, "which token should be sent?", questions)
    amount = _amount(d.amount_text, asset, ctx, what, "how much should be sent?", questions)
    recipient = _recipient(d.recipient_text, ctx, what, questions, notes)
    if asset is None or amount is None or recipient is None:
        return None, questions, notes
    intent = TransferIntent(
        kind="transfer",
        asset=asset,
        budget=Budget(max=amount, period=None),
        recipient=recipient,
    )
    return intent, questions, notes


def _compile_swap(d: DraftIntent, ctx: _Context, label: str) -> _IntentResult:
    what = f"For swap {label}".strip()
    if d.recipient_text is not None:
        # M4 checks that what is bought arrives at the principal.
        return Unsupported(
            reason="a swap that sends the bought tokens to someone else is not supported; "
            "swap first, then send in a separate transfer"
        )

    questions: list[str] = []
    notes: list[str] = []
    sell = _asset(d.asset_symbol, ctx, what, "which token should be sold?", questions)
    buy = _asset(d.buy_symbol, ctx, what, "which token should be bought?", questions)
    sell_amount = _amount(
        d.amount_text, sell, ctx, what, "how much should be sold at most?", questions
    )
    if sell is not None and buy is not None and sell == buy:
        questions.append(f"{what}: it sells and buys the same token. Which token should be bought?")

    venues = _venues(d.venue_name, ctx, what, questions)

    min_out = None
    if d.min_out_text is not None:
        min_out = _amount(d.min_out_text, buy, ctx, what, "", questions)

    if questions or sell is None or buy is None or sell_amount is None or venues is None:
        return None, questions, notes

    ratio = None
    if min_out is None:
        notes.append(
            f"{what}: no minimum amount to receive was given, so the swap could return "
            "far less than the tokens are worth."
        )
    else:
        # "at least 0.03 WETH for 100 USDC" as a rate in base units. M4 checks
        # bought * denominator >= sold * numerator, so partial fills work too.
        ratio = Ratio(numerator=min_out, denominator=sell_amount)
    intent = SwapIntent(
        kind="swap",
        sell=sell,
        sell_budget=Budget(max=sell_amount, period=None),
        buy=buy,
        min_buy_per_sell=ratio,
        venues=venues,
    )
    return intent, questions, notes


def _cross_intent_questions(intents: list[Intent]) -> list[str]:
    """The Mandate model's cross-intent rule, asked as a question rather
    than raised: two intents over the same asset and counterparty."""
    keys = [
        ("transfer", i.asset.address, i.recipient)
        if isinstance(i, TransferIntent)
        else ("swap", i.sell.address, i.buy.address)
        for i in intents
    ]
    if len(set(keys)) != len(keys):
        return [
            "Two of these send the same token to the same recipient (or swap the same "
            "pair). Combine them into one amount."
        ]
    return []


# --- grounding -------------------------------------------------------------------


def _asset(
    symbol: str | None, ctx: _Context, what: str, missing: str, questions: list[str]
) -> AssetRef | None:
    known = ", ".join([ctx.registry.native.symbol] + [t.symbol for t in ctx.registry.tokens])
    if symbol is None:
        questions.append(f"{what}: {missing}")
        return None
    if not _appears_as_word(symbol, ctx.instruction):
        questions.append(
            f"{what}: the token {_shown(symbol)} isn't in your instruction. Which token do you "
            f"mean? Known on {ctx.registry.chain_name}: {known}."
        )
        return None
    try:
        return ctx.registry.asset(symbol)
    except UnknownSymbolError:
        questions.append(
            f"{what}: {_shown(symbol)} isn't a token I know on {ctx.registry.chain_name}. "
            f"Known: {known}."
        )
        return None


def _amount(
    text: str | None,
    asset: AssetRef | None,
    ctx: _Context,
    what: str,
    missing: str,
    questions: list[str],
) -> int | None:
    """The amount in base units. Every way to get it wrong is a question.
    With no asset (its symbol needs a question first), only the checks that
    don't depend on decimals run, so one round can ask about both."""
    if text is None:
        questions.append(f"{what}: {missing}")
        return None
    shown = _shown(text)
    if "," in text:
        # "1,500" is 1500 in some places and 1.5 in others. Ask.
        questions.append(f"{what}: write {shown} without commas, e.g. 1500 or 1.5.")
        return None
    if len(text) > _MAX_AMOUNT_CHARS or not _AMOUNT.fullmatch(text):
        questions.append(
            f"{what}: {shown} isn't a plain amount. Write digits with an optional "
            "decimal point, like 50 or 0.25."
        )
        return None
    if not _amount_appears(text, ctx.instruction):
        questions.append(f"{what}: the amount {shown} isn't in your instruction. How much?")
        return None
    if asset is None:
        return None
    symbol = ctx.registry.symbol_for(asset.address) or "the token"
    base = _to_base_units(text, asset.decimals)
    if base is None:
        questions.append(
            f"{what}: {shown} {symbol} has more decimal places than {symbol} supports "
            f"({asset.decimals})."
        )
        return None
    if base == 0:
        questions.append(f"{what}: the amount must be more than zero.")
        return None
    if base >= UINT256_MAX:
        questions.append(f"{what}: {shown} {symbol} is larger than any token amount.")
        return None
    return base


def _to_base_units(text: str, decimals: int) -> int | None:
    """ "1.5" with 6 decimals -> 1500000, with integers only. None if the
    value isn't a whole number of base units. Decimal arithmetic would round
    once a result passes 28 significant digits (its default precision), and
    18-decimal amounts get there quickly."""
    whole, _, fraction = text.partition(".")
    fraction = fraction.rstrip("0")  # "1.50" and "1.5" are the same amount
    if len(fraction) > decimals:
        return None
    return int(whole) * 10**decimals + int(fraction.ljust(decimals, "0") or "0")


def _recipient(
    text: str | None, ctx: _Context, what: str, questions: list[str], notes: list[str]
) -> str | None:
    if text is None:
        questions.append(f"{what}: who should receive it? Give an address.")
        return None
    shown = _shown(text)
    if _HEX_ADDRESS.fullmatch(text):
        if not _appears_verbatim(text, ctx.instruction):
            questions.append(
                f"{what}: the address {shown} isn't in your instruction. Who should receive it?"
            )
            return None
        letters = text[2:]
        if letters != letters.lower() and text != to_checksum_address(text):
            # Mixed case is a checksum, and this one is wrong: likely a typo.
            questions.append(
                f"{what}: the address {shown} has an invalid checksum. Check it and type it again."
            )
            return None
        address = to_checksum_address(text)
        if letters == letters.lower() and any(c.isalpha() for c in letters):
            notes.append(
                f"{what}: the address {address} was typed without a checksum, so a "
                "typo in it can't be detected. Compare it character by character."
            )
        source = "you typed"
    elif text.lower().startswith("0x"):
        questions.append(f"{what}: {shown} isn't a valid address (0x and 40 hex digits).")
        return None
    else:
        if not _appears_as_word(text, ctx.instruction):
            questions.append(f"{what}: {shown} isn't in your instruction. Who should receive it?")
            return None
        found = ctx.book.get(_book_key(text))
        if found is None:
            questions.append(f"{what}: I don't have an address for {shown}. What is it?")
            return None
        address = found
        notes.append(f"{what}: {shown} is {address}, from the address book.")
        source = "from the address book"

    if address in ctx.forbidden_recipients:
        questions.append(
            f"{what}: the address {source} is {ctx.forbidden_recipients[address]}; tokens sent "
            "there are lost or go nowhere. Who should receive it?"
        )
        return None
    return address


def _venues(
    name: str | None, ctx: _Context, what: str, questions: list[str]
) -> tuple[str, ...] | None:
    known = ", ".join(v.name for v in ctx.registry.venues) or "none"
    if name is None:
        questions.append(f"{what}: on which venue? Known on {ctx.registry.chain_name}: {known}.")
        return None
    if not _appears_as_word(name, ctx.instruction):
        questions.append(
            f"{what}: the venue {_shown(name)} isn't in your instruction. Which venue? "
            f"Known: {known}."
        )
        return None
    try:
        return ctx.registry.venue(name)
    except UnknownVenueError:
        questions.append(
            f"{what}: {_shown(name)} isn't a venue I know on {ctx.registry.chain_name}. "
            f"Known: {known}."
        )
        return None


def _appears_as_word(needle: str, text: str) -> bool:
    """Case-insensitive, not inside a longer word. "USDC" appears in
    "send 100USDC" and in "$USDC" but not in "USDCX"."""
    pattern = r"(?<![A-Za-z_])" + re.escape(needle) + r"(?![A-Za-z0-9_])"
    return re.search(pattern, text, re.IGNORECASE | re.ASCII) is not None


def _amount_appears(amount: str, text: str) -> bool:
    """The amount as a whole number in the text: "5" is not in "50", "1.5",
    "-5", "0x5" or "5e3"."""
    pattern = (
        r"(?<![0-9A-Za-z_.,+\-])" + re.escape(amount) + r"(?![0-9])(?![.,][0-9])(?![eE][+\-]?[0-9])"
    )
    return re.search(pattern, text, re.ASCII) is not None


def _appears_verbatim(address: str, text: str) -> bool:
    """Exactly as written (case included), not part of a longer hex string."""
    pattern = r"(?<![0-9A-Za-z])" + re.escape(address) + r"(?![0-9A-Za-z])"
    return re.search(pattern, text, re.ASCII) is not None


# --- helpers ---------------------------------------------------------------------


def _checksummed(value: str) -> str:
    if not _HEX_ADDRESS.fullmatch(value):
        raise ValueError("not an address")
    return to_checksum_address(value)


def _book_key(name: str) -> str:
    return " ".join(name.split()).casefold()


def _load_address_book(book: Mapping[str, str]) -> dict[str, str]:
    """The operator's names for addresses. A bad entry is a configuration
    error: refuse to compile anything rather than skip it."""
    loaded: dict[str, str] = {}
    for name, address in book.items():
        key = _book_key(name)
        if not key or key.startswith("0x"):
            raise CompileError("address book names must be non-empty and not start with 0x")
        if key in loaded:
            raise CompileError("address book has two entries for one name (ignoring case)")
        if not _HEX_ADDRESS.fullmatch(address) or address != to_checksum_address(address):
            raise CompileError("address book addresses must be written with their EIP-55 checksum")
        loaded[key] = address
    return loaded


def _clean(value: str, *, limit: int) -> str:
    """A Draft string made safe to print: control and format characters
    (terminal escapes, bidi overrides) become '?', long values are cut.
    Draft strings come from the extractor, so we never print them raw."""
    clean = "".join("?" if unicodedata.category(c).startswith("C") else c for c in value)
    return clean if len(clean) <= limit else clean[: limit - 1] + "…"


def _shown(value: str) -> str:
    """A Draft value quoted inside a question."""
    return f'"{_clean(value, limit=60)}"'
