"""Mandate models: what the user allowed, shaped like the effects M4 checks.

A mandate doesn't describe calls ("call swap() on router R"). It bounds
outcomes ("at most 100 USDC may leave, at least 0.0003 WETH per USDC must
arrive, approvals only to R"), because that is what simulation measures and the
same outcome can be reached through many different calls. It is a budget the
agent's transactions draw on, not a script of steps, so approve-then-swap is
one mandate. See docs/m3-plan.md §1.

Every field is always present, null included. The mandate id is a hash of the
canonical JSON (canonical.py), so "missing" and "null" must never both be
possible spellings of one mandate. Fields reserved for standing mandates
(`period`) exist now for the same reason, and one-shot mandates must leave them
null.
"""

import re
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Annotated, Any, Literal, Self

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    PlainSerializer,
    Strict,
    model_validator,
)

from mandate_firewall.models import UINT256_MAX, Address, Hash32, Uint256

ONE_SHOT_MAX_LIFETIME = timedelta(hours=24)
DEFAULT_LIFETIME = timedelta(minutes=30)
DEFAULT_MAX_TRANSACTIONS = 3
MAX_INSTRUCTION_CHARS = 4000

# Small integers stay JSON numbers. Capped at 2**53 - 1 so every JSON parser
# (including ones that read numbers as doubles) sees the same value.
_JSON_SAFE_INT = 2**53 - 1
StrictCount = Annotated[int, Strict(), Field(ge=1, le=_JSON_SAFE_INT)]
ChainId = Annotated[int, Strict(), Field(gt=0, le=_JSON_SAFE_INT)]

_UTC_SECONDS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_UTC_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def _utc_seconds(value: Any) -> datetime:
    """A timezone-aware datetime at whole seconds, or its one string spelling
    "YYYY-MM-DDTHH:MM:SSZ". Pydantic would also take unix numbers, offsets
    like +02:00 and fractions, each a second way to write the same instant."""
    if isinstance(value, str):
        if not _UTC_SECONDS.fullmatch(value):
            raise ValueError("expected a UTC time written as YYYY-MM-DDTHH:MM:SSZ")
        return datetime.strptime(value, _UTC_FORMAT).replace(tzinfo=UTC)
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("a mandate time must be timezone-aware")
        if value.microsecond:
            raise ValueError("a mandate time must be whole seconds")
        return value.astimezone(UTC)
    raise ValueError("expected a datetime or a UTC time string")


UtcSeconds = Annotated[
    datetime,
    BeforeValidator(_utc_seconds),
    PlainSerializer(lambda dt: dt.strftime(_UTC_FORMAT), return_type=str, when_used="json"),
]

# A budget or minimum of UINT256_MAX reads as "unlimited" to most contracts.
# Mandates never grant that.
Bounded = Annotated[Uint256, Field(gt=0, lt=UINT256_MAX)]


class _Strict(BaseModel):
    # extra="forbid": a stored mandate with fields we don't know about is not
    # one we wrote, so reading it back must fail.
    model_config = ConfigDict(frozen=True, extra="forbid")


class MandateKind(StrEnum):
    ONE_SHOT = "one_shot"  # STANDING arrives with the standing-mandates milestone (M5)


class Period(_Strict):
    """Reserved for standing mandates (M5): budgets and caps that reset every
    `unit`, in windows starting at `anchor`. One-shot mandates must leave every
    period null, so no stored mandate depends on this shape yet."""

    unit: Literal["day", "week", "month"]
    anchor: UtcSeconds


class AssetRef(_Strict):
    """A token or native ETH, resolved from the trusted registry, never from
    a token's own name or symbol (which its deployer chooses)."""

    chain_id: ChainId
    address: Address | None  # None = native ETH
    decimals: Annotated[int, Strict(), Field(ge=0, le=77)]  # display only


class Budget(_Strict):
    """The most of an asset that may leave the principal, in base units."""

    max: Bounded
    period: Period | None  # None = over the mandate's whole life


class Ratio(_Strict):
    """numerator / denominator, in base units of buy per base unit of sell.
    M4 compares with integers only: bought * denominator >= sold * numerator."""

    numerator: Bounded
    denominator: Bounded


class TransferIntent(_Strict):
    kind: Literal["transfer"]
    asset: AssetRef
    budget: Budget
    recipient: Address


class SwapIntent(_Strict):
    """Sell up to a budget of one asset for another. Implicit, checked by M4:
    what is bought arrives at the principal."""

    kind: Literal["swap"]
    sell: AssetRef
    sell_budget: Budget
    buy: AssetRef
    min_buy_per_sell: Ratio | None  # None = the user gave no minimum
    venues: tuple[Address, ...] = Field(min_length=1)  # the only allowed spenders

    @model_validator(mode="after")
    def _check(self) -> Self:
        if (self.sell.chain_id, self.sell.address) == (self.buy.chain_id, self.buy.address):
            raise ValueError("a swap sells one asset for a different one")
        if len(set(self.venues)) != len(self.venues):
            raise ValueError("each venue may appear only once")
        return self


Intent = Annotated[TransferIntent | SwapIntent, Field(discriminator="kind")]


class Limits(_Strict):
    max_transactions: StrictCount
    period: Period | None  # None = over the mandate's whole life


class Mandate(_Strict):
    """What the user allowed one agent account to do, until it expires.

    The model checks that a mandate is well-formed. Whether it is still
    active (expired, revoked, used up) is the store's job, so an expired
    mandate still loads.
    """

    schema_version: Annotated[int, Strict(), Field(ge=1, le=1)]
    kind: MandateKind
    chain_id: ChainId
    principal: Address  # the agent account this mandate governs
    intents: tuple[Intent, ...] = Field(min_length=1)
    limits: Limits
    created_at: UtcSeconds
    expires_at: UtcSeconds
    # The user's own words (trusted), for the audit log and M4's explanation.
    instruction: str = Field(min_length=1, max_length=MAX_INSTRUCTION_CHARS)
    nonce: Hash32  # random, so two identical instructions get different ids

    @model_validator(mode="after")
    def _check(self) -> Self:
        if self.expires_at <= self.created_at:
            raise ValueError("a mandate must expire after it is created")
        if not self.instruction.strip():
            raise ValueError("the instruction is empty")

        if self.kind is MandateKind.ONE_SHOT:
            if self.expires_at - self.created_at > ONE_SHOT_MAX_LIFETIME:
                raise ValueError("a one-shot mandate lasts at most 24 hours")
            if self.limits.period is not None or any(
                budget.period is not None for budget in self._budgets()
            ):
                raise ValueError("a one-shot mandate has no periods")

        for asset in self._assets():
            if asset.chain_id != self.chain_id:
                raise ValueError("every asset must be on the mandate's chain")

        # Two intents over the same asset and counterparty would make it
        # ambiguous which budget a transaction draws on. The user merges them.
        keys = [
            ("transfer", i.asset.address, i.recipient)
            if isinstance(i, TransferIntent)
            else ("swap", i.sell.address, i.buy.address)
            for i in self.intents
        ]
        if len(set(keys)) != len(keys):
            raise ValueError("two intents cover the same asset and counterparty")

        for intent in self.intents:
            if isinstance(intent, SwapIntent) and self.principal in intent.venues:
                raise ValueError("the principal can't be its own venue")
        return self

    def _budgets(self) -> list[Budget]:
        return [i.budget if isinstance(i, TransferIntent) else i.sell_budget for i in self.intents]

    def _assets(self) -> list[AssetRef]:
        return [
            asset
            for i in self.intents
            for asset in ((i.asset,) if isinstance(i, TransferIntent) else (i.sell, i.buy))
        ]
