"""Mandate models: strict values, one-shot rules, reserved standing fields."""

from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import ValidationError

from mandate_firewall.mandate.models import (
    ONE_SHOT_MAX_LIFETIME,
    AssetRef,
    Budget,
    Limits,
    Mandate,
    MandateKind,
    Period,
    Ratio,
    SwapIntent,
    TransferIntent,
)
from mandate_firewall.models import UINT256_MAX

CHAIN = 84532
PRINCIPAL = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
BOB = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
ROUTER = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
USDC = AssetRef(chain_id=CHAIN, address="0x036CbD53842c5426634e7929541eC2318f3dCF7e", decimals=6)
WETH = AssetRef(chain_id=CHAIN, address="0x4200000000000000000000000000000000000006", decimals=18)
ETH = AssetRef(chain_id=CHAIN, address=None, decimals=18)
CREATED = datetime(2026, 10, 9, 12, 0, 0, tzinfo=UTC)


def transfer(**overrides: Any) -> TransferIntent:
    fields: dict[str, Any] = {
        "kind": "transfer",
        "asset": USDC,
        "budget": Budget(max=50_000_000, period=None),
        "recipient": BOB,
    }
    return TransferIntent(**(fields | overrides))


def swap(**overrides: Any) -> SwapIntent:
    fields: dict[str, Any] = {
        "kind": "swap",
        "sell": USDC,
        "sell_budget": Budget(max=100_000_000, period=None),
        "buy": WETH,
        "min_buy_per_sell": Ratio(numerator=3 * 10**16, denominator=100_000_000),
        "venues": (ROUTER,),
    }
    return SwapIntent(**(fields | overrides))


def mandate(**overrides: Any) -> Mandate:
    """Send 50 USDC to Bob, valid for 30 minutes."""
    fields: dict[str, Any] = {
        "schema_version": 1,
        "kind": MandateKind.ONE_SHOT,
        "chain_id": CHAIN,
        "principal": PRINCIPAL,
        "intents": (transfer(),),
        "limits": Limits(max_transactions=3, period=None),
        "created_at": CREATED,
        "expires_at": CREATED + timedelta(minutes=30),
        "instruction": "send 50 USDC to 0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        "nonce": "0x" + "ab" * 32,
    }
    return Mandate(**(fields | overrides))


def test_valid_mandates() -> None:
    assert mandate().intents[0].recipient == BOB
    both = mandate(intents=(transfer(), swap()))
    assert isinstance(both.intents[1], SwapIntent)
    assert mandate(intents=(transfer(asset=ETH),)).intents[0].asset.address is None
    assert mandate(intents=(swap(min_buy_per_sell=None),)).intents[0].min_buy_per_sell is None


def test_frozen() -> None:
    with pytest.raises(ValidationError):
        mandate().chain_id = 1  # type: ignore[misc]


def test_unknown_fields_are_rejected() -> None:
    data = mandate().model_dump()
    data["spend_anything"] = True
    with pytest.raises(ValidationError):
        Mandate.model_validate(data)
    data = mandate().model_dump()
    data["intents"][0]["memo"] = "hi"
    with pytest.raises(ValidationError):
        Mandate.model_validate(data)


def test_every_field_is_required() -> None:
    """No defaults: a missing field and a null field must not both be
    spellings of the same mandate (the id is a hash of the JSON)."""
    data = mandate().model_dump()
    for name in data:
        partial = {k: v for k, v in data.items() if k != name}
        with pytest.raises(ValidationError):
            Mandate.model_validate(partial)
    budget = {"max": 1}
    with pytest.raises(ValidationError):
        Budget.model_validate(budget)  # period must be given, even as None
    with pytest.raises(ValidationError):
        Limits.model_validate({"max_transactions": 3})


def test_intent_kind_selects_the_model() -> None:
    data = mandate().model_dump()
    data["intents"][0]["kind"] = "approve"
    with pytest.raises(ValidationError):
        Mandate.model_validate(data)


@pytest.mark.parametrize("value", [0, UINT256_MAX, UINT256_MAX + 1, -1, True, 1.0, "1_000"])
def test_budget_bounds(value: Any) -> None:
    """Zero is no budget, UINT256_MAX reads as "unlimited" to contracts."""
    with pytest.raises(ValidationError):
        Budget(max=value, period=None)


def test_budget_accepts_decimal_strings() -> None:
    assert Budget(max="50000000", period=None).max == 50_000_000
    assert Budget(max=UINT256_MAX - 1, period=None).max == UINT256_MAX - 1


@pytest.mark.parametrize(
    ("numerator", "denominator"), [(0, 1), (1, 0), (UINT256_MAX, 1), (1, UINT256_MAX)]
)
def test_ratio_bounds(numerator: int, denominator: int) -> None:
    with pytest.raises(ValidationError):
        Ratio(numerator=numerator, denominator=denominator)


@pytest.mark.parametrize("value", [True, 1.0, "84532", 0, -1, 2**53])
def test_chain_id_is_a_strict_small_int(value: Any) -> None:
    with pytest.raises(ValidationError):
        mandate(chain_id=value)


@pytest.mark.parametrize("value", [2, 0, True, 1.0, "1"])
def test_schema_version_is_exactly_1(value: Any) -> None:
    with pytest.raises(ValidationError):
        mandate(schema_version=value)


@pytest.mark.parametrize("value", [0, True, 3.0, "3"])
def test_max_transactions_is_a_strict_positive_int(value: Any) -> None:
    with pytest.raises(ValidationError):
        Limits(max_transactions=value, period=None)


@pytest.mark.parametrize("decimals", [-1, 78, True, 6.0])
def test_decimals_range(decimals: Any) -> None:
    with pytest.raises(ValidationError):
        AssetRef(chain_id=CHAIN, address=None, decimals=decimals)


def test_addresses_are_checksummed() -> None:
    lower = mandate(principal=PRINCIPAL.lower())
    assert lower.principal == PRINCIPAL
    with pytest.raises(ValidationError):
        mandate(principal="0xF39Fd6e51aad88F6F4ce6aB8827279cffFb92266")  # bad checksum
    with pytest.raises(ValidationError):
        transfer(recipient="bob.eth")


# --- times ---------------------------------------------------------------------


def test_time_string_spelling() -> None:
    m = mandate(created_at="2026-10-09T12:00:00Z", expires_at="2026-10-09T12:30:00Z")
    assert m.created_at == CREATED
    assert m.model_dump(mode="json")["expires_at"] == "2026-10-09T12:30:00Z"


@pytest.mark.parametrize(
    "value",
    [
        "2026-10-09T12:00:00+00:00",  # an offset instead of Z
        "2026-10-09T12:00:00.000Z",  # fractions
        "2026-10-09 12:00:00Z",
        "2026-10-09T12:00:00z",
        1791547200,  # a unix timestamp
        datetime(2026, 10, 9, 12, 0, 0),  # naive
        datetime(2026, 10, 9, 12, 0, 0, 500, tzinfo=UTC),  # not whole seconds
    ],
)
def test_other_time_spellings_are_rejected(value: Any) -> None:
    with pytest.raises(ValidationError):
        mandate(created_at=value)


def test_aware_times_are_converted_to_utc() -> None:
    plus_two = timezone(timedelta(hours=2))
    m = mandate(created_at=datetime(2026, 10, 9, 14, 0, 0, tzinfo=plus_two))
    assert m.created_at == CREATED
    assert m.created_at.utcoffset() == timedelta(0)


def test_expiry_must_follow_creation() -> None:
    with pytest.raises(ValidationError):
        mandate(expires_at=CREATED)
    with pytest.raises(ValidationError):
        mandate(expires_at=CREATED - timedelta(seconds=1))


def test_one_shot_lasts_at_most_24_hours() -> None:
    assert mandate(expires_at=CREATED + ONE_SHOT_MAX_LIFETIME)
    with pytest.raises(ValidationError, match="24 hours"):
        mandate(expires_at=CREATED + ONE_SHOT_MAX_LIFETIME + timedelta(seconds=1))


# --- reserved standing-mandate fields ---------------------------------------------


def test_period_model_exists_but_one_shot_rejects_it() -> None:
    weekly = Period(unit="week", anchor=CREATED)
    with pytest.raises(ValidationError, match="no periods"):
        mandate(limits=Limits(max_transactions=3, period=weekly))
    with pytest.raises(ValidationError, match="no periods"):
        mandate(intents=(transfer(budget=Budget(max=1, period=weekly)),))
    with pytest.raises(ValidationError, match="no periods"):
        mandate(intents=(swap(sell_budget=Budget(max=1, period=weekly)),))


def test_standing_kind_does_not_exist_yet() -> None:
    with pytest.raises(ValidationError):
        mandate(kind="standing")


# --- cross-field rules ---------------------------------------------------------------


def test_assets_must_be_on_the_mandate_chain() -> None:
    mainnet_usdc = USDC.model_copy(update={"chain_id": 8453})
    with pytest.raises(ValidationError, match="chain"):
        mandate(intents=(transfer(asset=mainnet_usdc),))
    with pytest.raises(ValidationError, match="chain"):
        mandate(intents=(swap(buy=WETH.model_copy(update={"chain_id": 8453})),))


def test_swap_needs_two_different_assets() -> None:
    with pytest.raises(ValidationError, match="different"):
        swap(buy=USDC)


def test_swap_needs_unique_venues() -> None:
    with pytest.raises(ValidationError):
        swap(venues=())
    with pytest.raises(ValidationError, match="once"):
        swap(venues=(ROUTER, ROUTER.lower()))  # same address, two spellings


def test_principal_is_not_a_venue() -> None:
    with pytest.raises(ValidationError, match="venue"):
        mandate(intents=(swap(venues=(PRINCIPAL,)),))


def test_overlapping_intents_are_rejected() -> None:
    """Which budget would a transfer of USDC to Bob draw on?"""
    with pytest.raises(ValidationError, match="same asset"):
        mandate(intents=(transfer(), transfer(budget=Budget(max=1, period=None))))
    with pytest.raises(ValidationError, match="same asset"):
        mandate(intents=(swap(), swap(min_buy_per_sell=None)))
    # Different recipient, or a transfer and a swap of the same asset: fine.
    assert mandate(intents=(transfer(), transfer(recipient=PRINCIPAL), swap()))


def test_intents_and_instruction_are_required() -> None:
    with pytest.raises(ValidationError):
        mandate(intents=())
    with pytest.raises(ValidationError):
        mandate(instruction="")
    with pytest.raises(ValidationError, match="empty"):
        mandate(instruction="  \n ")
    with pytest.raises(ValidationError):
        mandate(instruction="x" * 4001)
    # Pydantic refuses lone surrogates, which can't be encoded as UTF-8.
    with pytest.raises(ValidationError, match="unicode"):
        mandate(instruction="send \ud800")


def test_nonce_is_32_bytes_of_hex() -> None:
    assert mandate(nonce="0x" + "AB" * 32).nonce == "0x" + "ab" * 32
    with pytest.raises(ValidationError):
        mandate(nonce="0x1234")
