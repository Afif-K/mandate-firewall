"""Canonical mandate JSON: one byte string per mandate, and its sha256 id."""

import json

import pytest

from mandate_firewall.mandate.canonical import (
    CanonicalFormError,
    canonical_json,
    mandate_id,
    parse_canonical,
)
from mandate_firewall.mandate.models import (
    AssetRef,
    Budget,
    Limits,
    Mandate,
    Ratio,
    SwapIntent,
)
from tests.unit.test_mandate_models import mandate

USDC = AssetRef(chain_id=84532, address="0x036CbD53842c5426634e7929541eC2318f3dCF7e", decimals=6)
WETH = AssetRef(chain_id=84532, address="0x4200000000000000000000000000000000000006", decimals=18)

KNOWN = Mandate(
    schema_version=1,
    kind="one_shot",
    chain_id=84532,
    principal="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    intents=(
        SwapIntent(
            kind="swap",
            sell=USDC,
            sell_budget=Budget(max=100_000_000, period=None),
            buy=WETH,
            min_buy_per_sell=Ratio(numerator=3 * 10**16, denominator=100_000_000),
            venues=("0x5FbDB2315678afecb367f032d93F642f64180aa3",),
        ),
    ),
    limits=Limits(max_transactions=3, period=None),
    created_at="2026-10-09T12:00:00Z",
    expires_at="2026-10-09T12:30:00Z",
    instruction="swap 100 USDC for WETH on Uniswap, at least 0.03 WETH — merci",
    nonce="0x" + "ab" * 32,
)

# Written out by hand: keys sorted at every level, no whitespace, nulls kept,
# uint256 values as strings, the em dash as raw UTF-8 (not —).
KNOWN_JSON = (
    '{"chain_id":84532,"created_at":"2026-10-09T12:00:00Z",'
    '"expires_at":"2026-10-09T12:30:00Z",'
    '"instruction":"swap 100 USDC for WETH on Uniswap, at least 0.03 WETH — merci",'
    '"intents":[{"buy":{"address":"0x4200000000000000000000000000000000000006",'
    '"chain_id":84532,"decimals":18},"kind":"swap",'
    '"min_buy_per_sell":{"denominator":"100000000","numerator":"30000000000000000"},'
    '"sell":{"address":"0x036CbD53842c5426634e7929541eC2318f3dCF7e",'
    '"chain_id":84532,"decimals":6},"sell_budget":{"max":"100000000","period":null},'
    '"venues":["0x5FbDB2315678afecb367f032d93F642f64180aa3"]}],'
    '"kind":"one_shot","limits":{"max_transactions":3,"period":null},'
    '"nonce":"0xabababababababababababababababababababababababababababababababab",'
    '"principal":"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266","schema_version":1}'
).encode()
# Computed with `shasum -a 256` over KNOWN_JSON, not with our own code.
KNOWN_ID = "0x3b1c67fda43d132c0028c8453b531522e34c7f5949ea16d2c2dedbd003b660f7"


def test_known_answer() -> None:
    assert canonical_json(KNOWN) == KNOWN_JSON
    assert mandate_id(KNOWN) == KNOWN_ID


def test_round_trip() -> None:
    assert parse_canonical(KNOWN_JSON) == KNOWN
    m = mandate()
    assert parse_canonical(canonical_json(m)) == m


def test_input_key_order_does_not_change_the_id() -> None:
    data = KNOWN.model_dump(mode="json")
    reversed_data = dict(reversed(list(data.items())))
    assert mandate_id(Mandate.model_validate(reversed_data)) == KNOWN_ID


def test_any_change_changes_the_id() -> None:
    assert mandate_id(KNOWN.model_copy(update={"nonce": "0x" + "cd" * 32})) != KNOWN_ID
    other = mandate()
    assert mandate_id(other) != mandate_id(other.model_copy(update={"instruction": "send 51"}))


@pytest.mark.parametrize(
    "variant",
    [
        # Each is a valid mandate with the same meaning, in a second spelling.
        json.dumps(json.loads(KNOWN_JSON), sort_keys=True, ensure_ascii=False).encode(),  # spaces
        json.dumps(json.loads(KNOWN_JSON), separators=(",", ":"), sort_keys=True).encode(),  # \u
        json.dumps(  # keys not sorted
            dict(reversed(list(json.loads(KNOWN_JSON).items()))),
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode(),
        KNOWN_JSON.replace(b'"max":"100000000"', b'"max":100000000'),  # number, not string
        KNOWN_JSON + b"\n",
        b"\xef\xbb\xbf" + KNOWN_JSON,  # byte order mark
    ],
)
def test_non_canonical_spellings_are_rejected(variant: bytes) -> None:
    assert variant != KNOWN_JSON
    with pytest.raises(CanonicalFormError):
        parse_canonical(variant)


def test_duplicate_keys_are_rejected() -> None:
    """json.loads keeps the last duplicate; re-encoding then differs."""
    doubled = KNOWN_JSON.replace(b'{"chain_id":84532,', b'{"chain_id":1,"chain_id":84532,', 1)
    with pytest.raises(CanonicalFormError):
        parse_canonical(doubled)


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"not json",
        b"\xff\xfe",
        b"[]",
        KNOWN_JSON.replace(b'"schema_version":1', b'"schema_version":2'),
        KNOWN_JSON.replace(b"merci", b"merci \\ud800"),  # lone surrogate
    ],
)
def test_invalid_input_is_rejected(data: bytes) -> None:
    with pytest.raises(CanonicalFormError):
        parse_canonical(data)


def test_errors_do_not_echo_content() -> None:
    bad = KNOWN_JSON.replace(b'"schema_version":1', b'"schema_version":"secret-ish"')
    with pytest.raises(CanonicalFormError) as excinfo:
        parse_canonical(bad)
    assert "secret-ish" not in str(excinfo.value)
