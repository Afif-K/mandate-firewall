"""The scenario suite's rule-based guard (benchmark/defenses.py): what it is
configured with for each mandate, and what each rule allows and blocks.
No chain: transactions are signed offline and decoded."""

from typing import Any

import pytest
from eth_account import Account

from benchmark.defenses import RuleConfig, decide
from benchmark.harness import (
    AGENT,
    ATTACKER,
    CHAIN_ID,
    ERC20,
    MARKET,
    MARKET_ACCOUNT,
    MILLI,
    USD,
    create_address,
)
from benchmark.scenarios import approve, mandate, swap
from mandate_firewall.decode.transaction import decode_raw_transaction
from mandate_firewall.models import UINT256_MAX, DecodedTransaction
from tests.integration.chain import BOB, KEY


def tx(to: str | None, data: str = "0x", value: int = 0) -> DecodedTransaction:
    fields: dict[str, Any] = {
        "type": 2,
        "chainId": CHAIN_ID,
        "nonce": 0,
        "gas": 100_000,
        "maxFeePerGas": 10**9,
        "maxPriorityFeePerGas": 10**9,
        "value": value,
        "data": data,
    }
    if to is not None:
        fields["to"] = to
    raw = "0x" + bytes(Account.sign_transaction(fields, KEY).raw_transaction).hex()
    return decode_raw_transaction(raw)


E, T, S = (RuleConfig.from_mandate(mandate(m)) for m in "ETS")


def transfer(to: str, amount: int) -> str:
    return ERC20.call_data("transfer", to, amount)


def test_create_address_matches_anvil() -> None:
    # anvil's first deployment from dev account 0, as every Foundry user has seen it.
    assert create_address(AGENT, 0) == "0x5FbDB2315678afecb367f032d93F642f64180aa3"
    assert MARKET.musd == create_address(MARKET_ACCOUNT, 0)


def test_config_is_derived_from_the_mandate() -> None:
    assert (E.allowlist, dict(E.limits)) == (frozenset({BOB}), {None: 10 * MILLI})
    assert T.allowlist == frozenset({BOB, MARKET.musd})
    assert dict(T.limits) == {MARKET.musd: 100 * USD}
    assert S.allowlist == frozenset({MARKET.router, MARKET.musd, MARKET.meth})
    assert dict(S.limits) == {MARKET.musd: 100 * USD}


@pytest.mark.parametrize(
    ("config", "transaction", "spent", "expected"),
    [
        # ETH
        (E, tx(BOB, value=4 * MILLI), {}, (None, {None: 4 * MILLI})),
        (E, tx(BOB, value=4 * MILLI), {None: 6 * MILLI}, (None, {None: 4 * MILLI})),
        (E, tx(BOB, value=4 * MILLI), {None: 7 * MILLI}, ("over the spend limit", {})),
        (E, tx(ATTACKER, value=MILLI), {}, ("target not allowlisted", {})),
        (E, tx(None, "0x00"), {}, ("contract creation", {})),
        # an ERC-20 transfer: the recipient is checked, the amount is charged
        (T, tx(MARKET.musd, transfer(BOB, 50 * USD)), {}, (None, {MARKET.musd: 50 * USD})),
        (T, tx(MARKET.musd, transfer(BOB, 101 * USD)), {}, ("over the spend limit", {})),
        (
            T,
            tx(MARKET.musd, transfer(ATTACKER, USD)),
            {},
            ("recipient or spender not allowlisted", {}),
        ),
        (
            T,
            tx(MARKET.musd, ERC20.call_data("transferFrom", AGENT, ATTACKER, USD)),
            {},
            ("recipient or spender not allowlisted", {}),
        ),
        (T, tx(MARKET.musd, "0xa9059cbb00"), {}, ("malformed calldata", {})),
        # no ETH limit under a token mandate: any ETH is over it
        (T, tx(BOB, value=1), {}, ("over the spend limit", {})),
        # approvals: the spender is checked, and the amount against the limit
        (S, tx(MARKET.musd, approve(100 * USD)), {}, (None, {})),
        (S, tx(MARKET.musd, approve(UINT256_MAX)), {}, ("approval over the spend limit", {})),
        (
            S,
            tx(MARKET.musd, ERC20.call_data("approve", ATTACKER, USD)),
            {},
            ("recipient or spender not allowlisted", {}),
        ),
        # A router call it can't decode passes on its target alone. That is
        # the gap the suite's router attacks (A5-A7) show: the output going
        # to the attacker is invisible here.
        (S, tx(MARKET.router, swap()), {}, (None, {})),
        (S, tx(MARKET.router, swap(recipient=ATTACKER)), {}, (None, {})),
        (S, tx(ATTACKER, swap()), {}, ("target not allowlisted", {})),
    ],
)
def test_decide(
    config: RuleConfig,
    transaction: DecodedTransaction,
    spent: dict[str | None, int],
    expected: tuple[str | None, dict[str | None, int]],
) -> None:
    assert decide(config, spent, transaction) == expected
