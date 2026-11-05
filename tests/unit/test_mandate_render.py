"""The confirmation summary: a fixed template, full addresses, exact amounts."""

from datetime import timedelta

import pytest

from mandate_firewall.mandate.registry import load_registry
from mandate_firewall.mandate.render import format_units, render, safe_text, summary_line
from tests.unit.test_mandate_models import BOB, CREATED, ETH, USDC, WETH, mandate, swap, transfer

REGISTRY = load_registry(84532)
ROUTER = "0x94cC0AaC535CCDB3C01d6787D6413C739ae12bc4"  # SwapRouter02 in the registry
NOW = CREATED + timedelta(minutes=1)


def test_transfer_exact_screen() -> None:
    text = render(mandate(), REGISTRY, now=NOW)
    assert text == (
        "Mandate for agent account 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266\n"
        "  on Base Sepolia (chain 84532)\n"
        "  valid until 2026-10-09 12:30:00 UTC (in 29 min)\n"
        '  you said: "send 50 USDC to 0x70997970C51812dc3A010C7d01b50e0d17dc79C8"\n'
        "\n"
        "  1. SEND at most 50 USDC (token 0x036CbD53842c5426634e7929541eC2318f3dCF7e)\n"
        "       to 0x70997970C51812dc3A010C7d01b50e0d17dc79C8\n"
        "\n"
        "  At most 3 transactions. Nothing else may leave this account."
    )


def test_swap_with_minimum() -> None:
    text = render(mandate(intents=(swap(venues=(ROUTER,)),)), REGISTRY, now=NOW)
    assert (
        "1. SWAP sell at most 100 USDC (token 0x036CbD53842c5426634e7929541eC2318f3dCF7e)" in text
    )
    assert "buy WETH (token 0x4200000000000000000000000000000000000006)" in text
    assert "minimum: at least 0.03 WETH per 100 USDC sold" in text
    assert f"Uniswap v3 SwapRouter02 ({ROUTER})" in text


def test_swap_without_minimum_warns() -> None:
    text = render(
        mandate(intents=(swap(min_buy_per_sell=None, venues=(ROUTER,)),)), REGISTRY, now=NOW
    )
    assert "minimum: NONE ⚠ you could receive far less" in text


def test_addresses_are_never_shortened() -> None:
    text = render(mandate(intents=(transfer(), swap(venues=(ROUTER,)))), REGISTRY, now=NOW)
    assert "…" not in text and "..." not in text
    for address in (BOB, USDC.address, WETH.address, ROUTER, mandate().principal):
        assert address in text


def test_unregistered_names_are_flagged() -> None:
    other_venue = "0x5FbDB2315678afecb367f032d93F642f64180aa3"  # not in the registry
    text = render(mandate(intents=(swap(venues=(other_venue,)),)), REGISTRY, now=NOW)
    assert f"UNREGISTERED CONTRACT ({other_venue})" in text


def test_native_eth() -> None:
    text = render(
        mandate(intents=(transfer(asset=ETH, budget=transfer().budget),)), REGISTRY, now=NOW
    )
    assert "SEND at most 0.00000000005 ETH (native)" in text  # 50_000_000 wei


def test_replaces_line_and_singular_transaction() -> None:
    from mandate_firewall.mandate.models import Limits

    m = mandate(limits=Limits(max_transactions=1, period=None))
    text = render(m, REGISTRY, now=NOW, replaces="0xabc")
    assert "At most 1 transaction. Nothing" in text
    assert "This REPLACES active mandate 0xabc, which will be revoked." in text


@pytest.mark.parametrize(
    ("now", "expected"),
    [
        (CREATED, "in 30 min"),
        (CREATED + timedelta(minutes=29, seconds=30), "in under a minute"),
        (CREATED + timedelta(minutes=30), "expired"),
    ],
)
def test_relative_expiry(now: object, expected: str) -> None:
    assert f"({expected})" in render(mandate(), REGISTRY, now=now)  # type: ignore[arg-type]


def test_long_lifetimes_in_hours() -> None:
    m = mandate(expires_at=CREATED + timedelta(hours=5, minutes=7))
    assert "(in 5 h 7 min)" in render(m, REGISTRY, now=CREATED)


def test_instruction_is_made_safe_for_the_terminal() -> None:
    m = mandate(instruction="send 50 USDC\x1b[2J‮ to Bob\nnext line")
    text = render(m, REGISTRY, now=NOW)
    assert "\x1b" not in text and "‮" not in text
    assert 'you said: "send 50 USDC?[2J? to Bob next line"' in text


@pytest.mark.parametrize(
    ("value", "decimals", "expected"),
    [
        (0, 6, "0"),
        (1_500_000, 6, "1.5"),
        (1, 6, "0.000001"),
        (100_000_000, 6, "100"),
        (5, 0, "5"),
        (123456789012345678123456789012345678, 18, "123456789012345678.123456789012345678"),
    ],
)
def test_format_units(value: int, decimals: int, expected: str) -> None:
    assert format_units(value, decimals) == expected


def test_summary_line() -> None:
    line = summary_line(mandate(intents=(transfer(), swap(venues=(ROUTER,)))), REGISTRY)
    assert line == f"send ≤50 USDC to {BOB}; swap ≤100 USDC for WETH"


def test_safe_text_cuts() -> None:
    assert safe_text("a" * 10, limit=5) == "aaaa…"
