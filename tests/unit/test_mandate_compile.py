"""Compiler: every Draft value grounded, or a question, or a refusal."""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from mandate_firewall.mandate.canonical import mandate_id
from mandate_firewall.mandate.compile import (
    Compiled,
    CompileError,
    CompileResult,
    NeedsClarification,
    Unsupported,
    compile_draft,
)
from mandate_firewall.mandate.draft import Draft, DraftIntent
from mandate_firewall.mandate.models import SwapIntent, TransferIntent
from mandate_firewall.mandate.registry import load_registry

REGISTRY = load_registry(84532)
PRINCIPAL = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
BOB = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
EVE = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
WETH = "0x4200000000000000000000000000000000000006"
ROUTER = "0x94cC0AaC535CCDB3C01d6787D6413C739ae12bc4"
NOW = datetime(2026, 11, 5, 12, 0, 0, tzinfo=UTC)
NONCE = "0x" + "ab" * 32


def send(
    amount: str | None = "50", symbol: str | None = "USDC", to: str | None = BOB, **extra: Any
) -> DraftIntent:
    return DraftIntent(
        kind="transfer", asset_symbol=symbol, amount_text=amount, recipient_text=to, **extra
    )


def swap(
    amount: str | None = "100",
    sell: str | None = "USDC",
    buy: str | None = "WETH",
    venue: str | None = "uniswap",
    min_out: str | None = None,
    **extra: Any,
) -> DraftIntent:
    return DraftIntent(
        kind="swap",
        asset_symbol=sell,
        amount_text=amount,
        buy_symbol=buy,
        venue_name=venue,
        min_out_text=min_out,
        **extra,
    )


def run(
    instruction: str,
    *intents: DraftIntent,
    ambiguities: tuple[str, ...] = (),
    unsupported: str | None = None,
    **kwargs: Any,
) -> CompileResult:
    draft = Draft(intents=intents, ambiguities=ambiguities, unsupported=unsupported)
    options: dict[str, Any] = {
        "instruction": instruction,
        "registry": REGISTRY,
        "principal": PRINCIPAL,
        "now": NOW,
        "nonce": NONCE,
    }
    return compile_draft(draft, **(options | kwargs))


def compiled(result: CompileResult) -> Compiled:
    assert isinstance(result, Compiled), result
    return result


def questions(result: CompileResult) -> str:
    """All questions as one string, for `in` checks."""
    assert isinstance(result, NeedsClarification), result
    return "\n".join(result.questions)


def refused(result: CompileResult) -> str:
    assert isinstance(result, Unsupported), result
    return result.reason


# --- the ambiguity table (docs/m3-plan.md §2) ------------------------------------


def test_send_with_amount_and_address_compiles() -> None:
    text = f"send 50 USDC to {BOB}"
    result = compiled(run(text, send()))
    m = result.mandate
    assert (m.chain_id, m.principal, m.instruction, m.nonce) == (84532, PRINCIPAL, text, NONCE)
    assert (m.created_at, m.expires_at) == (NOW, NOW + timedelta(minutes=30))
    assert m.limits.max_transactions == 3
    (intent,) = m.intents
    assert isinstance(intent, TransferIntent)
    assert intent.asset.address == USDC
    assert intent.budget.max == 50_000_000  # 6 decimals
    assert intent.recipient == BOB
    assert result.notes == ()


def test_send_some_asks_how_much() -> None:
    assert "how much" in questions(run(f"send some USDC to {BOB}", send(amount=None)))


def test_send_to_a_name_uses_the_address_book() -> None:
    result = compiled(run("send 50 USDC to Bob", send(to="Bob"), address_book={"bob": BOB}))
    assert result.mandate.intents[0].recipient == BOB  # type: ignore[union-attr]
    assert any("address book" in note and BOB in note for note in result.notes)


def test_send_to_an_unknown_name_asks_for_the_address() -> None:
    assert "don't have an address" in questions(run("send 50 USDC to Bob", send(to="Bob")))


def test_send_without_recipient_asks_who() -> None:
    assert "who should receive" in questions(run("send 50 USDC", send(to=None)))


def test_swap_without_amount_or_venue_asks_both() -> None:
    q = questions(run("swap my USDC for ETH", swap(amount=None, buy="ETH", venue=None)))
    assert "how much" in q
    assert "which venue" in q.lower()
    assert "uniswap" in q  # the known venues are listed


def test_extractor_ambiguities_are_asked() -> None:
    result = run(
        "buy the token from that tweet",
        ambiguities=("Which token do you mean? I can't read the tweet.",),
    )
    assert "can't read the tweet" in questions(result)


def test_extractor_unsupported_is_refused() -> None:
    reason = refused(run("bridge 50 USDC to Base mainnet", send(), unsupported="bridging"))
    assert reason == "bridging"


def test_standing_instruction_is_refused_even_if_the_extractor_misses_it() -> None:
    # The extractor read a plain one-shot swap and didn't flag the schedule.
    reason = refused(run("DCA 50 USDC into WETH every week on uniswap", swap(amount="50")))
    assert "recurring" in reason


@pytest.mark.parametrize(
    "text",
    [
        "pay Bob 50 USDC every month",
        "send 50 USDC daily",
        "swap 10 USDC per week",
        "a recurring payment of 50 USDC",
        "send 50 USDC each\tmonth",
    ],
)
def test_standing_wording_is_refused(text: str) -> None:
    assert "recurring" in refused(run(text, send()))


def test_everything_is_not_a_schedule() -> None:
    compiled(run(f"send 50 USDC to {BOB}, everything is fine", send()))


# --- addresses -------------------------------------------------------------------


def test_address_not_in_the_instruction_is_refused() -> None:
    # The user named Bob; the extractor produced Eve.
    q = questions(run(f"send 50 USDC to {BOB}", send(to=EVE)))
    assert "isn't in your instruction" in q


def test_address_must_appear_with_the_same_case() -> None:
    q = questions(run(f"send 50 USDC to {BOB.lower()}", send(to=BOB)))
    assert "isn't in your instruction" in q


def test_address_inside_longer_hex_is_not_grounded() -> None:
    q = questions(run(f"send 50 USDC to {BOB}ff", send(to=BOB)))
    assert "isn't in your instruction" in q


def test_bad_checksum_is_a_question() -> None:
    typo = BOB[:-1] + "c"  # last letter's case flipped: "C" -> "c"
    q = questions(run(f"send 50 USDC to {typo}", send(to=typo)))
    assert "invalid checksum" in q


def test_lowercase_address_compiles_with_a_note() -> None:
    low = BOB.lower()
    result = compiled(run(f"send 50 USDC to {low}", send(to=low)))
    assert result.mandate.intents[0].recipient == BOB  # type: ignore[union-attr]
    assert any("without a checksum" in note for note in result.notes)


def test_malformed_address_is_a_question() -> None:
    short = BOB[:-2]
    assert "isn't a valid address" in questions(run(f"send 50 USDC to {short}", send(to=short)))


@pytest.mark.parametrize(
    ("address", "what"),
    [
        ("0x" + "00" * 20, "zero address"),
        (PRINCIPAL, "agent's own account"),
        (USDC, "USDC token contract"),
        (ROUTER, "uniswap contract"),
    ],
)
def test_recipients_that_lose_the_funds_are_refused(address: str, what: str) -> None:
    assert what in questions(run(f"send 50 USDC to {address}", send(to=address)))


def test_address_book_name_must_be_in_the_instruction() -> None:
    q = questions(run(f"send 50 USDC to {BOB}", send(to="Bob"), address_book={"Bob": BOB}))
    assert "isn't in your instruction" in q


def test_address_book_names_ignore_case_and_spacing() -> None:
    result = run(
        "send 50 USDC to bob  smith", send(to="Bob Smith"), address_book={"bob smith": BOB}
    )
    assert "isn't in your instruction" in questions(result)  # "bob  smith" != "Bob Smith"
    result = run("send 50 USDC to bob smith", send(to="Bob Smith"), address_book={"BOB SMITH": BOB})
    compiled(result)


# --- amounts ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "amount",
    ["1e6", "1.5e3", ".5", "5.", "-5", "+5", "inf", "NaN", "0x10", "1_000", "١٢", "5 ", "½"],
)
def test_float_looking_or_odd_amounts_are_questions(amount: str) -> None:
    q = questions(run(f"send {amount} USDC to {BOB}", send(amount=amount)))
    assert "isn't a plain amount" in q


@pytest.mark.parametrize("amount", ["1,500", "1,5", "1,000,000"])
def test_commas_are_ambiguous(amount: str) -> None:
    assert "without commas" in questions(run(f"send {amount} USDC to {BOB}", send(amount=amount)))


@pytest.mark.parametrize(
    "instruction",
    [
        f"send 50 USDC to {BOB}",  # 5 is inside 50
        f"send 1.5 USDC to {BOB}",
        f"send -5 USDC to {BOB}",
        f"send 5e3 USDC to {BOB}",
        f"send 0x5 USDC to {BOB}",
        f"send 5.25 USDC to {BOB}",
    ],
)
def test_amount_must_appear_as_a_whole_number(instruction: str) -> None:
    q = questions(run(instruction, send(amount="5")))
    assert "isn't in your instruction" in q


@pytest.mark.parametrize(
    "instruction", ["send 5 USDC", "send $5 USDC", "send 5USDC", "send (5) USDC", "USDC: send 5."]
)
def test_amount_grounded_next_to_punctuation(instruction: str) -> None:
    result = run(f"{instruction} to {BOB}", send(amount="5"))
    assert compiled(result).mandate.intents[0].budget.max == 5_000_000  # type: ignore[union-attr]


def test_too_many_decimals_is_a_question() -> None:
    q = questions(run(f"send 1.0000001 USDC to {BOB}", send(amount="1.0000001")))
    assert "more decimal places than USDC supports (6)" in q


def test_trailing_zeros_are_not_extra_decimals() -> None:
    result = compiled(run(f"send 1.5000000 USDC to {BOB}", send(amount="1.5000000")))
    assert result.mandate.intents[0].budget.max == 1_500_000  # type: ignore[union-attr]


def test_eighteen_decimals_convert_exactly() -> None:
    # 36 significant digits: Decimal's default 28-digit context would round.
    amount = "123456789012345678.123456789012345678"
    result = compiled(run(f"send {amount} ETH to {BOB}", send(amount=amount, symbol="ETH")))
    (intent,) = result.mandate.intents
    assert isinstance(intent, TransferIntent)
    assert intent.asset.address is None  # native
    assert intent.budget.max == 123456789012345678123456789012345678


def test_zero_is_a_question() -> None:
    assert "more than zero" in questions(run(f"send 0.000 USDC to {BOB}", send(amount="0.000")))


def test_too_large_is_a_question() -> None:
    huge = "9" * 80
    assert "larger than any" in questions(run(f"send {huge} USDC to {BOB}", send(amount=huge)))


# --- symbols and venues ----------------------------------------------------------


def test_unknown_symbol_lists_known_ones() -> None:
    q = questions(run(f"send 50 DAI to {BOB}", send(symbol="DAI")))
    assert "isn't a token I know" in q
    assert "ETH, USDC, WETH" in q


def test_symbol_not_in_the_instruction_is_refused() -> None:
    # The user said USDC; the extractor wrote WETH.
    assert "isn't in your instruction" in questions(
        run(f"send 50 USDC to {BOB}", send(symbol="WETH"))
    )


def test_symbol_inside_a_longer_word_is_not_grounded() -> None:
    assert "isn't in your instruction" in questions(run(f"send 50 USDCX to {BOB}", send()))


def test_lookalike_symbol_is_unknown() -> None:
    fake = "USDС"  # Cyrillic Es
    assert "isn't a token I know" in questions(run(f"send 50 {fake} to {BOB}", send(symbol=fake)))


def test_symbol_case_is_ignored() -> None:
    compiled(run(f"send 50 usdc to {BOB}", send(symbol="usdc")))


def test_unknown_venue_is_a_question() -> None:
    q = questions(run("swap 100 USDC for WETH on sushiswap", swap(venue="sushiswap")))
    assert "isn't a venue I know" in q


def test_venue_not_in_the_instruction_is_refused() -> None:
    q = questions(run("swap 100 USDC for WETH", swap(venue="uniswap")))
    assert "isn't in your instruction" in q


# --- swaps -----------------------------------------------------------------------


def test_swap_with_minimum_compiles_to_a_ratio() -> None:
    text = "swap 100 USDC for at least 0.03 WETH on Uniswap"
    result = compiled(run(text, swap(venue="Uniswap", min_out="0.03")))
    (intent,) = result.mandate.intents
    assert isinstance(intent, SwapIntent)
    assert (intent.sell.address, intent.buy.address) == (USDC, WETH)
    assert intent.sell_budget.max == 100_000_000
    assert intent.min_buy_per_sell is not None
    assert intent.min_buy_per_sell.numerator == 3 * 10**16  # 0.03 WETH
    assert intent.min_buy_per_sell.denominator == 100_000_000  # per 100 USDC
    assert intent.venues == (ROUTER,)
    assert result.notes == ()


def test_swap_without_minimum_compiles_with_a_warning() -> None:
    result = compiled(run("swap 100 USDC for WETH on uniswap", swap()))
    assert result.mandate.intents[0].min_buy_per_sell is None  # type: ignore[union-attr]
    assert any("no minimum" in note for note in result.notes)


def test_swap_minimum_must_be_grounded() -> None:
    q = questions(run("swap 100 USDC for WETH on uniswap", swap(min_out="0.03")))
    assert "isn't in your instruction" in q


def test_swap_minimum_with_too_many_decimals() -> None:
    text = "swap 100 WETH for at least 0.0000001 USDC on uniswap"
    q = questions(run(text, swap(sell="WETH", buy="USDC", min_out="0.0000001")))
    assert "more decimal places" in q


def test_swap_to_another_recipient_is_unsupported() -> None:
    text = f"swap 100 USDC for WETH on uniswap and send it to {BOB}"
    assert "someone else" in refused(run(text, swap(recipient_text=BOB)))


def test_swap_of_a_token_for_itself_is_a_question() -> None:
    assert "same token" in questions(run("swap 100 USDC for USDC on uniswap", swap(buy="USDC")))


def test_transfer_with_swap_fields_asks_if_a_swap_was_meant() -> None:
    q = questions(run(f"send 50 USDC to {BOB} on uniswap", send(venue_name="uniswap")))
    assert "Did you mean a swap?" in q


# --- several intents and several questions ---------------------------------------


def test_transfer_and_swap_together() -> None:
    text = f"send 50 USDC to {BOB} and swap 100 USDC for WETH on uniswap"
    result = compiled(run(text, send(), swap()))
    assert [i.kind for i in result.mandate.intents] == ["transfer", "swap"]


def test_duplicate_intents_ask_to_combine() -> None:
    text = f"send 50 USDC to {BOB}, then another 20 USDC to {BOB}"
    assert "Combine them" in questions(run(text, send(), send(amount="20")))


def test_all_questions_come_in_one_round_and_are_numbered() -> None:
    q = questions(
        run("send some tokens and swap 100 USDC", send(None, None, None), swap(venue=None))
    )
    assert "For transfer #1: which token" in q
    assert "For transfer #1: how much" in q
    assert "For transfer #1: who should receive" in q
    assert "For swap #2: on which venue" in q


def test_no_intents_asks_what_to_do() -> None:
    assert "What should the agent do?" in questions(run("hello"))


# --- printing untrusted Draft strings --------------------------------------------


def test_control_characters_in_draft_strings_are_not_printed() -> None:
    evil = "\x1b[2J‮USDC"  # clear screen, right-to-left override
    q = questions(run(f"send 50 {evil} to {BOB}", send(symbol=evil)))
    assert "\x1b" not in q and "‮" not in q
    assert "?[2J?USDC" in q
    q = questions(run("x", ambiguities=("why\x1b[0m?",)))
    assert "\x1b" not in q


def test_long_draft_strings_are_cut() -> None:
    long = "A" * 200
    q = questions(run(f"send 50 {long} to {BOB}", send(symbol=long)))
    assert "A" * 60 not in q and "…" in q


# --- configuration and determinism ----------------------------------------------


def test_instruction_too_long_is_unsupported() -> None:
    assert "longer than" in refused(run(f"send 50 USDC to {BOB} " + "x" * 4000, send()))


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_transactions": 0},
        {"principal": "0x1234"},
        {"address_book": {"bob": BOB.lower()}},  # no checksum
        {"address_book": {"Bob": BOB, "BOB": EVE}},  # same name ignoring case
        {"address_book": {"0xbob": BOB}},
        {"address_book": {"  ": BOB}},
    ],
)
def test_bad_configuration_raises(kwargs: dict[str, Any]) -> None:
    with pytest.raises(CompileError):
        run(f"send 50 USDC to {BOB}", send(), **kwargs)


@pytest.mark.parametrize("lifetime", [timedelta(0), timedelta(hours=24, seconds=1)])
def test_lifetime_out_of_range_raises(lifetime: timedelta) -> None:
    # The Mandate model would reject these too; the compiler says why first.
    with pytest.raises(CompileError, match="lifetime"):
        run(f"send 50 USDC to {BOB}", send(), lifetime=lifetime)


def test_configured_lifetime_and_cap() -> None:
    result = run(f"send 50 USDC to {BOB}", send(), lifetime=timedelta(hours=2), max_transactions=1)
    m = compiled(result).mandate
    assert m.expires_at - m.created_at == timedelta(hours=2)
    assert m.limits.max_transactions == 1


def test_now_is_truncated_to_seconds() -> None:
    result = run(f"send 50 USDC to {BOB}", send(), now=NOW.replace(microsecond=999_999))
    assert compiled(result).mandate.created_at == NOW


def test_same_input_same_mandate_id() -> None:
    text = f"send 50 USDC to {BOB}"
    first = compiled(run(text, send())).mandate
    again = compiled(run(text, send())).mandate
    assert mandate_id(first) == mandate_id(again)


def test_default_nonce_is_random() -> None:
    text = f"send 50 USDC to {BOB}"
    a = compiled(run(text, send(), nonce=None)).mandate
    b = compiled(run(text, send(), nonce=None)).mandate
    assert a.nonce != b.nonce
