"""Live check against the real Messages API: catches drift between our raw
HTTP request and the API (docs/m3-plan.md §5).

Opt-in only, because it costs money: `uv run pytest -m llm`. The default
run deselects it (addopts in pyproject.toml), and it skips without
LLM_API_KEY (from the environment or .env).
"""

from datetime import UTC, datetime

import pytest

from mandate_firewall.capture.extractor import AnthropicExtractor
from mandate_firewall.capture.settings import CaptureSettings
from mandate_firewall.mandate.compile import Compiled, NeedsClarification, compile_draft
from mandate_firewall.mandate.registry import load_registry

pytestmark = pytest.mark.llm

BOB = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
PRINCIPAL = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"


@pytest.fixture(scope="module")
def extractor() -> AnthropicExtractor:
    settings = CaptureSettings()
    if settings.llm_api_key is None:
        pytest.skip("LLM_API_KEY not set")
    return AnthropicExtractor(settings)


def _compile(text: str, extractor: AnthropicExtractor) -> object:
    return compile_draft(
        extractor.extract(text),
        instruction=text,
        registry=load_registry(84532),
        principal=PRINCIPAL,
        now=datetime.now(UTC),
    )


def test_transfer_compiles(extractor: AnthropicExtractor) -> None:
    result = _compile(f"send 50 USDC to {BOB}", extractor)
    assert isinstance(result, Compiled), result
    (intent,) = result.mandate.intents
    assert intent.kind == "transfer"
    assert intent.budget.max == 50_000_000
    assert intent.recipient == BOB  # type: ignore[union-attr]


def test_swap_with_minimum_compiles(extractor: AnthropicExtractor) -> None:
    result = _compile("swap 100 USDC for at least 0.03 WETH on Uniswap", extractor)
    assert isinstance(result, Compiled), result
    (intent,) = result.mandate.intents
    assert intent.kind == "swap"
    assert intent.min_buy_per_sell is not None  # type: ignore[union-attr]


def test_missing_minimum_is_asked_then_answered(extractor: AnthropicExtractor) -> None:
    # docs/m4-plan.md §6: the answer is appended to the instruction, and the
    # real extractor must pick the minimum up from that second line.
    first = "swap 100 USDC for WETH on Uniswap"
    asked = _compile(first, extractor)
    assert isinstance(asked, NeedsClarification), asked
    assert any("at least how much WETH" in q for q in asked.questions)
    result = _compile(f"{first}\nat least 0.03 WETH", extractor)
    assert isinstance(result, Compiled), result
    ratio = result.mandate.intents[0].min_buy_per_sell  # type: ignore[union-attr]
    assert ratio is not None and ratio.numerator == 3 * 10**16


def test_missing_values_become_questions(extractor: AnthropicExtractor) -> None:
    result = _compile("swap my USDC for ETH", extractor)
    assert isinstance(result, NeedsClarification), result


def test_recurring_is_flagged(extractor: AnthropicExtractor) -> None:
    draft = extractor.extract(
        "pay 50 USDC to 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 every month"
    )
    assert draft.unsupported is not None
