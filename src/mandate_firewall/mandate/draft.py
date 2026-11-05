"""The Draft: what the extractor read in the user's instruction, as strings.

A Draft is deliberately weaker than a Mandate. Every value is text copied
from the instruction: no base units, no token addresses, no chain ids. The
LLM extractor (commit 5) and the structured CLI flags (commit 6) both produce
one, and the compiler (compile.py) is the only way a Draft becomes a Mandate.
Nothing in a Draft is trusted: the compiler grounds every value in the
user's own text, the registry or the operator's address book.

Every field except `kind` is optional. If the instruction doesn't say how
much, the field is null and the compiler asks. We don't depend on the LLM
noticing what's missing.
"""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

MAX_DRAFT_INTENTS = 5

# Bounds against a runaway or hostile extractor response. Real values are short.
Text = Annotated[str, Field(min_length=1, max_length=200)]
Question = Annotated[str, Field(min_length=1, max_length=500)]


class _Strict(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class DraftIntent(_Strict):
    kind: Literal["transfer", "swap"]
    asset_symbol: Text | None = None  # transfer: the asset; swap: what is sold
    amount_text: Text | None = None  # transfer: the amount; swap: the sell amount
    recipient_text: Text | None = None  # transfer only: an address or an address-book name
    buy_symbol: Text | None = None  # swap only
    min_out_text: Text | None = None  # swap only: least amount of buy_symbol to receive
    venue_name: Text | None = None  # swap only


class Draft(_Strict):
    intents: tuple[DraftIntent, ...] = Field(max_length=MAX_DRAFT_INTENTS)
    ambiguities: tuple[Question, ...] = Field(default=(), max_length=10)
    unsupported: Text | None = None  # e.g. "bridging", "a recurring payment"
