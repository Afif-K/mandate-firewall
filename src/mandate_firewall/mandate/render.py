"""Render a mandate as the text the user confirms.

This text is the security control of capture (docs/m3-plan.md §2): the user
reads it and types "yes". So it comes from a fixed template filled with the
compiled Mandate and the trusted registry. No LLM prose, nothing the
extractor wrote.

Two rules:
- Addresses are printed in full, never shortened to 0x1234…abcd. Address
  poisoning attacks generate addresses that match the first and last
  characters of a real one, so a shortened address is the one thing they
  need the user to see.
- Amounts are converted from base units with integer arithmetic, exactly.
  The summary never rounds.
"""

import math
import unicodedata
from datetime import datetime, timedelta

from mandate_firewall.mandate.models import AssetRef, Mandate, Ratio, SwapIntent, TransferIntent
from mandate_firewall.mandate.registry import Registry

NO_MINIMUM_WARNING = "NONE ⚠ you could receive far less than the tokens are worth"


def render(
    mandate: Mandate, registry: Registry, *, now: datetime, replaces: str | None = None
) -> str:
    """The confirmation summary. `replaces` names an active mandate that
    locking this one will revoke."""
    lines = [
        f"Mandate for agent account {mandate.principal}",
        f"  on {registry.chain_name} (chain {mandate.chain_id})",
        f"  valid until {_utc(mandate.expires_at)} ({_relative(mandate.expires_at, now)})",
        f'  you said: "{safe_text(mandate.instruction)}"',
        "",
    ]
    for number, intent in enumerate(mandate.intents, start=1):
        lines += intent_lines(number, intent, registry)
        lines.append("")
    lines.append(
        f"  At most {mandate.limits.max_transactions} transaction"
        f"{'s' if mandate.limits.max_transactions != 1 else ''}. "
        "Nothing else may leave this account."
    )
    if replaces is not None:
        lines.append(f"  This REPLACES active mandate {replaces}, which will be revoked.")
    return "\n".join(lines)


def summary_line(mandate: Mandate, registry: Registry) -> str:
    """One line per mandate, for `mandate list`."""
    parts = []
    for intent in mandate.intents:
        if isinstance(intent, TransferIntent):
            amount = amount_text(intent.budget.max, intent.asset, registry, with_address=False)
            parts.append(f"send ≤{amount} to {intent.recipient}")
        else:
            sell = amount_text(intent.sell_budget.max, intent.sell, registry, with_address=False)
            parts.append(f"swap ≤{sell} for {_symbol(intent.buy, registry)}")
    return "; ".join(parts)


def format_units(value: int, decimals: int) -> str:
    """Base units to a decimal string, exactly: 1500000 with 6 -> "1.5"."""
    if decimals == 0:
        return str(value)
    whole, fraction = divmod(value, 10**decimals)
    fraction_text = str(fraction).rjust(decimals, "0").rstrip("0")
    return f"{whole}.{fraction_text}" if fraction_text else str(whole)


def safe_text(value: str, limit: int = 500) -> str:
    """Text made safe for a terminal: control and format characters
    (escapes, bidi overrides, newlines) become '?' or a space."""
    out = []
    for char in value:
        if char in "\n\t":
            out.append(" ")
        elif unicodedata.category(char).startswith("C"):
            out.append("?")
        else:
            out.append(char)
    text = "".join(out)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def intent_lines(number: int, intent: TransferIntent | SwapIntent, registry: Registry) -> list[str]:
    """The lines for one intent, numbered from 1. Shared with the verifier's
    explanations (verify/explain.py), so "You asked" there is word for word
    what the user confirmed here."""
    if isinstance(intent, TransferIntent):
        return [
            f"  {number}. SEND at most {amount_text(intent.budget.max, intent.asset, registry)}",
            f"       to {intent.recipient}",
        ]
    return _swap_lines(number, intent, registry)


def _swap_lines(number: int, intent: SwapIntent, registry: Registry) -> list[str]:
    sell = amount_text(intent.sell_budget.max, intent.sell, registry)
    lines = [
        f"  {number}. SWAP sell at most {sell}",
        f"       buy {asset_text(intent.buy, registry)}",
        f"       minimum: {_minimum(intent.min_buy_per_sell, intent, registry)}",
        "       only via:",
    ]
    lines += [f"         {venue_text(address, registry)}" for address in intent.venues]
    return lines


def _minimum(ratio: Ratio | None, intent: SwapIntent, registry: Registry) -> str:
    if ratio is None:
        return NO_MINIMUM_WARNING
    # Exact either way: the ratio is stored as written ("0.03 WETH for 100
    # USDC"), so print both sides rather than dividing.
    buy = format_units(ratio.numerator, intent.buy.decimals)
    sell = format_units(ratio.denominator, intent.sell.decimals)
    return (
        f"at least {buy} {_symbol(intent.buy, registry)} per {sell} "
        f"{_symbol(intent.sell, registry)} sold"
    )


def amount_text(
    value: int, asset: AssetRef, registry: Registry, *, with_address: bool = True
) -> str:
    text = f"{format_units(value, asset.decimals)} {_symbol(asset, registry)}"
    if with_address:
        text += f" ({_where(asset)})"
    return text


def asset_text(asset: AssetRef, registry: Registry) -> str:
    return f"{_symbol(asset, registry)} ({_where(asset)})"


def _where(asset: AssetRef) -> str:
    return "native" if asset.address is None else f"token {asset.address}"


def _symbol(asset: AssetRef, registry: Registry) -> str:
    # Registry names only: a token's own symbol() is chosen by its deployer.
    return registry.symbol_for(asset.address) or "UNREGISTERED TOKEN"


def venue_text(address: str, registry: Registry) -> str:
    for venue in registry.venues:
        for contract in venue.contracts:
            if contract.address == address:
                return f"{contract.label} ({address})"
    return f"UNREGISTERED CONTRACT ({address})"


def _utc(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S UTC")


def _relative(when: datetime, now: datetime) -> str:
    delta = when - now
    if delta <= timedelta(0):
        return "expired"
    if delta < timedelta(minutes=1):
        return "in under a minute"
    minutes = math.ceil(delta.total_seconds() / 60)  # a fresh 30-minute mandate says 30
    if minutes < 120:
        return f"in {minutes} min"
    return f"in {minutes // 60} h {minutes % 60} min"
