"""Seed a mandate store for proxy tests, the way `mandate new` would, minus
the person: since M3 commit 7 the proxy blocks every transaction from a
sender without an active mandate, and since M4 it checks each transaction's
effects against that mandate, so proxy tests start by creating one that
covers what they send."""

import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path

from mandate_firewall.mandate.models import (
    AssetRef,
    Budget,
    Limits,
    Mandate,
    MandateKind,
    SwapIntent,
    TransferIntent,
)
from mandate_firewall.mandate.store import MandateStore

# anvil's dev account 1, the usual recipient in tests.
BOB = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"


def native_transfer_mandate(
    chain_id: int,
    principal: str,
    *,
    created_at: datetime | None = None,
    minutes: int = 30,
    max_transactions: int = 3,
    recipient: str = BOB,
    budget: int = 10**18,
    instruction: str | None = None,
) -> Mandate:
    """A mandate to send up to `budget` wei (1 ETH) to `recipient` (Bob).
    `instruction` is the user's words it records (default: the amount in wei)."""
    intent = TransferIntent(
        kind="transfer",
        asset=AssetRef(chain_id=chain_id, address=None, decimals=18),
        budget=Budget(max=budget, period=None),
        recipient=recipient,
    )
    return mandate_with(
        chain_id,
        principal,
        intent,
        created_at=created_at,
        minutes=minutes,
        max_transactions=max_transactions,
        instruction=instruction or f"send up to {budget} wei to {recipient}",
    )


def token_transfer(
    chain_id: int, token: str, budget: int, recipient: str = BOB, decimals: int = 6
) -> TransferIntent:
    return TransferIntent(
        kind="transfer",
        asset=AssetRef(chain_id=chain_id, address=token, decimals=decimals),
        budget=Budget(max=budget, period=None),
        recipient=recipient,
    )


def mandate_with(
    chain_id: int,
    principal: str,
    *intents: TransferIntent | SwapIntent,
    created_at: datetime | None = None,
    minutes: int = 30,
    max_transactions: int = 3,
    instruction: str = "test mandate",
) -> Mandate:
    """A one-shot mandate with these intents, as `mandate new` would lock it."""
    created = (created_at or datetime.now(UTC)).replace(microsecond=0)
    return Mandate(
        schema_version=1,
        kind=MandateKind.ONE_SHOT,
        chain_id=chain_id,
        principal=principal,
        intents=intents,
        limits=Limits(max_transactions=max_transactions, period=None),
        created_at=created,
        expires_at=created + timedelta(minutes=minutes),
        instruction=instruction,
        nonce="0x" + secrets.token_hex(32),
    )


def replace_mandate(path: Path, mandate: Mandate) -> str:
    """Lock `mandate` in place of the principal's active one, like
    `mandate new --replace`, next to a running proxy."""
    store = MandateStore(path)
    try:
        return store.add(mandate, replace=True)
    finally:
        store.close()


def seed_store(path: Path, *mandates: Mandate, at: datetime | None = None) -> list[str]:
    """Create the store (0600 in a 0700 directory) if needed, add the
    mandates and return their ids. `at` is the writer's clock, so a test can
    add a mandate "in the past" that is expired by the time the proxy reads it."""
    store = MandateStore(path, create=True, clock=(lambda: at) if at else lambda: datetime.now(UTC))
    try:
        return [store.add(m) for m in mandates]
    finally:
        store.close()
