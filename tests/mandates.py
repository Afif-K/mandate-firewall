"""Seed a mandate store for proxy tests, the way `mandate new` would, minus
the person: since M3 commit 7 the proxy blocks every transaction from a
sender without an active mandate, so proxy tests start by creating one."""

import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path

from mandate_firewall.mandate.models import (
    AssetRef,
    Budget,
    Limits,
    Mandate,
    MandateKind,
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
) -> Mandate:
    """A mandate to send up to 1 ETH to Bob. Until M4 the proxy doesn't compare effects
    with the content, so for the gate only principal, chain, expiry and the
    cap matter."""
    created = (created_at or datetime.now(UTC)).replace(microsecond=0)
    return Mandate(
        schema_version=1,
        kind=MandateKind.ONE_SHOT,
        chain_id=chain_id,
        principal=principal,
        intents=(
            TransferIntent(
                kind="transfer",
                asset=AssetRef(chain_id=chain_id, address=None, decimals=18),
                budget=Budget(max=10**18, period=None),
                recipient=recipient,
            ),
        ),
        limits=Limits(max_transactions=max_transactions, period=None),
        created_at=created,
        expires_at=created + timedelta(minutes=minutes),
        instruction=f"send up to 1 ETH to {recipient}",
        nonce="0x" + secrets.token_hex(32),
    )


def seed_store(path: Path, *mandates: Mandate, at: datetime | None = None) -> list[str]:
    """Create the store (0600 in a 0700 directory) if needed, add the
    mandates and return their ids. `at` is the writer's clock, so a test can
    add a mandate "in the past" that is expired by the time the proxy reads it."""
    store = MandateStore(path, create=True, clock=(lambda: at) if at else lambda: datetime.now(UTC))
    try:
        return [store.add(m) for m in mandates]
    finally:
        store.close()
