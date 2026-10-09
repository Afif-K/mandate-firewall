"""Mandate store: append-only content, status, counters, integrity, permissions."""

import logging
import re
import sqlite3
import stat
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from mandate_firewall.mandate import store as store_module
from mandate_firewall.mandate.canonical import canonical_json, mandate_id
from mandate_firewall.mandate.models import Mandate
from mandate_firewall.mandate.store import (
    MandateConflictError,
    MandateIntegrityError,
    MandateNotActiveError,
    MandateStatus,
    MandateStore,
    MandateStoreError,
)
from tests.unit.test_mandate_models import BOB, CREATED, PRINCIPAL, mandate

EXPIRES = CREATED + timedelta(minutes=30)


class Clock:
    def __init__(self) -> None:
        self.now = CREATED + timedelta(minutes=1)

    def __call__(self) -> datetime:
        return self.now


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def path(tmp_path: Path) -> Path:
    return tmp_path / "state" / "mandates.db"


@pytest.fixture
def store(path: Path, clock: Clock) -> MandateStore:
    return MandateStore(path, create=True, clock=clock)


def other(nonce_byte: str = "cd", **overrides: object) -> Mandate:
    """A different mandate (another nonce) for the same principal."""
    return mandate(nonce="0x" + nonce_byte * 32, **overrides)


def raw(path: Path) -> sqlite3.Connection:
    """A direct connection, as someone editing the file would have."""
    return sqlite3.connect(path, isolation_level=None)


# --- creating and opening ------------------------------------------------------


def test_create_sets_private_modes(path: Path, store: MandateStore) -> None:
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert raw(path).execute("PRAGMA user_version").fetchone()[0] == 1


def test_open_without_create_requires_the_file(path: Path) -> None:
    with pytest.raises(MandateStoreError, match="does not exist"):
        MandateStore(path)


def test_reopen_keeps_everything(path: Path, store: MandateStore, clock: Clock) -> None:
    mid = store.add(mandate())
    store.record_transaction(mid)
    store.close()
    reopened = MandateStore(path, clock=clock)
    stored = reopened.get(mid)
    assert stored.mandate == mandate()
    assert stored.transactions == 1


def test_unknown_schema_version(path: Path, store: MandateStore) -> None:
    store.close()
    raw(path).execute("PRAGMA user_version = 2")
    with pytest.raises(MandateStoreError, match="schema version 2"):
        MandateStore(path)


def test_other_sqlite_file_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "other.db"
    raw(path).execute("CREATE TABLE t (x)")
    with pytest.raises(MandateStoreError, match="no mandate store schema"):
        MandateStore(path)


def test_garbage_file_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "garbage.db"
    path.write_bytes(b"this is not a database" * 100)
    with pytest.raises(MandateStoreError):
        MandateStore(path)


def test_warns_when_others_can_reach_the_store(
    path: Path, store: MandateStore, clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    store.close()
    path.chmod(0o644)
    path.parent.chmod(0o755)
    with caplog.at_level(logging.WARNING):
        MandateStore(path, clock=clock).close()
    messages = [r.getMessage() for r in caplog.records]
    assert any("mandate store " in m and "644" in m for m in messages)
    assert any("mandate store directory" in m and "755" in m for m in messages)


def test_no_warning_for_private_store(
    path: Path, store: MandateStore, clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    store.close()
    with caplog.at_level(logging.WARNING):
        MandateStore(path, clock=clock).close()
    assert not caplog.records


# --- adding and reading ------------------------------------------------------------


def test_add_and_get(store: MandateStore) -> None:
    mid = store.add(mandate())
    assert mid == mandate_id(mandate())
    stored = store.get(mid)
    assert stored.mandate == mandate()
    assert stored.status is MandateStatus.ACTIVE
    assert stored.transactions == 0
    assert store.active_for(84532, PRINCIPAL) == stored
    assert [s.id for s in store.all()] == [mid]


def test_lookup_needs_chain_and_principal(store: MandateStore) -> None:
    store.add(mandate())
    assert store.active_for(84532, BOB) is None
    assert store.active_for(8453, PRINCIPAL) is None


def test_unknown_id(store: MandateStore) -> None:
    with pytest.raises(MandateNotActiveError, match="no mandate"):
        store.get("0x" + "00" * 32)


def test_refuses_expired_or_future_mandates(store: MandateStore, clock: Clock) -> None:
    clock.now = EXPIRES
    with pytest.raises(MandateStoreError, match="already expired"):
        store.add(mandate())
    clock.now = CREATED - timedelta(minutes=2)
    with pytest.raises(MandateStoreError, match="future"):
        store.add(mandate())
    clock.now = CREATED - timedelta(seconds=30)  # within the allowed skew
    assert store.add(mandate())


# --- one active mandate per principal ------------------------------------------------


def test_second_active_mandate_is_refused(store: MandateStore) -> None:
    first = store.add(mandate())
    with pytest.raises(MandateConflictError, match=first):
        store.add(other())
    assert store.active_for(84532, PRINCIPAL).id == first  # type: ignore[union-attr]


def test_replace_revokes_the_old_one(store: MandateStore) -> None:
    first = store.add(mandate())
    second = store.add(other(), replace=True)
    assert store.get(first).status is MandateStatus.REVOKED
    assert store.active_for(84532, PRINCIPAL).id == second  # type: ignore[union-attr]


def test_failed_replace_rolls_back_the_revoke(store: MandateStore) -> None:
    """Re-adding the same mandate with replace: the revoke and the insert are
    one transaction, so when the insert fails the revoke is undone."""
    mid = store.add(mandate())
    with pytest.raises(MandateStoreError, match="already stored"):
        store.add(mandate(), replace=True)
    assert store.get(mid).status is MandateStatus.ACTIVE


def test_other_principals_and_chains_are_independent(store: MandateStore) -> None:
    store.add(mandate())
    assert store.add(other(principal=BOB))
    assert len([s for s in store.all() if s.status is MandateStatus.ACTIVE]) == 2


def test_new_mandate_allowed_after_expiry(store: MandateStore, clock: Clock) -> None:
    first = store.add(mandate())
    clock.now = EXPIRES
    assert store.get(first).status is MandateStatus.EXPIRED
    assert store.active_for(84532, PRINCIPAL) is None
    later = other(created_at=EXPIRES, expires_at=EXPIRES + timedelta(minutes=30))
    assert store.add(later)


# --- status changes ---------------------------------------------------------------------


def test_expires_exactly_at_expires_at(store: MandateStore, clock: Clock) -> None:
    mid = store.add(mandate())
    clock.now = EXPIRES - timedelta(seconds=1)
    assert store.get(mid).status is MandateStatus.ACTIVE
    clock.now = EXPIRES
    assert store.get(mid).status is MandateStatus.EXPIRED


def test_revoke(store: MandateStore) -> None:
    mid = store.add(mandate())
    assert store.revoke(mid) is True
    assert store.get(mid).status is MandateStatus.REVOKED
    assert store.active_for(84532, PRINCIPAL) is None
    assert store.revoke(mid) is False
    with pytest.raises(MandateNotActiveError):
        store.revoke("0x" + "00" * 32)


def test_record_transactions_until_exhausted(store: MandateStore) -> None:
    mid = store.add(mandate())  # max_transactions = 3
    assert store.record_transaction(mid).transactions == 1
    assert store.record_transaction(mid).transactions == 2
    last = store.record_transaction(mid)
    assert (last.transactions, last.status) == (3, MandateStatus.EXHAUSTED)
    with pytest.raises(MandateNotActiveError, match="exhausted"):
        store.record_transaction(mid)
    assert store.get(mid).transactions == 3
    assert store.active_for(84532, PRINCIPAL) is None


def test_record_transaction_needs_an_active_mandate(store: MandateStore, clock: Clock) -> None:
    expired = store.add(mandate())
    clock.now = EXPIRES
    with pytest.raises(MandateNotActiveError, match="expired"):
        store.record_transaction(expired)
    revoked = store.add(other(created_at=EXPIRES, expires_at=EXPIRES + timedelta(minutes=5)))
    store.revoke(revoked)
    with pytest.raises(MandateNotActiveError, match="revoked"):
        store.record_transaction(revoked)


def test_counts_are_shared_across_connections(
    path: Path, store: MandateStore, clock: Clock
) -> None:
    """The CLI and the proxy each open the file; both see one count."""
    mid = store.add(mandate())
    second = MandateStore(path, clock=clock)
    store.record_transaction(mid)
    second.record_transaction(mid)
    store.record_transaction(mid)
    assert second.get(mid).status is MandateStatus.EXHAUSTED


def test_check_and_increment_hold_the_write_lock(
    path: Path, store: MandateStore, clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Another process arrives between our check and our increment, when one
    slot is left. It must not get in: the first caller holds the write lock
    from BEGIN (IMMEDIATE) on, so the second can't take the same last slot."""
    mid = store.add(mandate())  # max_transactions = 3
    store.record_transaction(mid)
    store.record_transaction(mid)
    rival = MandateStore(path, clock=clock, busy_timeout=0.1)
    outcome: list[str] = []
    real_load = MandateStore._load

    def load_then_rival(self: MandateStore, *args: object) -> object:
        result = real_load(self, *args)  # type: ignore[arg-type]
        if self is store and not outcome:  # first load inside our transaction
            try:
                rival.record_transaction(mid)
                outcome.append("rival charged")
            except MandateStoreError as exc:
                outcome.append(f"rival refused: {exc}")
        return result

    monkeypatch.setattr(MandateStore, "_load", load_then_rival)
    last = store.record_transaction(mid)
    assert outcome[0].startswith("rival refused: mandate store is unavailable")
    assert (last.transactions, last.status) == (3, MandateStatus.EXHAUSTED)


def test_sqlite_errors_during_a_write_become_store_errors(path: Path, store: MandateStore) -> None:
    mid = store.add(mandate())
    raw(path).execute(  # the increment's INSERT now fails, like a full disk would
        "CREATE TRIGGER fail BEFORE INSERT ON counters BEGIN SELECT RAISE(ABORT, 'full'); END"
    )
    with pytest.raises(MandateStoreError, match="write failed"):
        store.record_transaction(mid)


# --- append-only, enforced by the database -----------------------------------------------


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE mandates SET principal = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8'",
        "DELETE FROM mandates",
        "UPDATE events SET event = 'exhausted'",
        "DELETE FROM events",
        "UPDATE counters SET transactions = 0",
        "DELETE FROM counters",
    ],
)
def test_triggers_refuse_edits(path: Path, store: MandateStore, sql: str) -> None:
    mid = store.add(mandate())
    store.record_transaction(mid)
    store.revoke(mid)
    with pytest.raises(sqlite3.IntegrityError, match="append-only|only go up|never deleted"):
        raw(path).execute(sql)


def test_store_code_never_edits_content() -> None:
    source = Path(store_module.__file__).read_text()
    code = source.replace(store_module._SCHEMA, "")  # the triggers name these on purpose
    assert not re.search(r"\bUPDATE\s+(mandates|events)\b", code, re.IGNORECASE)
    assert not re.search(r"\bDELETE\s+FROM\b", code, re.IGNORECASE)


# --- tampering ---------------------------------------------------------------------------


def tamper(path: Path, sql: str, *params: object) -> None:
    """Edit the file the way an attacker with write access would: drop the
    triggers first."""
    db = raw(path)
    for name in ("mandates_no_update", "mandates_no_delete"):
        db.execute(f"DROP TRIGGER IF EXISTS {name}")
    db.execute(sql, params)


def test_changed_body_is_detected(path: Path, store: MandateStore) -> None:
    mid = store.add(mandate())
    body = canonical_json(mandate()).replace(b'"max":"50000000"', b'"max":"50000001"')
    tamper(path, "UPDATE mandates SET body = ?", body)
    with pytest.raises(MandateIntegrityError, match="does not match its id"):
        store.get(mid)
    with pytest.raises(MandateIntegrityError):
        store.active_for(84532, PRINCIPAL)


def test_non_canonical_body_is_detected(path: Path, store: MandateStore) -> None:
    mid = store.add(mandate())
    tamper(path, "UPDATE mandates SET body = ?", canonical_json(mandate()) + b"\n")
    with pytest.raises(MandateIntegrityError, match="canonical"):
        store.get(mid)


def test_body_from_another_mandate_is_detected(path: Path, store: MandateStore) -> None:
    mid = store.add(mandate())
    tamper(path, "UPDATE mandates SET body = ?", canonical_json(other()))
    with pytest.raises(MandateIntegrityError, match="does not match its id"):
        store.get(mid)


def test_moved_lookup_columns_are_detected(path: Path, store: MandateStore) -> None:
    """Pointing a stored mandate at another principal via the index column."""
    mid = store.add(mandate())
    tamper(path, "UPDATE mandates SET principal = ?", BOB)
    with pytest.raises(MandateIntegrityError, match="lookup columns"):
        store.active_for(84532, BOB)
    with pytest.raises(MandateIntegrityError, match="lookup columns"):
        store.get(mid)


def test_extended_expiry_column_is_detected(path: Path, store: MandateStore) -> None:
    mid = store.add(mandate())
    tamper(path, "UPDATE mandates SET expires_at = '2099-01-01T00:00:00Z'")
    with pytest.raises(MandateIntegrityError, match="lookup columns"):
        store.get(mid)


def test_two_active_mandates_are_detected(path: Path, store: MandateStore) -> None:
    store.add(mandate())
    second = other()
    raw(path).execute(
        "INSERT INTO mandates VALUES (?, ?, ?, ?, ?, ?)",
        (
            mandate_id(second),
            canonical_json(second),
            84532,
            PRINCIPAL,
            "2026-10-09T12:00:00Z",
            "2026-10-09T12:30:00Z",
        ),
    )
    with pytest.raises(MandateIntegrityError, match="more than one"):
        store.active_for(84532, PRINCIPAL)
