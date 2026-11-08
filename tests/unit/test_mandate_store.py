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
from mandate_firewall.mandate.models import Budget, Limits, Mandate
from mandate_firewall.mandate.store import (
    AlreadyChargedError,
    BudgetExceededError,
    MandateConflictError,
    MandateIntegrityError,
    MandateNotActiveError,
    MandateStatus,
    MandateStore,
    MandateStoreError,
)
from tests.unit.test_mandate_models import BOB, CREATED, PRINCIPAL, mandate, swap, transfer

EXPIRES = CREATED + timedelta(minutes=30)
TX = "0x" + "aa" * 32  # a transaction hash


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
    assert raw(path).execute("PRAGMA user_version").fetchone()[0] == 2


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
    raw(path).execute("PRAGMA user_version = 3")
    with pytest.raises(MandateStoreError, match="schema version 3"):
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
        "UPDATE spending SET spent = zeroblob(32)",
        "UPDATE spending SET intent_index = 1",
        "DELETE FROM spending",
        "UPDATE charged SET mandate_id = 'x'",
        "DELETE FROM charged",
    ],
)
def test_triggers_refuse_edits(path: Path, store: MandateStore, sql: str) -> None:
    mid = store.add(mandate())
    store.record_transaction(mid, charges={0: 5}, tx_hash=TX)
    store.revoke(mid)
    with pytest.raises(
        sqlite3.IntegrityError, match="append-only|only go up|never deleted|goes up|is never"
    ):
        raw(path).execute(sql)


def test_store_code_never_edits_content() -> None:
    source = Path(store_module.__file__).read_text()
    code = source.replace(store_module._SCHEMA, "").replace(store_module._SCHEMA_V2, "")
    # (the triggers name these on purpose)
    assert not re.search(r"\bUPDATE\s+(mandates|events|charged)\b", code, re.IGNORECASE)
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


# --- counters-only (the proxy's mode) -----------------------------------------------


@pytest.fixture
def proxy_view(path: Path, store: MandateStore, clock: Clock) -> MandateStore:
    return MandateStore(path, counters_only=True, clock=clock)


def test_counters_only_can_charge_and_exhaust(
    store: MandateStore, proxy_view: MandateStore
) -> None:
    mid = store.add(mandate())  # max_transactions=3
    assert [proxy_view.record_transaction(mid).transactions for _ in range(3)] == [1, 2, 3]
    assert store.get(mid).status is MandateStatus.EXHAUSTED  # the event was written too
    with pytest.raises(MandateNotActiveError):
        proxy_view.record_transaction(mid)


def test_counters_only_refuses_add_and_revoke(
    store: MandateStore, proxy_view: MandateStore
) -> None:
    mid = store.add(mandate())
    with pytest.raises(MandateStoreError, match="counters-only: add"):
        proxy_view.add(other())
    with pytest.raises(MandateStoreError, match="counters-only: revoke"):
        proxy_view.revoke(mid)
    assert store.get(mid).status is MandateStatus.ACTIVE


@pytest.mark.parametrize(
    "sql",
    [
        "INSERT INTO mandates VALUES ('x', x'00', 1, 'p', 'c', 'e')",
        "UPDATE events SET event = 'revoked'",
        "DELETE FROM counters",
        "DELETE FROM spending",
        "DELETE FROM charged",
        "UPDATE charged SET at = 'x'",
        "DROP TRIGGER mandates_no_update",
        "DROP TRIGGER spending_only_up",
        "CREATE TABLE x (a)",
        "PRAGMA user_version = 2",
        "PRAGMA writable_schema = ON",
        "ATTACH DATABASE ':memory:' AS other",
    ],
)
def test_counters_only_connection_denies_other_writes(
    store: MandateStore, proxy_view: MandateStore, sql: str
) -> None:
    # Not just the Python methods: the connection itself refuses, whatever
    # SQL a proxy code path might run. One gap, by design: an INSERT into
    # events is allowed (record_transaction writes "exhausted"), and the
    # authorizer can't see the value, so "revoked" is refused only by
    # revoke() in Python. Revoking can only make the agent do less.
    store.add(mandate())
    with pytest.raises(sqlite3.DatabaseError, match="not authorized"):
        proxy_view._db.execute(sql)


def test_counters_only_never_creates_or_initializes(path: Path) -> None:
    with pytest.raises(MandateStoreError, match="does not exist"):
        MandateStore(path, counters_only=True)
    path.parent.mkdir()
    path.touch()
    with pytest.raises(MandateStoreError, match="not an initialized mandate store"):
        MandateStore(path, counters_only=True)
    assert path.stat().st_size == 0  # not even a WAL header was written
    with pytest.raises(ValueError, match="can't create"):
        MandateStore(path, create=True, counters_only=True)


def test_latest_for_returns_the_newest_whatever_its_status(
    store: MandateStore, clock: Clock
) -> None:
    assert store.latest_for(84532, PRINCIPAL) is None
    first = store.add(mandate())
    second = store.add(other(), replace=True)
    latest = store.latest_for(84532, PRINCIPAL)
    assert latest is not None and latest.id == second
    clock.now = EXPIRES
    latest = store.latest_for(84532, PRINCIPAL)
    assert latest is not None and (latest.id, latest.status) == (second, MandateStatus.EXPIRED)
    assert store.get(first).status is MandateStatus.REVOKED
    assert store.latest_for(1, PRINCIPAL) is None


# --- the spending ledger (M4, schema version 2) ---------------------------------------
#
# mandate() sends at most 50 USDC (50_000_000 base units) to Bob; swap() sells
# at most 100 USDC. Intent indexes are positions in `intents`.

USDC_50 = 50_000_000


def two_intents() -> Mandate:
    return mandate(intents=(transfer(), swap()))


def test_charges_accumulate_per_intent(path: Path, store: MandateStore, clock: Clock) -> None:
    mid = store.add(two_intents())
    assert store.get(mid).spent == (0, 0)
    store.record_transaction(mid, charges={0: 10_000_000})
    stored = store.record_transaction(mid, charges={0: 5_000_000, 1: 40_000_000})
    assert (stored.spent, stored.transactions) == ((15_000_000, 40_000_000), 2)
    store.close()
    assert MandateStore(path, clock=clock).get(mid).spent == (15_000_000, 40_000_000)


def test_a_transaction_without_charges_spends_nothing(store: MandateStore) -> None:
    mid = store.add(mandate())
    stored = store.record_transaction(mid)  # e.g. an approval, or the M3 proxy
    assert (stored.spent, stored.transactions) == ((0,), 1)


def test_spending_the_whole_budget_exhausts_the_mandate(store: MandateStore) -> None:
    mid = store.add(mandate())  # 3 transactions allowed, 50 USDC
    last = store.record_transaction(mid, charges={0: USDC_50})
    assert (last.status, last.transactions, last.spent) == (MandateStatus.EXHAUSTED, 1, (USDC_50,))
    with pytest.raises(MandateNotActiveError, match="exhausted"):
        store.record_transaction(mid)


def test_exhausted_only_when_every_budget_is_spent(store: MandateStore) -> None:
    mid = store.add(two_intents())
    after_one = store.record_transaction(mid, charges={0: USDC_50})
    assert after_one.status is MandateStatus.ACTIVE  # the swap budget is untouched
    after_both = store.record_transaction(mid, charges={1: 100_000_000})
    assert after_both.status is MandateStatus.EXHAUSTED


def assert_nothing_written(store: MandateStore, mid: str, before: object) -> None:
    after = store.get(mid)
    assert (after.spent, after.transactions, after.status) == before
    assert store.charged_to(TX) is None


def test_over_budget_is_refused_and_writes_nothing(store: MandateStore) -> None:
    mid = store.add(mandate())
    store.record_transaction(mid, charges={0: 30_000_000})
    before = (store.get(mid).spent, 1, MandateStatus.ACTIVE)
    with pytest.raises(BudgetExceededError, match="intent 1 has too little budget left"):
        store.record_transaction(mid, charges={0: 20_000_001}, tx_hash=TX)
    assert_nothing_written(store, mid, before)
    # Exactly what's left is fine.
    assert store.record_transaction(mid, charges={0: 20_000_000}).spent == (USDC_50,)


def test_the_recheck_is_what_counts(path: Path, store: MandateStore, clock: Clock) -> None:
    """Two transactions verified against the same "30 of 50 spent": 15 each
    fits on its own, together they don't. The second charge must be refused,
    even from another connection (the CLI and the proxy are separate
    processes). If the first spent the budget exactly, the mandate would be
    exhausted and the second refused for that instead."""
    mid = store.add(mandate())
    store.record_transaction(mid, charges={0: 30_000_000})
    proxy = MandateStore(path, clock=clock)
    store.record_transaction(mid, charges={0: 15_000_000})
    with pytest.raises(BudgetExceededError):
        proxy.record_transaction(mid, charges={0: 15_000_000})
    assert store.get(mid).spent == (45_000_000,)


def test_budget_check_and_charge_hold_the_write_lock(
    path: Path, store: MandateStore, clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Like the transaction-cap race test: a rival charges the same budget
    between our read of it and our write. It must wait for our lock."""
    mid = store.add(mandate(limits=Limits(max_transactions=10, period=None)))
    store.record_transaction(mid, charges={0: 30_000_000})
    rival = MandateStore(path, clock=clock, busy_timeout=0.1)
    outcome: list[str] = []
    real_load = MandateStore._load

    def load_then_rival(self: MandateStore, *args: object) -> object:
        result = real_load(self, *args)  # type: ignore[arg-type]
        if self is store and not outcome:
            try:
                rival.record_transaction(mid, charges={0: 20_000_000})
                outcome.append("rival charged")
            except MandateStoreError as exc:
                outcome.append(f"rival refused: {exc}")
        return result

    monkeypatch.setattr(MandateStore, "_load", load_then_rival)
    ours = store.record_transaction(mid, charges={0: 20_000_000})
    assert outcome[0].startswith("rival refused: mandate store is unavailable")
    assert ours.spent == (USDC_50,)


def test_approval_limits_fit_what_is_left_after_the_charges(store: MandateStore) -> None:
    mid = store.add(two_intents())  # the swap sells at most 100 USDC
    store.record_transaction(mid, charges={1: 40_000_000})
    before = (store.get(mid).spent, 1, MandateStatus.ACTIVE)
    with pytest.raises(BudgetExceededError, match="intent 2 .* for the approval"):
        store.record_transaction(mid, charges={1: 10_000_000}, approval_limits={1: 50_000_001})
    assert_nothing_written(store, mid, before)
    ok = store.record_transaction(mid, charges={1: 10_000_000}, approval_limits={1: 50_000_000})
    assert ok.spent == (0, 50_000_000)  # an approval spends nothing


def test_refusals_never_carry_amounts(store: MandateStore) -> None:
    # The proxy returns these messages to the agent (Decision 6).
    mid = store.add(two_intents())
    messages = []
    for kwargs in ({"charges": {0: USDC_50 + 1}}, {"approval_limits": {1: 100_000_001}}):
        with pytest.raises(BudgetExceededError) as caught:
            store.record_transaction(mid, **kwargs)  # type: ignore[arg-type]
        messages.append(str(caught.value).replace(mid, ""))
    for message in messages:
        assert re.findall(r"\d+", message) in (["1"], ["2"])  # only the intent number


def test_a_transaction_is_charged_once(store: MandateStore) -> None:
    mid = store.add(mandate())
    store.record_transaction(mid, charges={0: 1}, tx_hash=TX.upper().replace("0X", "0x"))
    assert store.charged_to(TX) == mid  # stored lowercase, found either way
    assert store.charged_to(TX.upper().replace("0X", "0x")) == mid
    with pytest.raises(AlreadyChargedError, match="already charged"):
        store.record_transaction(mid, charges={0: 1}, tx_hash=TX)
    stored = store.get(mid)
    assert (stored.spent, stored.transactions) == ((1,), 1)
    assert store.charged_to("0x" + "bb" * 32) is None


@pytest.mark.parametrize(
    "kwargs",
    [
        {"charges": {1: 1}},  # no intent 1
        {"charges": {-1: 1}},
        {"charges": {True: 1}},
        {"charges": {0: 0}},
        {"charges": {0: -1}},
        {"charges": {0: True}},
        {"charges": {0: 2**256}},
        {"approval_limits": {3: 1}},
        {"approval_limits": {0: 0}},
        {"tx_hash": "0x1234"},
        {"tx_hash": TX + "\n"},
    ],
)
def test_malformed_charges_are_refused(store: MandateStore, kwargs: dict[str, object]) -> None:
    mid = store.add(mandate())
    with pytest.raises(ValueError):
        store.record_transaction(mid, **kwargs)  # type: ignore[arg-type]
    assert (store.get(mid).spent, store.get(mid).transactions) == ((0,), 0)


# uint256 as 32-byte big-endian BLOBs: SQLite's memcmp order is numeric order.
BOUNDARIES = [(0, 1), (2**63 - 1, 2**63), (2**64 - 1, 2**64), (2**255 - 1, 2**255), (255, 256)]


@pytest.mark.parametrize(("low", "high"), BOUNDARIES)
def test_blob_order_is_numeric_order(low: int, high: int) -> None:
    db = sqlite3.connect(":memory:")
    lo, hi = store_module._to_blob(low), store_module._to_blob(high)
    assert db.execute("SELECT ? < ?, ? < ?", (lo, hi, hi, lo)).fetchone() == (1, 0)
    assert store_module._from_blob(hi) == high


@pytest.mark.parametrize(("low", "high"), BOUNDARIES)
def test_spending_trigger_compares_numerically(
    path: Path, store: MandateStore, low: int, high: int
) -> None:
    big = mandate(intents=(transfer(budget=Budget(max=2**256 - 2, period=None)),))
    mid = store.add(big)
    store.record_transaction(mid, charges={0: high} if high else {})
    db = raw(path)
    with pytest.raises(sqlite3.IntegrityError, match="only goes up"):
        db.execute("UPDATE spending SET spent = ?", (store_module._to_blob(low),))
    db.execute("UPDATE spending SET spent = ?", (store_module._to_blob(high + 1),))  # up is fine
    assert store.get(mid).spent == (high + 1,)


@pytest.mark.parametrize("value", [b"\x00" * 31, b"\x00" * 33, "0" * 64, 5])
def test_spending_must_be_a_32_byte_blob(path: Path, store: MandateStore, value: object) -> None:
    mid = store.add(mandate())
    with pytest.raises(sqlite3.IntegrityError):
        raw(path).execute(
            "INSERT INTO spending VALUES (?, ?, 0, ?)", (mid, "2026-10-09T12:00:00Z", value)
        )


@pytest.mark.parametrize(
    ("index", "amount", "message"),
    [(1, 1, "an intent it doesn't have"), (0, USDC_50 + 1, "above its budget")],
)
def test_spending_rows_that_do_not_fit_the_mandate_are_integrity_failures(
    path: Path, store: MandateStore, index: int, amount: int, message: str
) -> None:
    mid = store.add(mandate())
    raw(path).execute(
        "INSERT INTO spending VALUES (?, ?, ?, ?)",
        (mid, "2026-10-09T12:00:00Z", index, store_module._to_blob(amount)),
    )
    with pytest.raises(MandateIntegrityError, match=message):
        store.get(mid)


def test_counters_only_can_charge_budgets_and_record_hashes(
    store: MandateStore, proxy_view: MandateStore
) -> None:
    mid = store.add(mandate())
    stored = proxy_view.record_transaction(mid, charges={0: USDC_50}, tx_hash=TX)
    assert stored.status is MandateStatus.EXHAUSTED
    assert store.get(mid).spent == (USDC_50,)
    assert store.charged_to(TX) == mid


# --- upgrading a version 1 store ----------------------------------------------------------


def v1_store(path: Path) -> str:
    """A store as M3 wrote it: version 1 schema, one mandate, one transaction."""
    path.parent.mkdir(mode=0o700, exist_ok=True)
    db = raw(path)
    db.executescript(f"BEGIN; {store_module._SCHEMA} PRAGMA user_version = 1; COMMIT;")
    m = mandate()
    mid = mandate_id(m)
    db.execute(
        "INSERT INTO mandates VALUES (?, ?, ?, ?, ?, ?)",
        (
            mid,
            canonical_json(m),
            m.chain_id,
            m.principal,
            "2026-10-09T12:00:00Z",
            "2026-10-09T12:30:00Z",
        ),
    )
    db.execute("INSERT INTO counters VALUES (?, '2026-10-09T12:00:00Z', 1)", (mid,))
    db.close()
    path.chmod(0o600)
    return mid


def test_the_proxy_refuses_a_version_1_store_and_leaves_it_alone(path: Path) -> None:
    v1_store(path)
    before = path.read_bytes()
    with pytest.raises(MandateStoreError, match="schema version 1 .* mandate list"):
        MandateStore(path, counters_only=True)
    assert path.read_bytes() == before


def test_a_writable_open_upgrades_version_1(
    path: Path, clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    mid = v1_store(path)
    with caplog.at_level(logging.INFO, logger="mandate_firewall"):
        upgraded = MandateStore(path, clock=clock)
    assert "upgraded from schema version 1 to 2" in caplog.text
    stored = upgraded.get(mid)
    assert (stored.transactions, stored.spent, stored.status) == (1, (0,), MandateStatus.ACTIVE)
    upgraded.record_transaction(mid, charges={0: 5}, tx_hash=TX)
    upgraded.close()
    # Now the proxy can open it.
    assert MandateStore(path, counters_only=True, clock=clock).get(mid).spent == (5,)


def test_an_upgraded_store_has_the_same_schema_as_a_new_one(tmp_path: Path, path: Path) -> None:
    v1_store(path)
    MandateStore(path).close()
    fresh = tmp_path / "fresh" / "mandates.db"
    MandateStore(fresh, create=True).close()

    def schema(p: Path) -> list[tuple[str, str]]:
        rows = raw(p).execute("SELECT name, sql FROM sqlite_master ORDER BY name").fetchall()
        return [(name, " ".join((sql or "").split())) for name, sql in rows]

    assert schema(path) == schema(fresh)


def test_a_spent_budget_writes_the_exhausted_event(path: Path, store: MandateStore) -> None:
    mid = store.add(mandate())
    store.record_transaction(mid, charges={0: USDC_50})
    events = raw(path).execute("SELECT event FROM events WHERE mandate_id = ?", (mid,)).fetchall()
    assert events == [("exhausted",)]


def test_a_spent_budget_reads_as_exhausted_even_without_the_event(
    path: Path, store: MandateStore
) -> None:
    # Like the transaction count: the status follows from the numbers too, so
    # a lost (or deleted) event doesn't revive a mandate whose budget is gone.
    mid = store.add(mandate())
    raw(path).execute(
        "INSERT INTO spending VALUES (?, ?, 0, ?)",
        (mid, "2026-10-09T12:00:00Z", store_module._to_blob(USDC_50)),
    )
    assert store.get(mid).status is MandateStatus.EXHAUSTED


def test_a_bool_is_not_an_intent_index(store: MandateStore) -> None:
    mid = store.add(two_intents())  # True == 1 would be a valid index here
    with pytest.raises(ValueError, match="intent the mandate doesn't have"):
        store.record_transaction(mid, charges={True: 1})  # type: ignore[dict-item]


@pytest.mark.parametrize("value", [b"\x00" * 31, b"\x00" * 33, "00" * 32, 7])
def test_reading_a_spending_amount_that_is_not_32_bytes(value: object) -> None:
    # The schema's CHECK makes this unreachable unless the table was replaced.
    with pytest.raises(MandateIntegrityError, match="not 32 bytes"):
        store_module._from_blob(value)
