"""The mandate store: locked mandates on disk, in SQLite.

The capture CLI writes mandates here, running as the firewall's OS user. The
proxy reads them, and its only write is counting transactions: it opens the
store with counters_only=True, which an SQLite authorizer enforces on the
connection. The agent runs as another user and can't open the file, so file
permissions are the boundary (docs/m3-plan.md §3). The file is created 0600;
a store that other users can reach is warned about, like the audit log.

Five tables (schema version 2):
- mandates: the canonical JSON of each mandate, keyed by its sha256 id.
  Append-only: SQLite triggers refuse UPDATE and DELETE. Every read re-checks
  that the bytes are canonical and hash to the id, and that the lookup columns
  (chain, principal, times) agree with the bytes.
- events: status changes ("revoked", "exhausted"), also append-only.
  "Expired" isn't stored; it follows from the clock.
- counters: transactions charged per (mandate, period start). One-shot
  mandates have one period, starting at created_at. Standing mandates (M5)
  will add more rows, not columns.
- spending (M4): how much of each intent's budget is spent, per (mandate,
  period start, intent index). Amounts are uint256, which SQLite's 64-bit
  integers can't hold, so they are stored as 32-byte big-endian BLOBs.
  SQLite compares BLOBs with memcmp, and for equal-length big-endian bytes
  that is numeric order, so the "only goes up" trigger stays a plain `<`.
  (A decimal string would sort "9" after "10".)
- charged (M4): the hash of every charged transaction, so a re-send of the
  same signed bytes is never charged twice (docs/m4-plan.md §4).

Version 1 stores (M3) are upgraded to version 2 by any writable open (the
capture CLI). The proxy opens counters-only and never upgrades: it refuses a
version 1 store and says how to upgrade it.

Not tamper-evident against the firewall's own OS user: whoever can write the
file can drop the triggers and delete a "revoked" event, a counter or a
spending row. Content can't be changed undetected (the hash), status, counts
and spending can.
"""

import logging
import os
import re
import sqlite3
import stat
import threading
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from mandate_firewall.mandate.canonical import (
    CanonicalFormError,
    canonical_json,
    mandate_id,
    parse_canonical,
)
from mandate_firewall.mandate.models import Mandate, TransferIntent
from mandate_firewall.models import UINT256_MAX

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 2
UINT256_BYTES = 32
_TX_HASH = re.compile(r"0x[0-9a-fA-F]{64}")
# A mandate created this far in the future means the capture machine's clock
# and ours disagree; refuse rather than guess which one is right.
MAX_CLOCK_SKEW = timedelta(minutes=1)

_SCHEMA = """
CREATE TABLE mandates (
    id         TEXT PRIMARY KEY,
    body       BLOB NOT NULL,
    chain_id   INTEGER NOT NULL,
    principal  TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
) STRICT;
CREATE INDEX mandates_by_principal ON mandates (chain_id, principal);

CREATE TABLE events (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    mandate_id TEXT NOT NULL REFERENCES mandates (id),
    event      TEXT NOT NULL CHECK (event IN ('revoked', 'exhausted')),
    at         TEXT NOT NULL,
    UNIQUE (mandate_id, event)
) STRICT;

CREATE TABLE counters (
    mandate_id   TEXT NOT NULL REFERENCES mandates (id),
    period_start TEXT NOT NULL,
    transactions INTEGER NOT NULL CHECK (transactions >= 0),
    PRIMARY KEY (mandate_id, period_start)
) STRICT;

CREATE TRIGGER mandates_no_update BEFORE UPDATE ON mandates
BEGIN SELECT RAISE(ABORT, 'mandates are append-only'); END;
CREATE TRIGGER mandates_no_delete BEFORE DELETE ON mandates
BEGIN SELECT RAISE(ABORT, 'mandates are append-only'); END;
CREATE TRIGGER events_no_update BEFORE UPDATE ON events
BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
CREATE TRIGGER events_no_delete BEFORE DELETE ON events
BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
CREATE TRIGGER counters_no_delete BEFORE DELETE ON counters
BEGIN SELECT RAISE(ABORT, 'counters are never deleted'); END;
CREATE TRIGGER counters_only_up BEFORE UPDATE ON counters
WHEN NEW.transactions < OLD.transactions
  OR NEW.mandate_id IS NOT OLD.mandate_id
  OR NEW.period_start IS NOT OLD.period_start
BEGIN SELECT RAISE(ABORT, 'counters only go up'); END;
"""

# Added in schema version 2 (M4). Applied on top of _SCHEMA for a new store,
# and on its own to upgrade a version 1 store, so both end up identical.
_SCHEMA_V2 = """
CREATE TABLE spending (
    mandate_id   TEXT NOT NULL REFERENCES mandates (id),
    period_start TEXT NOT NULL,
    intent_index INTEGER NOT NULL CHECK (intent_index >= 0),
    spent        BLOB NOT NULL CHECK (length(spent) = 32),
    PRIMARY KEY (mandate_id, period_start, intent_index)
) STRICT;

CREATE TABLE charged (
    tx_hash    TEXT PRIMARY KEY,
    mandate_id TEXT NOT NULL REFERENCES mandates (id),
    at         TEXT NOT NULL
) STRICT;

CREATE TRIGGER spending_no_delete BEFORE DELETE ON spending
BEGIN SELECT RAISE(ABORT, 'spending is never deleted'); END;
CREATE TRIGGER spending_only_up BEFORE UPDATE ON spending
WHEN NEW.spent < OLD.spent
  OR NEW.mandate_id IS NOT OLD.mandate_id
  OR NEW.period_start IS NOT OLD.period_start
  OR NEW.intent_index IS NOT OLD.intent_index
BEGIN SELECT RAISE(ABORT, 'spending only goes up'); END;
CREATE TRIGGER charged_no_update BEFORE UPDATE ON charged
BEGIN SELECT RAISE(ABORT, 'charged transactions are append-only'); END;
CREATE TRIGGER charged_no_delete BEFORE DELETE ON charged
BEGIN SELECT RAISE(ABORT, 'charged transactions are append-only'); END;
"""


class MandateStoreError(Exception):
    """The store can't be opened, read or written."""


class MandateIntegrityError(MandateStoreError):
    """A stored mandate doesn't match its id or its lookup columns."""


class MandateConflictError(MandateStoreError):
    """The principal already has an active mandate (and replace wasn't asked)."""


class ChargeRefusedError(MandateStoreError):
    """The mandate can't take this transaction. Nothing was charged. The
    message is returned to the agent, so it never contains a budget or an
    amount (docs/m4-plan.md, Decision 6)."""


class MandateNotActiveError(ChargeRefusedError):
    """The mandate is expired, revoked or exhausted, or doesn't exist."""


class BudgetExceededError(ChargeRefusedError):
    """A charge would exceed an intent's budget, or an approval would exceed
    what is left of it. Usually another transaction spent the budget after
    this one was verified."""


class AlreadyChargedError(ChargeRefusedError):
    """This exact transaction (same hash) was already charged."""


# What a counters_only connection may write: counters, spending, charged
# transaction hashes, the "exhausted" event a full counter or budget implies,
# and SQLite's AUTOINCREMENT bookkeeping for events.
# Everything not listed is denied: no mandate rows, no status changes by
# UPDATE, no DELETE, no schema changes (DROP TRIGGER), no PRAGMA, no ATTACH.
_COUNTERS_ONLY_WRITES: dict[int, frozenset[str]] = {
    sqlite3.SQLITE_INSERT: frozenset(
        {"counters", "events", "sqlite_sequence", "spending", "charged"}
    ),
    sqlite3.SQLITE_UPDATE: frozenset({"counters", "sqlite_sequence", "spending"}),
}
_COUNTERS_ONLY_ALWAYS = frozenset(
    {
        sqlite3.SQLITE_SELECT,
        sqlite3.SQLITE_READ,
        sqlite3.SQLITE_TRANSACTION,
        sqlite3.SQLITE_FUNCTION,
    }
)


def _counters_only(action: int, arg1: str | None, *_: object) -> int:
    if action in _COUNTERS_ONLY_ALWAYS:
        return sqlite3.SQLITE_OK
    if arg1 is not None and arg1 in _COUNTERS_ONLY_WRITES.get(action, frozenset()):
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


class MandateStatus(StrEnum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    EXHAUSTED = "exhausted"


class StoredMandate(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    mandate: Mandate
    status: MandateStatus
    transactions: int  # charged so far, in the current period
    spent: tuple[int, ...]  # per intent, in base units, in the current period


class MandateStore:
    """One SQLite connection, used under a lock. Each write is one
    transaction that SQLite fsyncs before it returns (synchronous=FULL).

    counters_only=True is the proxy's mode: the file must already be an
    initialized store, add() and revoke() refuse, and an SQLite authorizer
    on the connection denies every write except transaction counters. So a
    bug (or a future code path) in the proxy can't create, change or revoke
    a mandate, whatever SQL it runs. Fully read-only isn't possible: the
    counter that enforces max_transactions lives in this file.
    """

    def __init__(
        self,
        path: Path,
        *,
        create: bool = False,
        counters_only: bool = False,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        busy_timeout: float = 5.0,
    ) -> None:
        if create and counters_only:
            raise ValueError("a counters_only store can't create the file")
        self.path = path
        self.counters_only = counters_only
        self._clock = clock
        self._lock = threading.Lock()
        try:
            if create:
                _create_file(path)
            elif not path.is_file():
                raise MandateStoreError(f"mandate store {path} does not exist")
            _warn_if_reachable(path)
            # isolation_level=None: we issue BEGIN/COMMIT ourselves, so a
            # check and the write that depends on it share one transaction.
            self._db = sqlite3.connect(
                path, timeout=busy_timeout, isolation_level=None, check_same_thread=False
            )
            if counters_only:
                # Before any PRAGMA below: journal_mode = WAL writes to the
                # file, and the proxy must not write to a file that isn't
                # already our store (an empty file, someone else's database).
                self._init_schema()
            self._db.execute("PRAGMA foreign_keys = ON")
            self._db.execute("PRAGMA journal_mode = WAL")
            self._db.execute("PRAGMA synchronous = FULL")
            if counters_only:
                # Installed last: the PRAGMAs above are the only ones we run.
                self._db.set_authorizer(_counters_only)
            else:
                self._init_schema()
        except (sqlite3.Error, OSError) as exc:
            raise MandateStoreError(f"cannot open mandate store {path}: {exc}") from None

    def close(self) -> None:
        self._db.close()

    # --- writes ---------------------------------------------------------------

    def add(self, mandate: Mandate, *, replace: bool = False) -> str:
        """Store a confirmed mandate and return its id. If the principal
        already has an active mandate on this chain, refuse, or with
        replace=True revoke it in the same transaction."""
        self._refuse_if_counters_only("add")
        now = self._now()
        if mandate.expires_at <= now:
            raise MandateStoreError("the mandate has already expired")
        if mandate.created_at > now + MAX_CLOCK_SKEW:
            raise MandateStoreError("the mandate is created in the future (clock skew?)")
        mid = mandate_id(mandate)
        with self._write() as db:
            for current in self._active(db, mandate.chain_id, mandate.principal, now):
                if not replace:
                    raise MandateConflictError(
                        f"principal already has an active mandate ({current.id})"
                    )
                self._event(db, current.id, MandateStatus.REVOKED, now)
            try:
                db.execute(
                    "INSERT INTO mandates VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        mid,
                        canonical_json(mandate),
                        mandate.chain_id,
                        mandate.principal,
                        _ts(mandate.created_at),
                        _ts(mandate.expires_at),
                    ),
                )
            except sqlite3.IntegrityError:
                raise MandateStoreError(f"mandate {mid} is already stored") from None
        return mid

    def revoke(self, mid: str) -> bool:
        """Revoke a mandate. False if it had already stopped being active."""
        self._refuse_if_counters_only("revoke")
        now = self._now()
        with self._write() as db:
            stored = self._load(db, mid, now)
            if stored.status is not MandateStatus.ACTIVE:
                return False
            self._event(db, mid, MandateStatus.REVOKED, now)
        return True

    def record_transaction(
        self,
        mid: str,
        *,
        charges: Mapping[int, int] | None = None,
        approval_limits: Mapping[int, int] | None = None,
        tx_hash: str | None = None,
    ) -> StoredMandate:
        """Charge one transaction to an active mandate.

        `charges` maps intent index -> amount spent from its budget.
        `approval_limits` maps intent index -> an allowance the transaction
        grants, which must fit in what is left of that budget after the
        charges. `tx_hash`, if given, is recorded so the same transaction is
        never charged twice.

        Everything is checked and written in one SQLite transaction that
        holds the write lock from the start (BEGIN IMMEDIATE). The verifier
        decided with the spending it read before simulation; this is the
        check that counts, so two transactions racing for the same budget
        can't both get it. The mandate is marked exhausted when it reaches
        max_transactions, or when every intent's budget is fully spent.

        Raises a ChargeRefusedError (not active, over budget, already
        charged) with nothing written, or ValueError for malformed input.
        """
        charges = dict(charges or {})
        limits = dict(approval_limits or {})
        tx_hash = _check_tx_hash(tx_hash)
        now = self._now()
        with self._write() as db:
            stored = self._load(db, mid, now)
            if stored.status is not MandateStatus.ACTIVE:
                raise MandateNotActiveError(f"mandate {mid} is {stored.status}")
            budgets = _budgets(stored.mandate)
            _check_amounts(charges, len(budgets), "charge")
            _check_amounts(limits, len(budgets), "approval limit")
            if tx_hash is not None and self._charged_to(db, tx_hash) is not None:
                raise AlreadyChargedError(f"transaction {tx_hash} was already charged")

            spent = list(stored.spent)
            for index, amount in charges.items():
                spent[index] += amount
                if spent[index] > budgets[index]:
                    raise BudgetExceededError(
                        f"mandate {mid}: intent {index + 1} has too little budget left"
                    )
            for index, amount in limits.items():
                if budgets[index] - spent[index] < amount:
                    raise BudgetExceededError(
                        f"mandate {mid}: intent {index + 1} has too little budget left "
                        "for the approval"
                    )

            period = _ts(stored.mandate.created_at)  # one period until M5
            for index in sorted(charges):
                db.execute(
                    "INSERT INTO spending VALUES (?, ?, ?, ?)"
                    " ON CONFLICT (mandate_id, period_start, intent_index)"
                    " DO UPDATE SET spent = excluded.spent",
                    (mid, period, index, _to_blob(spent[index])),
                )
            db.execute(
                "INSERT INTO counters VALUES (?, ?, 1) ON CONFLICT (mandate_id, period_start)"
                " DO UPDATE SET transactions = transactions + 1",
                (mid, period),
            )
            if tx_hash is not None:
                db.execute("INSERT INTO charged VALUES (?, ?, ?)", (tx_hash, mid, _ts(now)))
            used = stored.transactions + 1
            if used >= stored.mandate.limits.max_transactions or spent == budgets:
                self._event(db, mid, MandateStatus.EXHAUSTED, now)
            return self._load(db, mid, now)

    def charged_to(self, tx_hash: str) -> str | None:
        """The id of the mandate this transaction was charged to, or None."""
        checked = _check_tx_hash(tx_hash)
        with self._lock:
            try:
                return self._charged_to(self._db, checked)  # type: ignore[arg-type]
            except sqlite3.Error as exc:
                raise MandateStoreError(f"cannot read mandate store: {exc}") from None

    # --- reads ----------------------------------------------------------------

    def get(self, mid: str) -> StoredMandate:
        with self._lock:
            return self._load(self._db, mid, self._now())

    def active_for(self, chain_id: int, principal: str) -> StoredMandate | None:
        """The principal's active mandate on this chain, or None. Raises
        MandateIntegrityError if any of the principal's rows fails its checks:
        a tampered store is an error to report, not a mandate to skip."""
        with self._lock:
            active = self._active(self._db, chain_id, principal, self._now())
        if len(active) > 1:  # add() prevents this; a store that has it was edited
            raise MandateIntegrityError("more than one active mandate for one principal")
        return active[0] if active else None

    def latest_for(self, chain_id: int, principal: str) -> StoredMandate | None:
        """The principal's most recently stored mandate on this chain, whatever
        its status, or None. For saying why there is no active mandate
        ("expired", "exhausted"); active_for() is what decides."""
        with self._lock:
            loaded = self._for_principal(self._db, chain_id, principal, self._now())
        return loaded[-1] if loaded else None

    def all(self) -> list[StoredMandate]:
        """Every stored mandate, oldest first."""
        with self._lock:
            now = self._now()
            ids = [row[0] for row in self._db.execute("SELECT id FROM mandates ORDER BY rowid")]
            return [self._load(self._db, mid, now) for mid in ids]

    # --- internals ------------------------------------------------------------

    def _now(self) -> datetime:
        return self._clock().replace(microsecond=0)

    def _refuse_if_counters_only(self, operation: str) -> None:
        if self.counters_only:
            raise MandateStoreError(f"store opened counters-only: {operation} is not allowed")

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        """BEGIN IMMEDIATE takes the write lock up front, so nothing can
        change between our checks and our writes, even from another process.
        A plain BEGIN would only lock at the first write, after the checks."""
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
            except sqlite3.Error as exc:
                raise MandateStoreError(f"mandate store is unavailable: {exc}") from None
            try:
                yield self._db
                self._db.execute("COMMIT")
            except BaseException as exc:
                try:
                    self._db.execute("ROLLBACK")
                except sqlite3.Error:
                    pass  # the failed statement may already have rolled back
                if isinstance(exc, sqlite3.Error):
                    raise MandateStoreError(f"mandate store write failed: {exc}") from None
                raise

    def _charged_to(self, db: sqlite3.Connection, tx_hash: str) -> str | None:
        row = db.execute("SELECT mandate_id FROM charged WHERE tx_hash = ?", (tx_hash,)).fetchone()
        return row[0] if row else None

    def _active(
        self, db: sqlite3.Connection, chain_id: int, principal: str, now: datetime
    ) -> list[StoredMandate]:
        loaded = self._for_principal(db, chain_id, principal, now)
        return [s for s in loaded if s.status is MandateStatus.ACTIVE]

    def _for_principal(
        self, db: sqlite3.Connection, chain_id: int, principal: str, now: datetime
    ) -> list[StoredMandate]:
        """Every mandate of the principal on this chain, oldest first. Each is
        fully checked, so one tampered row fails the whole lookup."""
        ids = [
            row[0]
            for row in db.execute(
                "SELECT id FROM mandates WHERE chain_id = ? AND principal = ? ORDER BY rowid",
                (chain_id, principal),
            )
        ]
        return [self._load(db, mid, now) for mid in ids]

    def _load(self, db: sqlite3.Connection, mid: str, now: datetime) -> StoredMandate:
        try:
            row = db.execute(
                "SELECT body, chain_id, principal, created_at, expires_at"
                " FROM mandates WHERE id = ?",
                (mid,),
            ).fetchone()
            if row is None:
                raise MandateNotActiveError(f"no mandate {mid}")
            events = {
                r[0] for r in db.execute("SELECT event FROM events WHERE mandate_id = ?", (mid,))
            }
            counter = db.execute(
                "SELECT transactions FROM counters WHERE mandate_id = ? AND period_start = ?",
                (mid, row[3]),
            ).fetchone()
            spending = db.execute(
                "SELECT intent_index, spent FROM spending"
                " WHERE mandate_id = ? AND period_start = ?",
                (mid, row[3]),
            ).fetchall()
        except sqlite3.Error as exc:
            raise MandateStoreError(f"cannot read mandate store: {exc}") from None

        body, chain_id, principal, created_at, expires_at = row
        try:
            if not isinstance(body, bytes):
                raise CanonicalFormError("mandate body is not bytes")
            mandate = parse_canonical(body)
        except CanonicalFormError as exc:
            raise MandateIntegrityError(f"mandate {mid}: {exc}") from None
        if mandate_id(mandate) != mid:
            raise MandateIntegrityError(f"mandate {mid}: content does not match its id")
        if (chain_id, principal, created_at, expires_at) != (
            mandate.chain_id,
            mandate.principal,
            _ts(mandate.created_at),
            _ts(mandate.expires_at),
        ):
            raise MandateIntegrityError(f"mandate {mid}: lookup columns do not match content")

        transactions = counter[0] if counter else 0
        budgets = _budgets(mandate)
        spent = [0] * len(budgets)
        for index, blob in spending:
            # The schema allows any index and any 32 bytes. A row that
            # doesn't fit this mandate wasn't written by record_transaction.
            if not 0 <= index < len(budgets):
                raise MandateIntegrityError(
                    f"mandate {mid}: spending for an intent it doesn't have"
                )
            spent[index] = _from_blob(blob)
            if spent[index] > budgets[index]:
                raise MandateIntegrityError(f"mandate {mid}: spending above its budget")

        if MandateStatus.REVOKED in events:
            status = MandateStatus.REVOKED
        elif (
            MandateStatus.EXHAUSTED in events
            or transactions >= mandate.limits.max_transactions
            or spent == budgets
        ):
            status = MandateStatus.EXHAUSTED
        elif now >= mandate.expires_at:
            status = MandateStatus.EXPIRED
        else:
            status = MandateStatus.ACTIVE
        return StoredMandate(
            id=mid, mandate=mandate, status=status, transactions=transactions, spent=tuple(spent)
        )

    def _event(self, db: sqlite3.Connection, mid: str, event: MandateStatus, now: datetime) -> None:
        db.execute(
            "INSERT INTO events (mandate_id, event, at) VALUES (?, ?, ?)",
            (mid, str(event), _ts(now)),
        )

    def _init_schema(self) -> None:
        version = self._db.execute("PRAGMA user_version").fetchone()[0]
        if version == SCHEMA_VERSION:
            return
        if version == 1:
            if self.counters_only:
                # The proxy never changes the schema, upgrades included.
                raise MandateStoreError(
                    "mandate store has schema version 1 and must be upgraded: run "
                    "`mandate-firewall mandate list` once, as the firewall's user"
                )
            self._db.executescript(f"BEGIN; {_SCHEMA_V2} PRAGMA user_version = 2; COMMIT;")
            logger.info("mandate store %s upgraded from schema version 1 to 2", self.path)
            return
        if version != 0:
            raise MandateStoreError(f"unknown mandate store schema version {version}")
        if self.counters_only:
            # The proxy never creates the schema: an empty file is not a store.
            raise MandateStoreError("file is not an initialized mandate store")
        tables = self._db.execute("SELECT count(*) FROM sqlite_master").fetchone()[0]
        if tables:
            raise MandateStoreError("file has tables but no mandate store schema version")
        self._db.executescript(
            f"BEGIN; {_SCHEMA} {_SCHEMA_V2} PRAGMA user_version = {SCHEMA_VERSION}; COMMIT;"
        )


def _budgets(mandate: Mandate) -> list[int]:
    return [
        i.budget.max if isinstance(i, TransferIntent) else i.sell_budget.max
        for i in mandate.intents
    ]


def _check_amounts(amounts: dict[int, int], intents: int, what: str) -> None:
    for index, amount in amounts.items():
        if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < intents:
            raise ValueError(f"{what} for an intent the mandate doesn't have")
        if isinstance(amount, bool) or not isinstance(amount, int) or not 0 < amount <= UINT256_MAX:
            raise ValueError(f"a {what} must be a positive uint256")


def _check_tx_hash(tx_hash: str | None) -> str | None:
    if tx_hash is None:
        return None
    if not isinstance(tx_hash, str) or not _TX_HASH.fullmatch(tx_hash):
        raise ValueError("a transaction hash is 0x followed by 64 hex digits")
    return tx_hash.lower()


def _to_blob(value: int) -> bytes:
    """A uint256 as 32 big-endian bytes: fixed length, so memcmp order is
    numeric order."""
    return value.to_bytes(UINT256_BYTES, "big")


def _from_blob(value: object) -> int:
    if not isinstance(value, bytes) or len(value) != UINT256_BYTES:
        raise MandateIntegrityError("a spending amount is not 32 bytes")
    return int.from_bytes(value, "big")


def _ts(value: datetime) -> str:
    """The same spelling as canonical JSON, which also sorts by time."""
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _create_file(path: Path) -> None:
    """Create the directory (0700) and the file (0600) if they don't exist.
    SQLite gives its -wal and -shm files the same mode as the database."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    os.close(fd)


def _warn_if_reachable(path: Path) -> None:
    # The modes above only apply when we create the file and directory.
    for target, kind in ((path, "mandate store"), (path.parent, "mandate store directory")):
        mode = target.stat().st_mode
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            logger.warning(
                "%s %s is accessible to other users (mode %o); the agent must not be able "
                "to write mandates",
                kind,
                target,
                mode & 0o777,
            )
